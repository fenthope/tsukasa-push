// Package vapid implements Voluntary Application Server Identification for
// Web Push (RFC 8292): ES256 JSON Web Tokens carried in the "vapid" HTTP
// authentication scheme, plus the application server public key used for
// subscription restriction (RFC 8292 §4).
//
// The sender package uses the signing side; the service package uses the
// verification side. JWT encoding is hand rolled per the narrow ES256
// profile required by RFC 8292 §2, using only the standard library.
package vapid

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Maximum accepted token validity window (RFC 8292 §2, §4.2).
const MaxTokenLifetime = 24 * time.Hour

// Scheme is the HTTP authentication scheme name registered by RFC 8292 §6.1.
const Scheme = "vapid"

// Validation errors. All wrap ErrBadCredential so callers can test the
// family with errors.Is while distinguishing causes.
var (
	ErrBadCredential   = errors.New("vapid: malformed vapid credentials")
	ErrBadSignature    = errors.New("vapid: invalid JWT signature")
	ErrExpired         = errors.New("vapid: token expired")
	ErrLifetimeTooLong = errors.New("vapid: token lifetime exceeds 24 hours")
	ErrAudience        = errors.New("vapid: token audience mismatch")
	ErrBadAlg          = errors.New("vapid: unsupported JWT algorithm")
)

// Signer produces VAPID authentication tokens with a stable application
// server identity (RFC 8292 §2). It is safe for concurrent use.
type Signer struct {
	private *ecdsa.PrivateKey
	keyB64  string // base64url uncompressed public key, the "k" parameter
}

// NewSigner returns a Signer for the given ES256-capable key.
func NewSigner(private *ecdsa.PrivateKey) (*Signer, error) {
	if private == nil || private.Curve != elliptic.P256() {
		return nil, errors.New("vapid: signer requires a P-256 key")
	}
	return &Signer{private: private, keyB64: EncodeKeyB64(&private.PublicKey)}, nil
}

// GenerateKey creates a new VAPID signing key pair. This key must be
// distinct from any key used for RFC 8291 push message key agreement
// (RFC 8292 §3.2).
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Public returns the signing public key, i.e. the stable application server
// identity.
func (s *Signer) Public() *ecdsa.PublicKey { return &s.private.PublicKey }

// PublicKeyB64 returns the base64url uncompressed encoding of the signing
// public key used in the "k" parameter and restricted subscriptions.
func (s *Signer) PublicKeyB64() string { return s.keyB64 }

// Claims are the JWT claims defined for VAPID by RFC 8292 §2, §2.1.
type Claims struct {
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	Subject  string `json:"sub,omitempty"`
}

// Token signs a VAPID JWT for the giver origin with the given subject and
// expiry. subject may be empty; when present it SHOULD be a mailto: or
// https: contact URI (RFC 8292 §2.1). The expiry must not be more than 24
// hours after the present.
func (s *Signer) Token(origin, subject string, expiry time.Time) (string, error) {
	dur := time.Until(expiry)
	if dur <= 0 {
		return "", fmt.Errorf("%w: expiry in the past", ErrLifetimeTooLong)
	}
	if dur > MaxTokenLifetime {
		return "", ErrLifetimeTooLong
	}
	claims, err := json.Marshal(Claims{Audience: origin, Expiry: expiry.Unix(), Subject: subject})
	if err != nil {
		return "", fmt.Errorf("vapid: marshal claims: %w", err)
	}
	signing := b64(jwtHeaderJSON) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := s.sign(digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

// Authorization returns the complete Authorization header field value
// ("vapid t=..., k=...") for the given push service origin.
func (s *Signer) Authorization(origin, subject string, expiry time.Time) (string, error) {
	token, err := s.Token(origin, subject, expiry)
	if err != nil {
		return "", err
	}
	return Scheme + " t=" + token + ", k=" + s.keyB64, nil
}

// JWT header for the VAPID profile (RFC 8292 §2.4).
var jwtHeaderJSON = []byte(`{"typ":"JWT","alg":"ES256"}`)

// sign produces the fixed-size JWS ES256 signature r||s (64 octets).
func (s *Signer) sign(digest []byte) ([]byte, error) {
	der, err := ecdsa.SignASN1(rand.Reader, s.private, digest)
	if err != nil {
		return nil, fmt.Errorf("vapid: sign: %w", err)
	}
	var rs struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		return nil, fmt.Errorf("vapid: parse signature: %w", err)
	}
	out := make([]byte, 64)
	rs.R.FillBytes(out[:32])
	rs.S.FillBytes(out[32:])
	return out, nil
}

// ParseAuthorization splits an "Authorization" header field value using the
// vapid scheme into its "t" (JWT) and "k" (public key) parameters. Unknown
// parameters are ignored per RFC 8292 §3.
func ParseAuthorization(header string) (token, key string, err error) {
	scheme, params, found := strings.Cut(strings.TrimSpace(header), " ")
	if !found || !strings.EqualFold(scheme, Scheme) {
		return "", "", fmt.Errorf("%w: scheme", ErrBadCredential)
	}
	seen := map[string]string{}
	for _, param := range strings.Split(params, ",") {
		name, value, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if name == "t" || name == "k" {
			if _, dup := seen[name]; dup {
				return "", "", fmt.Errorf("%w: duplicate %s", ErrBadCredential, name)
			}
			seen[name] = value
		}
	}
	token, k := seen["t"], seen["k"]
	if token == "" || k == "" {
		return "", "", fmt.Errorf("%w: missing t or k", ErrBadCredential)
	}
	return token, k, nil
}

// Verify checks a vapid Authorization header field value against the
// expected push service origin, as a push service would on receiving a
// push message request (RFC 8292 §4.2). It returns the validated claims and
// the embedded signing key.
func Verify(header, origin string, now time.Time) (Claims, *ecdsa.PublicKey, error) {
	token, key, err := ParseAuthorization(header)
	if err != nil {
		return Claims{}, nil, err
	}
	pub, err := DecodeKeyB64(key)
	if err != nil {
		return Claims{}, nil, err
	}
	claims, err := VerifyToken(token, pub, origin, now)
	if err != nil {
		return Claims{}, nil, err
	}
	return claims, pub, nil
}

// VerifyToken validates a VAPID JWT against a known public key, checking
// the signature and the aud/exp claims (present, not expired, not more
// than 24 hours ahead) per RFC 8292 §4.2. Additional claims are accepted
// and ignored (RFC 8292 §2.2).
func VerifyToken(token string, pub *ecdsa.PublicKey, origin string, now time.Time) (Claims, error) {
	var claims Claims
	if pub == nil {
		return claims, fmt.Errorf("%w: missing public key", ErrBadCredential)
	}
	headerB64, rest, found := strings.Cut(token, ".")
	if !found {
		return claims, fmt.Errorf("%w: segments", ErrBadCredential)
	}
	payloadB64, sigB64, found := strings.Cut(rest, ".")
	if !found || headerB64 == "" || payloadB64 == "" || sigB64 == "" {
		return claims, fmt.Errorf("%w: segments", ErrBadCredential)
	}

	header, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return claims, fmt.Errorf("%w: header encoding", ErrBadCredential)
	}
	var head struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &head); err != nil {
		return claims, fmt.Errorf("%w: header json", ErrBadCredential)
	}
	if head.Alg != "ES256" {
		return claims, fmt.Errorf("%w: %q", ErrBadAlg, head.Alg)
	}
	if head.Typ != "" && !strings.EqualFold(head.Typ, "JWT") {
		return claims, fmt.Errorf("%w: typ %q", ErrBadCredential, head.Typ)
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return claims, fmt.Errorf("%w: payload encoding", ErrBadCredential)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("%w: claims json", ErrBadCredential)
	}
	if claims.Audience == "" || claims.Expiry == 0 {
		return claims, fmt.Errorf("%w: aud/exp required", ErrBadCredential)
	}
	if claims.Audience != origin {
		return claims, fmt.Errorf("%w: got %q want %q", ErrAudience, claims.Audience, origin)
	}
	until := time.Unix(claims.Expiry, 0).Sub(now)
	if until <= 0 {
		return claims, ErrExpired
	}
	if until > MaxTokenLifetime {
		return claims, ErrLifetimeTooLong
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return claims, fmt.Errorf("%w: signature encoding", ErrBadCredential)
	}
	digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(sig[:32]),
		S: new(big.Int).SetBytes(sig[32:]),
	})
	if err != nil {
		return claims, fmt.Errorf("vapid: encode signature: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		return claims, ErrBadSignature
	}
	return claims, nil
}

// PublicKeyBytes returns the uncompressed X9.62 encoding of a P-256 public
// key (0x04||X||Y), the form used by the "k" parameter and by restricted
// subscriptions.
func PublicKeyBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil
	}
	raw := make([]byte, 65)
	raw[0] = 0x04
	pub.X.FillBytes(raw[1:33])
	pub.Y.FillBytes(raw[33:])
	return raw
}

// EncodeKeyB64 encodes a P-256 public key in the uncompressed X9.62 form
// (0x04||X||Y), base64url encoded without padding: the "k" parameter format
// of RFC 8292 §3.2, also used for subscription restriction (RFC 8292 §4.1).
func EncodeKeyB64(pub *ecdsa.PublicKey) string {
	raw := PublicKeyBytes(pub)
	if raw == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeKeyB64 parses the base64url uncompressed P-256 encoding produced by
// EncodeKeyB64. The point is validated to lie on the curve via crypto/ecdh
// (RFC 8291 §7).
func DecodeKeyB64(s string) (*ecdsa.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: key encoding", ErrBadCredential)
	}
	// NewPublicKey enforces the 0x04 prefix, length and point validity.
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("%w: key not on P-256", ErrBadCredential)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:]),
	}, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Origin returns the RFC 6454 §6.1 serialization of the URL's origin, the
// value required for a VAPID Jwt's "aud" claim (RFC 8292 §2): lowercase
// scheme, lowercase host and the port only when non default.
func Origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return scheme + "://" + host
}
