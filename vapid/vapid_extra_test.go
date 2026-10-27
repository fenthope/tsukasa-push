package vapid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// b64JSON encodes a value as base64url, the JWT segment encoding.
func b64JSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestParseAuthorizationIgnoresUnknownParameters(t *testing.T) {
	token, key, err := ParseAuthorization(`vapid t=abc, k=def, x=1, foo`)
	if err != nil {
		t.Fatal(err)
	}
	if token != "abc" || key != "def" {
		t.Errorf("token = %q, key = %q", token, key)
	}
}

func TestVerifyRejectsBrokenCredentials(t *testing.T) {
	_, _, err := Verify(`vapid t=abc, k=not-base64!`, "https://push.example.com", time.Now())
	if err == nil {
		t.Fatal("an invalid key must be rejected")
	}
	if !errors.Is(err, ErrBadCredential) {
		t.Errorf("err = %v, want ErrBadCredential", err)
	}
}

func TestVerifyTokenRejectsMalformedTokens(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey
	now := time.Now()

	header := b64JSON(t, map[string]string{"typ": "JWT", "alg": "ES256"})
	payload := b64JSON(t, map[string]any{
		"aud": "https://push.example.com",
		"exp": now.Add(time.Hour).Unix(),
	})
	signature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	for name, tc := range map[string]struct {
		token string
		want  error
	}{
		"no segments":        {"abc", ErrBadCredential},
		"two segments":       {header + "." + payload, ErrBadCredential},
		"empty segment":      {header + "..", ErrBadCredential},
		"header encoding":    {"!!!." + payload + "." + signature, ErrBadCredential},
		"header json":        {base64.RawURLEncoding.EncodeToString([]byte("{")) + "." + payload + "." + signature, ErrBadCredential},
		"wrong typ":          {b64JSON(t, map[string]string{"typ": "JWS", "alg": "ES256"}) + "." + payload + "." + signature, ErrBadCredential},
		"wrong alg":          {b64JSON(t, map[string]string{"typ": "JWT", "alg": "RS256"}) + "." + payload + "." + signature, ErrBadAlg},
		"payload encoding":   {header + ".!!!." + signature, ErrBadCredential},
		"claims json":        {header + "." + base64.RawURLEncoding.EncodeToString([]byte("{")) + "." + signature, ErrBadCredential},
		"missing aud":        {header + "." + b64JSON(t, map[string]any{"exp": now.Add(time.Hour).Unix()}) + "." + signature, ErrBadCredential},
		"missing exp":        {header + "." + b64JSON(t, map[string]any{"aud": "https://push.example.com"}) + "." + signature, ErrBadCredential},
		"signature encoding": {header + "." + payload + ".!!!", ErrBadCredential},
		"short signature":    {header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 10)), ErrBadCredential},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyToken(tc.token, pub, "https://push.example.com", now)
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyTokenRejectsMissingPublicKey(t *testing.T) {
	_, err := VerifyToken("a.b.c", nil, "https://push.example.com", time.Now())
	if !errors.Is(err, ErrBadCredential) {
		t.Errorf("err = %v, want ErrBadCredential", err)
	}
}

func TestPublicKeyBytesRejectsForeignKeys(t *testing.T) {
	if got := PublicKeyBytes(nil); got != nil {
		t.Errorf("bytes = %v, want nil", got)
	}
	if got := EncodeKeyB64(nil); got != "" {
		t.Errorf("key = %q, want an empty string", got)
	}
	foreign := &ecdsa.PublicKey{Curve: elliptic.P224()}
	if got := PublicKeyBytes(foreign); got != nil {
		t.Errorf("bytes = %v, want nil", got)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now()
	token, err := signer.Token("https://push.example.com", "mailto:ops@example.com", issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// The token is valid when it is issued and expired one minute later.
	_, err = VerifyToken(token, &key.PublicKey, "https://push.example.com", issued.Add(2*time.Minute))
	if !errors.Is(err, ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestAuthorizationContainsTheToken(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	header, err := signer.Authorization("https://push.example.com", "mailto:ops@example.com", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(header, Scheme+" ") {
		t.Errorf("header = %q", header)
	}
	token, k, err := ParseAuthorization(header)
	if err != nil {
		t.Fatal(err)
	}
	if k != EncodeKeyB64(&key.PublicKey) {
		t.Error("the key parameter does not match the signer")
	}
	if _, err := VerifyToken(token, &key.PublicKey, "https://push.example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
}
