package pushmsg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Errors returned by this package.
var (
	// ErrPayloadTooLarge indicates a plaintext that cannot fit into a
	// single MaxPayloadSize payload (RFC 8291 §4).
	ErrPayloadTooLarge = errors.New("pushmsg: plaintext exceeds maximum size")

	// ErrMalformed indicates a body that is not a well formed single
	// record aes128gcm coding.
	ErrMalformed = errors.New("pushmsg: malformed aes128gcm content")

	// ErrDecrypt indicates AEAD authentication failure, e.g. a wrong
	// authentication secret or a tampered message.
	ErrDecrypt = errors.New("pushmsg: decryption failed")
)

// paddingDelimiter is the mandatory final padding octet (RFC 8188 §3,
// checked per RFC 8291 §4).
const paddingDelimiter = 0x02

// curve is the P-256 curve used for all ECDH key agreement. Cached at
// package level to avoid repeated lookups on every encrypt/decrypt.
var curve = ecdh.P256()

// NewPublicKey parses an uncompressed P-256 public key, validating that the
// point lies on the curve.
func NewPublicKey(raw []byte) (*ecdh.PublicKey, error) {
	pub, err := curve.NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: invalid P-256 public key: %w", err)
	}
	return pub, nil
}

// NewPrivateKey parses a raw P-256 private key.
func NewPrivateKey(raw []byte) (*ecdh.PrivateKey, error) {
	priv, err := curve.NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: invalid P-256 private key: %w", err)
	}
	return priv, nil
}

// GenerateUAKeys creates a fresh P-256 key pair and authentication secret
// for a subscription (RFC 8291 §3.1, §3.2).
func GenerateUAKeys() (*UAKeys, error) {
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: generating ECDH key: %w", err)
	}
	auth := make([]byte, AuthSecretSize)
	if _, err := io.ReadFull(rand.Reader, auth); err != nil {
		return nil, fmt.Errorf("pushmsg: generating auth secret: %w", err)
	}
	return &UAKeys{Private: private, Public: private.PublicKey(), AuthSecret: auth}, nil
}

// derived carries the key material produced by the RFC 8291 §3.4 derivation
// sequence. The intermediate values exist for test observability.
type derived struct {
	ikm   []byte
	prk   []byte
	cek   []byte
	nonce []byte
}

// deriveKeys runs the full RFC 8291 §3.4 + RFC 8188 §2.2/§2.3 derivation.
// uaPublic and senderPublic are uncompressed P-256 points.
func deriveKeys(ecdhSecret, authSecret, salt, uaPublic, senderPublic []byte) (derived, error) {
	var d derived

	// HKDF-Extract(salt=auth_secret, IKM=ecdh_secret) then
	// HKDF-Expand with key_info = "WebPush: info" || 0x00 || ua_public || as_public.
	prkKey, err := hkdf.Extract(sha256.New, ecdhSecret, authSecret)
	if err != nil {
		return d, fmt.Errorf("pushmsg: hkdf extract key: %w", err)
	}
	keyInfo := make([]byte, 0, 14+1+len(uaPublic)+len(senderPublic))
	keyInfo = append(keyInfo, "WebPush: info"...)
	keyInfo = append(keyInfo, 0x00)
	keyInfo = append(keyInfo, uaPublic...)
	keyInfo = append(keyInfo, senderPublic...)
	d.ikm, err = hkdf.Expand(sha256.New, prkKey, string(keyInfo), 32)
	if err != nil {
		return d, fmt.Errorf("pushmsg: hkdf expand ikm: %w", err)
	}

	// HKDF-Extract(salt, IKM) per RFC 8188 §2.2.
	d.prk, err = hkdf.Extract(sha256.New, d.ikm, salt)
	if err != nil {
		return d, fmt.Errorf("pushmsg: hkdf extract prk: %w", err)
	}

	// CEK and NONCE per RFC 8188 §2.2, §2.3. The record sequence number is
	// zero for the single record mandated by RFC 8291 §4, so the nonce is
	// used unmodified.
	d.cek, err = hkdf.Expand(sha256.New, d.prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return d, fmt.Errorf("pushmsg: hkdf expand cek: %w", err)
	}
	d.nonce, err = hkdf.Expand(sha256.New, d.prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return d, fmt.Errorf("pushmsg: hkdf expand nonce: %w", err)
	}
	return d, nil
}

// Encrypt encrypts plaintext for the holder of uaPublic as a single-record
// aes128gcm body, generating an ephemeral sender key pair and salt.
func Encrypt(plaintext, authSecret []byte, uaPublic *ecdh.PublicKey) ([]byte, error) {
	sender, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: generating sender key: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("pushmsg: generating salt: %w", err)
	}
	return EncryptWith(plaintext, authSecret, uaPublic, sender, salt)
}

// EncryptWith encrypts like Encrypt but with a fixed sender key pair and
// salt, making the output deterministic. It exists for test vectors
// (RFC 8291 §5); production callers should use Encrypt.
func EncryptWith(plaintext, authSecret []byte, uaPublic *ecdh.PublicKey, sender *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, len(plaintext), MaxPlaintextSize)
	}
	if len(authSecret) != AuthSecretSize {
		return nil, fmt.Errorf("pushmsg: auth secret must be %d bytes, got %d", AuthSecretSize, len(authSecret))
	}
	if len(salt) != 16 {
		return nil, fmt.Errorf("pushmsg: salt must be 16 bytes, got %d", len(salt))
	}
	if uaPublic == nil || sender == nil {
		return nil, errors.New("pushmsg: nil key")
	}

	shared, err := sender.ECDH(uaPublic)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: ecdh: %w", err)
	}
	senderPublic := sender.PublicKey().Bytes()
	d, err := deriveKeys(shared, authSecret, salt, uaPublic.Bytes(), senderPublic)
	if err != nil {
		return nil, err
	}

	body := make([]byte, 0, HeaderSize+len(plaintext)+1+TagSize)
	var rs [4]byte
	binary.BigEndian.PutUint32(rs[:], RecordSize)
	body = append(body, salt...)
	body = append(body, rs[:]...)
	body = append(body, byte(KeyIDSize))
	body = append(body, senderPublic...)

	aead, err := newAEAD(d.cek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(body, d.nonce, append(bytes.Clone(plaintext), paddingDelimiter), nil), nil
}

// Decrypt decrypts a single-record aes128gcm body encrypted to the holder
// of uaPrivate. The rs parameter is ignored as permitted by RFC 8291 §4; a
// multi-record body fails authentication instead.
func Decrypt(body, authSecret []byte, uaPrivate *ecdh.PrivateKey) ([]byte, error) {
	if len(body) < HeaderSize+1+TagSize {
		return nil, ErrMalformed
	}
	if len(authSecret) != AuthSecretSize {
		return nil, fmt.Errorf("pushmsg: auth secret must be %d bytes, got %d", AuthSecretSize, len(authSecret))
	}
	if body[20] != KeyIDSize {
		return nil, ErrMalformed
	}
	salt := body[:16]
	senderPublic, err := curve.NewPublicKey(body[21 : 21+KeyIDSize])
	if err != nil {
		return nil, fmt.Errorf("pushmsg: sender key: %w", err)
	}
	record := body[HeaderSize:]

	shared, err := uaPrivate.ECDH(senderPublic)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: ecdh: %w", err)
	}
	senderPublicBytes := senderPublic.Bytes()
	d, err := deriveKeys(shared, authSecret, salt, uaPrivate.PublicKey().Bytes(), senderPublicBytes)
	if err != nil {
		return nil, err
	}

	aead, err := newAEAD(d.cek)
	if err != nil {
		return nil, err
	}
	padded, err := aead.Open(nil, d.nonce, record, nil)
	if err != nil {
		return nil, ErrDecrypt
	}

	// Strip zero padding and require the padding delimiter (RFC 8291 §4).
	i := len(padded)
	for i > 0 && padded[i-1] == 0x00 {
		i--
	}
	if i == 0 || padded[i-1] != paddingDelimiter {
		return nil, ErrMalformed
	}
	return padded[:i-1], nil
}

func newAEAD(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: gcm: %w", err)
	}
	return aead, nil
}
