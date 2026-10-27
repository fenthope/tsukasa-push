package pushmsg

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

// Inputs of the RFC 8291 §5 / Appendix A example, base64url.
const (
	plaintextB64  = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"
	asPrivateB64  = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	asPublicB64   = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	uaPrivateB64  = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	uaPublicB64   = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	saltB64       = "DGv6ra1nlYgDCS1FRnbzlw"
	authSecretB64 = "BTBZMqHH6r4Tts7J_aSIgg"
	headerB64     = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	ciphertextB64 = "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ"
	ecdhSecretB64 = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs"
	prkKeyB64     = "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k"
	ikmB64        = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg"
	prkB64        = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc"
	cekB64        = "oIhVW04MRdy2XN9CiKLxTg"
	nonceB64      = "4h_95klXJ5E_qnoN"
)

func mustB64u(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return b
}

func checkBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", name, got, want)
	}
}

func TestRFC8291Example(t *testing.T) {
	plaintext := mustB64u(t, plaintextB64)
	auth := mustB64u(t, authSecretB64)
	salt := mustB64u(t, saltB64)

	asPriv, err := ecdh.P256().NewPrivateKey(mustB64u(t, asPrivateB64))
	if err != nil {
		t.Fatal(err)
	}
	uaPriv, err := ecdh.P256().NewPrivateKey(mustB64u(t, uaPrivateB64))
	if err != nil {
		t.Fatal(err)
	}
	uaPub, err := ecdh.P256().NewPublicKey(mustB64u(t, uaPublicB64))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(uaPriv.PublicKey().Bytes(), uaPub.Bytes()) {
		t.Fatal("ua key pair mismatch")
	}

	// ECDH secret (Appendix A).
	shared, err := asPriv.ECDH(uaPub)
	if err != nil {
		t.Fatal(err)
	}
	checkBytes(t, "ecdh_secret", shared, mustB64u(t, ecdhSecretB64))

	// PRK_key = HKDF-Extract(salt=auth_secret, IKM=ecdh_secret).
	prkKey, err := hkdf.Extract(sha256.New, shared, auth)
	if err != nil {
		t.Fatal(err)
	}
	checkBytes(t, "prk_key", prkKey, mustB64u(t, prkKeyB64))

	// HKDF chain (Appendix A). The PRK for the key combining step is not
	// returned by deriveKeys; IKM covers the chain from there on.
	d, err := deriveKeys(shared, auth, salt, uaPub.Bytes(), asPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	checkBytes(t, "ikm", d.ikm, mustB64u(t, ikmB64))
	checkBytes(t, "prk", d.prk, mustB64u(t, prkB64))
	checkBytes(t, "cek", d.cek, mustB64u(t, cekB64))
	checkBytes(t, "nonce", d.nonce, mustB64u(t, nonceB64))

	// Encrypting with the fixed key and salt must reproduce the Appendix A
	// header||ciphertext byte for byte.
	want := append(mustB64u(t, headerB64), mustB64u(t, ciphertextB64)...)
	if len(want) != HeaderSize+58 {
		t.Fatalf("vector length %d", len(want))
	}
	got, err := EncryptWith(plaintext, auth, uaPub, asPriv, salt)
	if err != nil {
		t.Fatal(err)
	}
	checkBytes(t, "body", got, want)

	// The receiver path must recover the plaintext from the RFC body.
	back, err := Decrypt(want, auth, uaPriv)
	if err != nil {
		t.Fatal(err)
	}
	checkBytes(t, "plaintext", back, plaintext)
	if string(back) != "When I grow up, I want to be a watermelon" {
		t.Errorf("unexpected plaintext %q", back)
	}
}

func TestRoundTrip(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.AuthSecret) != AuthSecretSize {
		t.Fatalf("auth secret size %d", len(keys.AuthSecret))
	}
	if keys.Public != keys.Private.PublicKey() {
		t.Fatal("public key mismatch")
	}

	for _, size := range []int{0, 1, 42, 1000, MaxPlaintextSize} {
		plain := bytes.Repeat([]byte{byte(size)}, size)
		body, err := Encrypt(plain, keys.AuthSecret, keys.Public)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(body) > MaxPayloadSize {
			t.Fatalf("size %d: body %d exceeds payload limit", size, len(body))
		}
		back, err := Decrypt(body, keys.AuthSecret, keys.Private)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		checkBytes(t, "roundtrip", back, plain)
	}

	if _, err := Encrypt(make([]byte, MaxPlaintextSize+1), keys.AuthSecret, keys.Public); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("want ErrPayloadTooLarge, got %v", err)
	}
}

func TestDecryptRejects(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("tamper me")
	body, err := Encrypt(plain, keys.AuthSecret, keys.Public)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("truncated", func(t *testing.T) {
		if _, err := Decrypt(body[:HeaderSize], keys.AuthSecret, keys.Private); !errors.Is(err, ErrMalformed) {
			t.Errorf("want ErrMalformed, got %v", err)
		}
	})
	t.Run("bad idlen", func(t *testing.T) {
		bad := bytes.Clone(body)
		bad[20] = 64
		if _, err := Decrypt(bad, keys.AuthSecret, keys.Private); !errors.Is(err, ErrMalformed) {
			t.Errorf("want ErrMalformed, got %v", err)
		}
	})
	t.Run("wrong auth secret", func(t *testing.T) {
		other := make([]byte, AuthSecretSize)
		if _, err := Decrypt(body, other, keys.Private); !errors.Is(err, ErrDecrypt) {
			t.Errorf("want ErrDecrypt, got %v", err)
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		bad := bytes.Clone(body)
		bad[len(bad)-1] ^= 0xff
		if _, err := Decrypt(bad, keys.AuthSecret, keys.Private); !errors.Is(err, ErrDecrypt) {
			t.Errorf("want ErrDecrypt, got %v", err)
		}
	})
	t.Run("sender key not on curve", func(t *testing.T) {
		bad := bytes.Clone(body)
		bad[21+KeyIDSize-1] ^= 0xff // perturb y coordinate
		if _, err := Decrypt(bad, keys.AuthSecret, keys.Private); err == nil {
			t.Error("want error for off-curve point")
		}
	})
}

func TestPaddingDelimiter(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0xAB}, 16)
	auth := bytes.Repeat([]byte{0xCD}, AuthSecretSize)

	// A body with extra zero padding after the delimiter must decrypt.
	body, err := encryptPadded(plain42(), auth, keys, salt, []byte{paddingDelimiter, 0x00, 0x00, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decrypt(body, auth, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	checkBytes(t, "padded plaintext", back, plain42())

	// A wrong delimiter octet must be rejected (RFC 8291 §4).
	body, err = encryptPadded(plain42(), auth, keys, salt, []byte{0x04})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(body, auth, keys.Private); !errors.Is(err, ErrMalformed) {
		t.Errorf("want ErrMalformed, got %v", err)
	}
}

func plain42() []byte { return bytes.Repeat([]byte{'x'}, 42) }

// encryptPadded seals plaintext||pad exactly like EncryptWith but with
// caller-controlled trailing padding octets.
func encryptPadded(plaintext, authSecret []byte, keys *UAKeys, salt, pad []byte) ([]byte, error) {
	sender, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := sender.ECDH(keys.Public)
	if err != nil {
		return nil, err
	}
	senderPublic := sender.PublicKey().Bytes()
	d, err := deriveKeys(shared, authSecret, salt, keys.Public.Bytes(), senderPublic)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(d.cek)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, HeaderSize)
	body = append(body, salt...)
	body = append(body, 0x00, 0x00, 0x10, 0x00) // rs = 4096
	body = append(body, KeyIDSize)
	body = append(body, senderPublic...)
	return aead.Seal(body, d.nonce, append(bytes.Clone(plaintext), pad...), nil), nil
}
