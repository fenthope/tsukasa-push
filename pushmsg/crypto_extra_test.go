package pushmsg

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestNewPublicKeyRejectsInvalidKeys(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":       {},
		"too short":   {0x04},
		"not a point": {0x04, 0x01, 0x02, 0x03},
		"compressed":  {0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := NewPublicKey(raw)
			if err == nil {
				t.Fatal("an invalid key must be rejected")
			}
			if key != nil {
				t.Error("no key must be returned")
			}
			if !strings.Contains(err.Error(), "public key") {
				t.Errorf("unexpected error %v", err)
			}
		})
	}
}

func TestNewPrivateKeyRejectsInvalidKeys(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":     {},
		"too short": {0x01},
		"too long":  make([]byte, 33),
		"zero":      make([]byte, 32),
	} {
		t.Run(name, func(t *testing.T) {
			key, err := NewPrivateKey(raw)
			if err == nil {
				t.Fatal("an invalid key must be rejected")
			}
			if key != nil {
				t.Error("no key must be returned")
			}
			if !strings.Contains(err.Error(), "private key") {
				t.Errorf("unexpected error %v", err)
			}
		})
	}
}

func TestEncryptWithRejectsInvalidParameters(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sender, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 16)

	if _, err := EncryptWith([]byte("x"), []byte("short"), keys.Public, sender, salt); err == nil ||
		!strings.Contains(err.Error(), "auth secret") {
		t.Errorf("err = %v, want an auth secret error", err)
	}
	if _, err := EncryptWith([]byte("x"), keys.AuthSecret, keys.Public, sender, []byte("short")); err == nil ||
		!strings.Contains(err.Error(), "salt") {
		t.Errorf("err = %v, want a salt error", err)
	}
	if _, err := EncryptWith([]byte("x"), keys.AuthSecret, nil, sender, salt); err == nil ||
		!strings.Contains(err.Error(), "nil key") {
		t.Errorf("err = %v, want a nil key error", err)
	}
	if _, err := EncryptWith([]byte("x"), keys.AuthSecret, keys.Public, nil, salt); err == nil ||
		!strings.Contains(err.Error(), "nil key") {
		t.Errorf("err = %v, want a nil key error", err)
	}
}

func TestDecryptRejectsInvalidAuthSecret(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	body, err := Encrypt([]byte("payload"), keys.AuthSecret, keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(body, []byte("short"), keys.Private); err == nil ||
		!strings.Contains(err.Error(), "auth secret") {
		t.Errorf("err = %v, want an auth secret error", err)
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("no entropy")
}

func TestGenerateUAKeysReportsRandomFailures(t *testing.T) {
	original := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = original }()

	keys, err := GenerateUAKeys()
	if err == nil {
		t.Fatal("the failure must be reported")
	}
	if keys != nil {
		t.Error("no keys must be returned")
	}
}

func TestEncryptReportsRandomFailures(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	original := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = original }()

	body, err := Encrypt([]byte("payload"), keys.AuthSecret, keys.Public)
	if err == nil {
		t.Fatal("the failure must be reported")
	}
	if body != nil {
		t.Error("no body must be returned")
	}
}

func TestNewPublicKeyAcceptsValidKey(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewPublicKey(keys.Public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(keys.Public) {
		t.Error("the parsed key differs from the original one")
	}
}

func TestNewPrivateKeyAcceptsValidKey(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := NewPrivateKey(keys.Private.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(keys.Private) {
		t.Error("the parsed key differs from the original one")
	}
}
