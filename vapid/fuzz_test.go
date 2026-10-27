package vapid

import (
	"testing"
	"time"
)

// FuzzVerifyToken checks that arbitrary tokens never panic.
func FuzzVerifyToken(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		f.Fatal(err)
	}
	token, err := signer.Token("https://push.example.net", "", time.Now().Add(time.Hour))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add("")
	f.Add("a.b.c")
	f.Add("a.b.c.d")

	f.Fuzz(func(t *testing.T, tok string) {
		_, err := VerifyToken(tok, signer.Public(), "https://push.example.net", time.Now())
		if err == nil && tok != token {
			// Only the token signed by the key can verify.
			t.Fatal("unexpected valid token")
		}
	})
}

// FuzzParseAuthorization checks the credential parser against arbitrary
// header values.
func FuzzParseAuthorization(f *testing.F) {
	f.Add("vapid t=abc, k=def")
	f.Add("vapid")
	f.Add("")
	f.Add("Basic abc")

	f.Fuzz(func(t *testing.T, header string) {
		token, key, err := ParseAuthorization(header)
		if err != nil {
			return
		}
		if token == "" || key == "" {
			t.Fatal("empty parameter")
		}
	})
}

// FuzzDecodeKeyB64 checks that arbitrary keys never panic.
func FuzzDecodeKeyB64(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(EncodeKeyB64(&key.PublicKey))
	f.Add("")
	f.Add("!!!!")

	f.Fuzz(func(t *testing.T, encoded string) {
		pub, err := DecodeKeyB64(encoded)
		if err != nil {
			return
		}
		if len(PublicKeyBytes(pub)) != 65 {
			t.Fatal("unexpected key size")
		}
	})
}
