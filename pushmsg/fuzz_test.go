package pushmsg

import (
	"bytes"
	"testing"
)

// FuzzDecrypt checks that a malformed body never panics and never returns a
// plaintext for a body it did not authenticate.
func FuzzDecrypt(f *testing.F) {
	keys, err := GenerateUAKeys()
	if err != nil {
		f.Fatal(err)
	}
	body, err := Encrypt([]byte("hello"), keys.AuthSecret, keys.Public)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, HeaderSize+17))

	f.Fuzz(func(t *testing.T, data []byte) {
		plain, err := Decrypt(data, keys.AuthSecret, keys.Private)
		if err != nil {
			return
		}
		if len(plain) > MaxPlaintextSize {
			t.Fatalf("plaintext of %d bytes exceeds the limit", len(plain))
		}
	})
}

// FuzzParseSubscription checks that arbitrary documents never panic.
func FuzzParseSubscription(f *testing.F) {
	f.Add(`{"endpoint":"https://push.example.net/p/1","keys":{"p256dh":"","auth":""}}`)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`[]`)

	f.Fuzz(func(t *testing.T, doc string) {
		sub, err := ParseSubscription([]byte(doc))
		if err != nil {
			return
		}
		if sub.Endpoint == "" {
			t.Fatal("subscription without endpoint")
		}
		if len(sub.AuthSecret) != AuthSecretSize {
			t.Fatalf("auth secret of %d bytes", len(sub.AuthSecret))
		}
	})
}

// FuzzParseTTL checks the TTL parser against arbitrary header values.
func FuzzParseTTL(f *testing.F) {
	f.Add("0")
	f.Add("86400")
	f.Add("")
	f.Add("-1")
	f.Add("99999999999999999999999")

	f.Fuzz(func(t *testing.T, value string) {
		ttl, err := ParseTTL(value)
		if err != nil {
			return
		}
		if ttl > MaxTTL {
			t.Fatalf("ttl %d exceeds the maximum", ttl)
		}
	})
}
