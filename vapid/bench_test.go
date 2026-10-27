package vapid

import (
	"testing"
	"time"
)

func BenchmarkToken(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		b.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := signer.Token("https://push.example.net", "mailto:ops@example.com", expiry); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyToken(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		b.Fatal(err)
	}
	token, err := signer.Token("https://push.example.net", "", time.Now().Add(time.Hour))
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := VerifyToken(token, signer.Public(), "https://push.example.net", now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeDecodeKey(b *testing.B) {
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	encoded := EncodeKeyB64(&key.PublicKey)
	b.Run("encode", func(b *testing.B) {
		for b.Loop() {
			if EncodeKeyB64(&key.PublicKey) == "" {
				b.Fatal("empty key")
			}
		}
	})
	b.Run("decode", func(b *testing.B) {
		for b.Loop() {
			if _, err := DecodeKeyB64(encoded); err != nil {
				b.Fatal(err)
			}
		}
	})
}
