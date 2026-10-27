package vapid

import (
	"testing"
	"time"
)

func benchmarkSigner(b *testing.B) *Signer {
	b.Helper()
	key, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	signer, err := NewSigner(key)
	if err != nil {
		b.Fatal(err)
	}
	return signer
}

func BenchmarkToken(b *testing.B) {
	signer := benchmarkSigner(b)
	expiry := time.Now().Add(time.Hour)
	for b.Loop() {
		if _, err := signer.Token("https://push.example.com", "mailto:ops@example.com", expiry); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorization(b *testing.B) {
	signer := benchmarkSigner(b)
	expiry := time.Now().Add(time.Hour)
	for b.Loop() {
		if _, err := signer.Authorization("https://push.example.com", "mailto:ops@example.com", expiry); err != nil {
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
	token, err := signer.Token("https://push.example.com", "mailto:ops@example.com", time.Now().Add(time.Hour))
	if err != nil {
		b.Fatal(err)
	}
	pub := &key.PublicKey
	for b.Loop() {
		if _, err := VerifyToken(token, pub, "https://push.example.com", time.Now()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseAuthorization(b *testing.B) {
	signer := benchmarkSigner(b)
	header, err := signer.Authorization("https://push.example.com", "mailto:ops@example.com", time.Now().Add(time.Hour))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, _, err := ParseAuthorization(header); err != nil {
			b.Fatal(err)
		}
	}
}
