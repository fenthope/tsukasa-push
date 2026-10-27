package pushmsg

import (
	"bytes"
	"testing"
)

func benchmarkKeys(b *testing.B) *UAKeys {
	b.Helper()
	keys, err := GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	return keys
}

func BenchmarkGenerateUAKeys(b *testing.B) {
	for b.Loop() {
		if _, err := GenerateUAKeys(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt(b *testing.B) {
	keys := benchmarkKeys(b)
	payload := bytes.Repeat([]byte("m"), 1024)
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := Encrypt(payload, keys.AuthSecret, keys.Public); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	keys := benchmarkKeys(b)
	payload := bytes.Repeat([]byte("m"), 1024)
	body, err := Encrypt(payload, keys.AuthSecret, keys.Public)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := Decrypt(body, keys.AuthSecret, keys.Private); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveKeys(b *testing.B) {
	keys := benchmarkKeys(b)
	sender, err := GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	shared, err := sender.Private.ECDH(keys.Public)
	if err != nil {
		b.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x01}, 16)
	for b.Loop() {
		if _, err := deriveKeys(shared, keys.AuthSecret, salt, keys.Public.Bytes(), sender.Public.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}
