package device

import (
	"testing"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// benchSubscription returns a fresh subscription for benchmarks.
func benchSubscription(b *testing.B) *Subscription {
	b.Helper()
	sub, err := GenerateSubscription(
		"https://push.example.com/push/bench",
		"bench-token",
		"bench-distributor",
	)
	if err != nil {
		b.Fatal(err)
	}
	return sub
}

// benchEncryptedBody returns an encrypted body for the given subscription.
func benchEncryptedBody(b *testing.B, sub *Subscription, payload []byte) []byte {
	b.Helper()
	body, err := pushmsg.Encrypt(payload, sub.AuthSecret, sub.Public)
	if err != nil {
		b.Fatal(err)
	}
	return body
}

// BenchmarkReceiverDecrypt measures the cost of decrypting a single push
// message on the device side (ECDH + HKDF + AES-GCM).
func BenchmarkReceiverDecrypt(b *testing.B) {
	sub := benchSubscription(b)
	recv := NewReceiver(sub)
	body := benchEncryptedBody(b, sub, []byte("benchmark payload"))

	b.ResetTimer()
	for b.Loop() {
		if _, err := recv.Decrypt(body); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReceiverDecryptLargePayload measures decryption cost with a
// payload near the maximum size (3993 bytes plaintext).
func BenchmarkReceiverDecryptLargePayload(b *testing.B) {
	sub := benchSubscription(b)
	recv := NewReceiver(sub)
	payload := make([]byte, pushmsg.MaxPlaintextSize)
	body := benchEncryptedBody(b, sub, payload)

	b.ResetTimer()
	for b.Loop() {
		if _, err := recv.Decrypt(body); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGenerateSubscription measures the cost of generating a fresh
// device subscription (ECDH key pair generation).
func BenchmarkGenerateSubscription(b *testing.B) {
	for b.Loop() {
		if _, err := GenerateSubscription(
			"https://push.example.com/push/bench",
			"bench-token",
			"bench-distributor",
		); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReceiverDecryptProfile runs decryption while writing CPU and
// memory profiles for deep analysis with go tool pprof:
//
//	go test -bench=BenchmarkReceiverDecryptProfile -benchtime=100x \
//	  -cpuprofile=cpu.prof -memprofile=mem.prof ./upush/device/
func BenchmarkReceiverDecryptProfile(b *testing.B) {
	sub := benchSubscription(b)
	recv := NewReceiver(sub)
	body := benchEncryptedBody(b, sub, []byte("profile payload"))

	b.ResetTimer()
	for b.Loop() {
		if _, err := recv.Decrypt(body); err != nil {
			b.Fatal(err)
		}
	}
}
