// Command device-demo demonstrates the UnifiedPush end-device side: a device
// generates a subscription, shares its public key with the application server
// out of band, and later decrypts an incoming push message.
//
// In a real deployment the encrypted bytes arrive via the distributor
// (Android broadcast intents or Linux D-Bus). This example simulates the
// delivery by encrypting locally and decrypting immediately.
//
//	go run ./example/device
package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/upush/device"
)

func main() {
	// Expose pprof on localhost:6060 for CPU/memory profiling:
	//   go tool pprof http://localhost:6060/debug/pprof/profile
	//   go tool pprof http://localhost:6060/debug/pprof/heap
	go func() {
		log.Println("pprof listening on http://localhost:6060/debug/pprof/")
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			log.Fatalf("pprof server: %v", err)
		}
	}()

	// 1. The device generates a subscription with fresh key material.
	// The endpoint and connection token come from the UnifiedPush
	// distributor during registration.
	sub, err := device.GenerateSubscription(
		"https://push.example.com/push/device-42",
		"conn-token-abc",
		"example-distributor",
	)
	if err != nil {
		log.Fatalf("generate subscription: %v", err)
	}
	if err := sub.Validate(); err != nil {
		log.Fatalf("validate subscription: %v", err)
	}
	log.Printf("device registered: endpoint=%s distributor=%s",
		sub.Endpoint, sub.Distributor)

	// 2. The device creates a receiver. The private key stays on the
	// device; only the public key and endpoint go to the application
	// server out of band.
	recv := device.NewReceiver(sub)

	// 3. Simulate a stream of incoming encrypted messages from the
	// distributor. In production these arrive via Android broadcast
	// intents or Linux D-Bus.
	for i := 0; i < 100; i++ {
		payload := []byte(fmt.Sprintf(`{"msg":%d,"body":"hello device"}`, i))
		body, err := pushmsg.Encrypt(payload, sub.AuthSecret, sub.Public)
		if err != nil {
			log.Fatalf("encrypt: %v", err)
		}

		// 4. Decrypt the message on the device side.
		plain, err := recv.Decrypt(body)
		if err != nil {
			log.Fatalf("decrypt: %v", err)
		}
		if string(plain) != string(payload) {
			log.Fatalf("decrypted payload mismatch: %q", plain)
		}
	}

	log.Printf("decrypted 100 messages; connection token: %s", sub.ConnectionToken)
	log.Println("profile endpoints: http://localhost:6060/debug/pprof/")
	// Keep the process alive so pprof can be attached.
	select {}
}
