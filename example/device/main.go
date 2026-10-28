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

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/upush/device"
)

func main() {
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

	// 3. The application server encrypts a message for this device using
	// the device's public key and auth secret. (This step happens on the
	// server, not the device; it is shown here for a complete round trip.)
	payload := []byte(`{"title":"device-demo","body":"hello device"}`)
	body, err := pushmsg.Encrypt(payload, sub.AuthSecret, sub.Public)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}

	// 4. The device receives the encrypted bytes from the distributor and
	// decrypts them. This is the UnifiedPush end-device receiving path.
	plain, err := recv.Decrypt(body)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}
	fmt.Printf("received: %s\n", plain)

	log.Printf("connection token: %s", sub.ConnectionToken)
}
