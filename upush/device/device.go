// Package device implements the end-device side of UnifiedPush
// (unifiedpush.org). UnifiedPush builds on Web Push: the application
// server sends an RFC 8291 encrypted message to a Web Push endpoint,
// and the distributor delivers the encrypted bytes to the end-device
// connector. This package provides the device-side subscription
// management and message decryption.
//
// The transport by which the encrypted bytes reach the device
// (Android broadcast intents, Linux D-Bus, or an embedder-specific webhook)
// is intentionally not standardized by UnifiedPush and is left to the
// embedder. This package handles the portable part: storing the
// subscription and decrypting incoming messages.
package device

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// curve is the P-256 curve used for key generation. Cached at package
// level to avoid repeated lookups.
var curve = ecdh.P256()

// Subscription is a device-side push subscription. It holds the Web Push
// endpoint provided by a UnifiedPush distributor together with the key
// material needed to decrypt incoming push messages (RFC 8291 §3.1, §3.2).
//
// The Private key must be kept secret and never sent to the application
// server or the distributor.
type Subscription struct {
	// Endpoint is the Web Push push resource URL provided by the
	// UnifiedPush distributor (RFC 8030 capability URL).
	Endpoint string

	// ConnectionToken identifies the registration between the device
	// connector and the distributor (UnifiedPush spec). Every request
	// to the connector contains this token.
	ConnectionToken string

	// Distributor is the name of the UnifiedPush distributor.
	Distributor string

	// Public is the device's ECDH public key. It is shared with the
	// application server so it can encrypt messages for this device.
	Public *ecdh.PublicKey

	// Private is the device's ECDH private key. It is used to decrypt
	// incoming push messages and must be kept secret.
	Private *ecdh.PrivateKey

	// AuthSecret is the 16-byte authentication secret used in key
	// derivation (RFC 8291 §3.2).
	AuthSecret []byte

	// publicKeyBytes is the uncompressed encoding of Public, computed once
	// at construction time and reused for every decryption to avoid
	// recomputing the point encoding on each message.
	publicKeyBytes []byte
}

// Validate checks the subscription for internal consistency.
func (s *Subscription) Validate() error {
	if s.Endpoint == "" {
		return errors.New("device: missing endpoint")
	}
	if s.Public == nil {
		return errors.New("device: missing public key")
	}
	if s.Private == nil {
		return errors.New("device: missing private key")
	}
	if len(s.AuthSecret) != pushmsg.AuthSecretSize {
		return fmt.Errorf("device: auth secret must be %d bytes, got %d",
			pushmsg.AuthSecretSize, len(s.AuthSecret))
	}
	return nil
}

// PublicKeyB64 returns the base64url-encoded uncompressed P-256 public key,
// suitable for sharing with the application server out of band. The result
// is computed once at construction time and cached.
func (s *Subscription) PublicKeyB64() string {
	return base64.RawURLEncoding.EncodeToString(s.publicKeyBytes)
}

// Receiver decrypts incoming UnifiedPush push messages for a device
// subscription.
type Receiver struct {
	sub *Subscription
}

// NewReceiver creates a Receiver for the given subscription.
func NewReceiver(sub *Subscription) *Receiver {
	return &Receiver{sub: sub}
}

// Decrypt decrypts a raw UnifiedPush push message (the RFC 8291 encrypted
// body delivered by the distributor) and returns the plaintext payload.
func (r *Receiver) Decrypt(body []byte) ([]byte, error) {
	if r.sub == nil {
		return nil, errors.New("device: receiver has no subscription")
	}
	return pushmsg.Decrypt(body, r.sub.AuthSecret, r.sub.Private)
}

// Subscription returns the underlying subscription.
func (r *Receiver) Subscription() *Subscription {
	return r.sub
}

// GenerateSubscription creates a fresh device-side subscription with new
// key material, suitable for registering with a UnifiedPush distributor.
// The public key and endpoint should be delivered to the application server
// out of band; the private key stays on the device.
func GenerateSubscription(endpoint, connectionToken, distributor string) (*Subscription, error) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		return nil, err
	}
	return &Subscription{
		Endpoint:        endpoint,
		ConnectionToken: connectionToken,
		Distributor:     distributor,
		Public:          keys.Public,
		Private:         keys.Private,
		AuthSecret:      keys.AuthSecret,
		publicKeyBytes:  keys.Public.Bytes(),
	}, nil
}
