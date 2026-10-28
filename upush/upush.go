// Package upush implements helpers for sending push messages through
// UnifiedPush (unifiedpush.org). UnifiedPush builds on Web Push: the
// application server sends an RFC 8291 encrypted message to a Web Push
// endpoint obtained from a UnifiedPush distributor (RFC 8030, RFC 8188,
// RFC 8291, RFC 8292).
//
// This package is a thin wrapper over the sender package: UnifiedPush does
// not introduce a new wire protocol between the application server and the
// push server. The end user application obtains an endpoint and key material
// from a UnifiedPush connector and delivers them to the application server
// during registration; the application server then uses Push to deliver
// messages.
//
// Because some distributors require VAPID authentication (RFC 8292), the
// sender passed to Push must be configured with sender.WithVAPID using the
// application server's own VAPID signing key.
package upush

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/sender"
)

// MaxEndpointBytes is the maximum length of a UnifiedPush endpoint URL.
// The endpoint is a Web Push capability URL (RFC 8030).
const MaxEndpointBytes = 1000

// Subscription holds the subscription information a UnifiedPush client
// delivers to its application server during registration.
type Subscription struct {
	// Endpoint is the Web Push push resource URL provided by the
	// distributor. It is a capability URL (RFC 8030).
	Endpoint string

	// P256DHB64 is the base64url encoded uncompressed P-256 public key of
	// the end user application (RFC 8291 §3.1).
	P256DHB64 string

	// AuthB64 is the base64url encoded 16-byte authentication secret
	// (RFC 8291 §3.2).
	AuthB64 string
}

// Validate checks the subscription against the UnifiedPush constraints.
func (s *Subscription) Validate() error {
	if s.Endpoint == "" {
		return errors.New("upush: missing endpoint")
	}
	if len(s.Endpoint) > MaxEndpointBytes {
		return fmt.Errorf("upush: endpoint too long (%d > %d bytes)", len(s.Endpoint), MaxEndpointBytes)
	}
	if _, err := url.ParseRequestURI(s.Endpoint); err != nil {
		return fmt.Errorf("upush: invalid endpoint url: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s.P256DHB64)
	if err != nil {
		return fmt.Errorf("upush: p256dh encoding: %w", err)
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return fmt.Errorf("upush: p256dh point: %w", err)
	}
	auth, err := base64.RawURLEncoding.DecodeString(s.AuthB64)
	if err != nil {
		return fmt.Errorf("upush: auth encoding: %w", err)
	}
	if len(auth) != pushmsg.AuthSecretSize {
		return fmt.Errorf("upush: auth secret must be %d bytes, got %d", pushmsg.AuthSecretSize, len(auth))
	}
	return nil
}

// ToPushmsg converts the subscription to a pushmsg.Subscription usable by
// sender.Send.
func (s *Subscription) ToPushmsg() (*pushmsg.Subscription, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	raw, _ := base64.RawURLEncoding.DecodeString(s.P256DHB64)
	pub, _ := ecdh.P256().NewPublicKey(raw)
	auth, _ := base64.RawURLEncoding.DecodeString(s.AuthB64)
	return &pushmsg.Subscription{
		Endpoint:   s.Endpoint,
		Public:     pub,
		AuthSecret: auth,
	}, nil
}

// Push delivers a message to a UnifiedPush endpoint. It is a thin wrapper
// over sender.Send: UnifiedPush uses Web Push on the wire, so no new
// protocol is involved. The sender must be configured with a VAPID signer
// (sender.WithVAPID) because some distributors require VAPID
// authentication.
//
// The message payload must be at most pushmsg.MaxPlaintextSize (3993)
// bytes; the resulting encrypted push message is at most
// pushmsg.MaxPayloadSize (4096) bytes, as required by UnifiedPush.
func Push(ctx context.Context, snd *sender.Sender, sub *Subscription, msg sender.Message) error {
	subMsg, err := sub.ToPushmsg()
	if err != nil {
		return err
	}
	if len(msg.Payload) > pushmsg.MaxPlaintextSize {
		return pushmsg.ErrPayloadTooLarge
	}
	return snd.Send(ctx, subMsg, msg)
}
