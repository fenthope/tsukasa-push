package pushmsg

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Subscription is an application server's view of a push message
// subscription: the push resource endpoint together with the key material
// needed to encrypt messages (RFC 8291 §2.1).
type Subscription struct {
	Endpoint   string
	Public     *ecdh.PublicKey
	AuthSecret []byte
}

// subscriptionJSON mirrors the Push API PushSubscription.toJSON() shape
// (W3C Push API §PushSubscription), the interchange format between user
// agents and application servers.
type subscriptionJSON struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// ParseSubscription decodes a Push API subscription JSON document.
func ParseSubscription(data []byte) (*Subscription, error) {
	var sj subscriptionJSON
	if err := json.Unmarshal(data, &sj); err != nil {
		return nil, fmt.Errorf("pushmsg: subscription json: %w", err)
	}
	if sj.Endpoint == "" {
		return nil, fmt.Errorf("%w: missing endpoint", ErrMalformed)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sj.Keys.P256dh)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: p256dh encoding: %w", err)
	}
	pub, err := curve.NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: p256dh point: %w", err)
	}
	auth, err := base64.RawURLEncoding.DecodeString(sj.Keys.Auth)
	if err != nil {
		return nil, fmt.Errorf("pushmsg: auth encoding: %w", err)
	}
	if len(auth) != AuthSecretSize {
		return nil, fmt.Errorf("pushmsg: auth secret must be %d bytes, got %d", AuthSecretSize, len(auth))
	}
	return &Subscription{Endpoint: sj.Endpoint, Public: pub, AuthSecret: auth}, nil
}

// MarshalJSON renders the subscription in the Push API JSON shape.
func (s *Subscription) MarshalJSON() ([]byte, error) {
	var sj subscriptionJSON
	sj.Endpoint = s.Endpoint
	sj.Keys.P256dh = base64.RawURLEncoding.EncodeToString(s.Public.Bytes())
	sj.Keys.Auth = base64.RawURLEncoding.EncodeToString(s.AuthSecret)
	return json.Marshal(sj)
}
