package device

import (
	"testing"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

func TestGenerateSubscription(t *testing.T) {
	sub, err := GenerateSubscription(
		"https://push.example.com/push/abc",
		"conn-token-123",
		"example-distributor",
	)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Endpoint != "https://push.example.com/push/abc" {
		t.Errorf("endpoint = %q", sub.Endpoint)
	}
	if sub.ConnectionToken != "conn-token-123" {
		t.Errorf("connection token = %q", sub.ConnectionToken)
	}
	if sub.Distributor != "example-distributor" {
		t.Errorf("distributor = %q", sub.Distributor)
	}
	if sub.Public == nil {
		t.Error("missing public key")
	}
	if sub.Private == nil {
		t.Error("missing private key")
	}
	if len(sub.AuthSecret) != pushmsg.AuthSecretSize {
		t.Errorf("auth secret size = %d, want %d", len(sub.AuthSecret), pushmsg.AuthSecretSize)
	}
	if err := sub.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestSubscriptionValidateRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		sub  *Subscription
	}{
		{"empty endpoint", &Subscription{
			ConnectionToken: "token",
			AuthSecret:      make([]byte, 16),
		}},
		{"missing public key", &Subscription{
			Endpoint:   "https://x/push",
			Private:    nil,
			AuthSecret: make([]byte, 16),
		}},
		{"missing private key", &Subscription{
			Endpoint:   "https://x/push",
			Public:     nil,
			AuthSecret: make([]byte, 16),
		}},
		{"wrong auth size", &Subscription{
			Endpoint:   "https://x/push",
			AuthSecret: []byte("short"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.sub.Validate(); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

func TestReceiverDecrypt(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := &Subscription{
		Endpoint:   "https://push.example.com/push/abc",
		Public:     keys.Public,
		Private:    keys.Private,
		AuthSecret: keys.AuthSecret,
	}
	recv := NewReceiver(sub)

	payload := []byte("hello unifiedpush device")
	body, err := pushmsg.Encrypt(payload, keys.AuthSecret, keys.Public)
	if err != nil {
		t.Fatal(err)
	}

	got, err := recv.Decrypt(body)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestReceiverDecryptRejectsTamperedBody(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := &Subscription{
		Public:     keys.Public,
		Private:    keys.Private,
		AuthSecret: keys.AuthSecret,
	}
	recv := NewReceiver(sub)

	if _, err := recv.Decrypt([]byte("tampered")); err == nil {
		t.Error("expected decrypt to fail on tampered body")
	}
}

func TestReceiverNilSubscription(t *testing.T) {
	recv := NewReceiver(nil)
	if _, err := recv.Decrypt([]byte("body")); err == nil {
		t.Error("expected error for nil subscription")
	}
}

func TestReceiverSubscription(t *testing.T) {
	sub, err := GenerateSubscription("https://x/push", "tok", "dist")
	if err != nil {
		t.Fatal(err)
	}
	recv := NewReceiver(sub)
	if recv.Subscription() != sub {
		t.Error("subscription mismatch")
	}
}
