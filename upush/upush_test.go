package upush

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/sender"
	"github.com/fenthope/tsukasa-push/vapid"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestSubscriptionValidate(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	valid := Subscription{
		Endpoint:  "https://push.example.com/push/abc",
		P256DHB64: b64(keys.Public.Bytes()),
		AuthB64:   b64(keys.AuthSecret),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid subscription: %v", err)
	}

	cases := []struct {
		name string
		sub  Subscription
	}{
		{"empty endpoint", Subscription{
			P256DHB64: b64(keys.Public.Bytes()),
			AuthB64:   b64(keys.AuthSecret),
		}},
		{"endpoint too long", Subscription{
			Endpoint:  strings.Repeat("a", MaxEndpointBytes+1),
			P256DHB64: b64(keys.Public.Bytes()),
			AuthB64:   b64(keys.AuthSecret),
		}},
		{"invalid endpoint url", Subscription{
			Endpoint:  "://broken",
			P256DHB64: b64(keys.Public.Bytes()),
			AuthB64:   b64(keys.AuthSecret),
		}},
		{"bad p256dh encoding", Subscription{
			Endpoint:  "https://push.example.com/push/abc",
			P256DHB64: "!!!",
			AuthB64:   b64(keys.AuthSecret),
		}},
		{"bad auth encoding", Subscription{
			Endpoint:  "https://push.example.com/push/abc",
			P256DHB64: b64(keys.Public.Bytes()),
			AuthB64:   "!!!",
		}},
		{"wrong auth size", Subscription{
			Endpoint:  "https://push.example.com/push/abc",
			P256DHB64: b64(keys.Public.Bytes()),
			AuthB64:   b64([]byte("short")),
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

func TestSubscriptionToPushmsg(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := Subscription{
		Endpoint:  "https://push.example.com/push/abc",
		P256DHB64: b64(keys.Public.Bytes()),
		AuthB64:   b64(keys.AuthSecret),
	}
	converted, err := sub.ToPushmsg()
	if err != nil {
		t.Fatal(err)
	}
	if converted.Endpoint != sub.Endpoint {
		t.Errorf("endpoint = %q, want %q", converted.Endpoint, sub.Endpoint)
	}
	if !converted.Public.Equal(keys.Public) {
		t.Error("public key does not match")
	}
	if string(converted.AuthSecret) != string(keys.AuthSecret) {
		t.Error("auth secret does not match")
	}
}

func TestPushDeliversMessage(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := &Subscription{
		P256DHB64: b64(keys.Public.Bytes()),
		AuthB64:   b64(keys.AuthSecret),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/push/abc"

	vapidKey, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(vapidKey)
	if err != nil {
		t.Fatal(err)
	}
	snd := sender.New(sender.WithVAPID(signer, "mailto:ops@example.com"))

	payload := []byte("hello unifiedpush")
	if err := Push(context.Background(), snd, sub, sender.Message{
		Payload: payload,
		TTL:     60,
		Urgency: pushmsg.UrgencyHigh,
		Topic:   "demo",
	}); err != nil {
		t.Fatalf("push: %v", err)
	}
}

func TestPushRejectsInvalidSubscription(t *testing.T) {
	snd := sender.New()
	if err := Push(context.Background(), snd, &Subscription{}, sender.Message{Payload: []byte("x")}); err == nil {
		t.Error("expected an error for an invalid subscription")
	}
}

func TestPushRejectsOversizedPayload(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := &Subscription{
		Endpoint:  "https://push.example.com/push/abc",
		P256DHB64: b64(keys.Public.Bytes()),
		AuthB64:   b64(keys.AuthSecret),
	}
	vapidKey, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(vapidKey)
	if err != nil {
		t.Fatal(err)
	}
	snd := sender.New(sender.WithVAPID(signer, "mailto:ops@example.com"))

	oversized := make([]byte, pushmsg.MaxPlaintextSize+1)
	if err := Push(context.Background(), snd, sub, sender.Message{Payload: oversized}); err == nil {
		t.Error("expected an error for an oversized payload")
	} else if !errors.Is(err, pushmsg.ErrPayloadTooLarge) {
		t.Errorf("err = %v, want ErrPayloadTooLarge", err)
	}
}
