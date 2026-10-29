// Package e2e_test exercises the complete Web Push flow of the SDK: an
// application server sends a message to a push service, the user agent
// receives and decrypts it and acknowledges the delivery.
package e2e_test

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/receiver"
	"github.com/fenthope/tsukasa-push/sender"
	"github.com/fenthope/tsukasa-push/service"
	"github.com/fenthope/tsukasa-push/vapid"
)

func newPushService(t *testing.T) string {
	t.Helper()
	engine := touka.Default()
	svc := service.New(service.WithSubscriptionTTL(time.Hour))
	svc.Register(engine)
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestEndToEndDelivery(t *testing.T) {
	serviceURL := newPushService(t)

	ua, err := receiver.New(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ua.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	appSub, err := sub.AppSubscription()
	if err != nil {
		t.Fatal(err)
	}

	app := sender.New()
	payload := []byte(`{"title":"hello","body":"world"}`)
	if err := app.Send(context.Background(), appSub, sender.Message{Payload: payload, TTL: 60}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, err := ua.Poll(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Payload) != string(payload) {
		t.Errorf("payload = %q", msg.Payload)
	}
	if msg.URI == "" {
		t.Error("missing message URI")
	}
	if err := ua.Ack(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEndWithVAPIDRestriction(t *testing.T) {
	serviceURL := newPushService(t)

	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}

	ua, err := receiver.New(serviceURL, receiver.WithRestrictedKey(signer))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ua.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	appSub, err := sub.AppSubscription()
	if err != nil {
		t.Fatal(err)
	}

	// Without VAPID credentials the push service rejects the message.
	if err := sender.New().Send(context.Background(), appSub, sender.Message{TTL: 60}); !errors.Is(err, sender.ErrVAPIDRequired) {
		t.Errorf("want ErrVAPIDRequired, got %v", err)
	}

	app := sender.New(sender.WithVAPID(signer, "mailto:ops@example.com"))
	if err := app.Send(context.Background(), appSub, sender.Message{Payload: []byte("vapid"), TTL: 60}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, err := ua.Poll(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Payload) != "vapid" {
		t.Errorf("payload = %q", msg.Payload)
	}
}

func TestEndToEndSubscriptionGone(t *testing.T) {
	serviceURL := newPushService(t)

	ua, err := receiver.New(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ua.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	appSub, err := sub.AppSubscription()
	if err != nil {
		t.Fatal(err)
	}
	if err := ua.Unsubscribe(context.Background(), sub); err != nil {
		t.Fatal(err)
	}

	err = sender.New().Send(context.Background(), appSub, sender.Message{TTL: 60})
	if !errors.Is(err, sender.ErrSubscriptionNotFound) && !errors.Is(err, sender.ErrSubscriptionGone) {
		t.Errorf("want subscription gone, got %v", err)
	}
}

func TestEndToEndQueuedMessageIsDeliveredLater(t *testing.T) {
	serviceURL := newPushService(t)

	ua, err := receiver.New(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ua.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	appSub, err := sub.AppSubscription()
	if err != nil {
		t.Fatal(err)
	}

	// The message is sent before the user agent polls: the push service
	// stores it until the user agent shows up.
	if err := sender.New().Send(context.Background(), appSub, sender.Message{Payload: []byte("queued"), TTL: 60}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg, err := ua.Poll(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Payload) != "queued" {
		t.Errorf("payload = %q", msg.Payload)
	}
}

// TestEndToEndDistributorRelaysCiphertext models the connector/distributor
// role: it holds a bare subscription with no key material, relays the raw
// ciphertext to the application it serves, and the application — which
// provisioned the keys out of band — decrypts locally. The distributor
// never sees the plaintext, preserving the end-to-end boundary.
func TestEndToEndDistributorRelaysCiphertext(t *testing.T) {
	serviceURL := newPushService(t)

	// The application provisioned its own key material out of band; the
	// distributor never holds it.
	appKeys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}

	distributor, err := receiver.New(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := distributor.SubscribeBare(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// The application server encrypts to the push endpoint with the
	// application's own keys, then delivers to the shared push resource.
	app := sender.New()
	appSub := &pushmsg.Subscription{
		Endpoint:   sub.PushURI,
		Public:     appKeys.Public,
		AuthSecret: appKeys.AuthSecret,
	}
	payload := []byte("top secret")
	if err := app.Send(context.Background(), appSub, sender.Message{Payload: payload, TTL: 60}); err != nil {
		t.Fatal(err)
	}

	// The distributor polls the raw ciphertext — it cannot decrypt it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := distributor.PollRaw(ctx, sub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Body, payload) {
		t.Error("ciphertext leaks the plaintext payload")
	}
	if raw.URI == "" {
		t.Error("missing message URI")
	}

	// The application decrypts with its own private key.
	plain, err := pushmsg.Decrypt(raw.Body, appKeys.AuthSecret, appKeys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(payload) {
		t.Errorf("payload = %q", plain)
	}

	// The distributor acknowledges the relayed message.
	if err := distributor.Ack(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
}
