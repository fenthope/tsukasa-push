package receiver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

func TestSubscribeBareHasNoKeyMaterial(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.SubscribeBare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub.SubscriptionURI, url+"/subscription/") {
		t.Errorf("subscription uri = %q", sub.SubscriptionURI)
	}
	if !strings.HasPrefix(sub.PushURI, url+"/push/") {
		t.Errorf("push uri = %q", sub.PushURI)
	}
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private_key", "p256dh", "auth"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("bare subscription JSON leaks %q: %s", secret, data)
		}
	}
	if err := r.Unsubscribe(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
}

func TestSubscribeUsesExistingKeys(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.Subscribe(context.Background(), WithExistingKeys(keys))
	if err != nil {
		t.Fatal(err)
	}
	if sub.P256DH != base64.RawURLEncoding.EncodeToString(keys.Public.Bytes()) {
		t.Error("p256dh does not match the existing keys")
	}
	if sub.Auth != base64.RawURLEncoding.EncodeToString(keys.AuthSecret) {
		t.Error("auth does not match the existing keys")
	}
	back, err := sub.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if !back.Private.Equal(keys.Private) {
		t.Error("private key does not match the existing keys")
	}
}

func TestSubscribeRejectsInconsistentExistingKeys(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	other, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := r.Subscribe(ctx, WithExistingKeys(nil)); err == nil {
		t.Error("nil keys must be rejected")
	}
	if _, err := r.Subscribe(ctx, WithExistingKeys(&pushmsg.UAKeys{Private: keys.Private})); err == nil {
		t.Error("missing public key must be rejected")
	}
	if _, err := r.Subscribe(ctx, WithExistingKeys(&pushmsg.UAKeys{
		Private: keys.Private, Public: other.Public, AuthSecret: keys.AuthSecret,
	})); err == nil {
		t.Error("mismatched key pair must be rejected")
	}
	if _, err := r.Subscribe(ctx, WithExistingKeys(&pushmsg.UAKeys{
		Private: keys.Private, Public: keys.Public,
	})); err == nil {
		t.Error("missing auth secret must be rejected")
	}
}

func TestPollRawReturnsCiphertext(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Location", "/message/abc")
		w.Write([]byte("encrypted bytes"))
	})
	sub := &Subscription{
		ServiceURL:      srv.URL,
		SubscriptionURI: srv.URL + "/subscription/abc",
		PushURI:         srv.URL + "/push/abc",
	}
	raw, err := r.PollRaw(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw.Body) != "encrypted bytes" {
		t.Errorf("body = %q", raw.Body)
	}
	if raw.URI != srv.URL+"/message/abc" {
		t.Errorf("URI = %q", raw.URI)
	}
	if raw.ReceivedAt.IsZero() {
		t.Error("missing receive time")
	}
}

func TestPollRawAcceptsKeyedSubscriptions(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	sub, _ := mockSubscription(t, srv.URL)
	if _, err := r.PollRaw(context.Background(), sub); !errors.Is(err, ErrNoMessage) {
		t.Errorf("want ErrNoMessage, got %v", err)
	}
	if _, err := r.PollRaw(context.Background(), &sub.Subscription); !errors.Is(err, ErrNoMessage) {
		t.Errorf("want ErrNoMessage, got %v", err)
	}
	if _, err := r.PollRaw(context.Background(), nil); err == nil {
		t.Error("nil subscription must be rejected")
	}
}

func TestAppSubscriptionNeedsNoPrivateKey(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := &KeyedSubscription{
		Subscription: Subscription{PushURI: "https://push.example.net/push/abc"},
		P256DH:       base64.RawURLEncoding.EncodeToString(keys.Public.Bytes()),
		Auth:         base64.RawURLEncoding.EncodeToString(keys.AuthSecret),
	}
	app, err := sub.AppSubscription()
	if err != nil {
		t.Fatal(err)
	}
	if app.Endpoint != sub.PushURI {
		t.Errorf("endpoint = %q", app.Endpoint)
	}
	if !app.Public.Equal(keys.Public) {
		t.Error("public key mismatch")
	}
}

func TestKeyedSubscriptionJSONStaysFlat(t *testing.T) {

	sub := &KeyedSubscription{
		Subscription: Subscription{
			ServiceURL:      "https://push.example.net",
			SubscriptionURI: "https://push.example.net/subscription/abc",
			PushURI:         "https://push.example.net/push/abc",
		},
		P256DH:     "pub",
		Auth:       "auth",
		PrivateKey: "priv",
	}
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service_url", "subscription_uri", "push_uri", "p256dh", "auth", "private_key"} {
		if _, ok := fields[name]; !ok {
			t.Errorf("flat field %q missing: %s", name, data)
		}
	}
	// Old documents saved before the role split decode unchanged.
	var back KeyedSubscription
	if err := json.Unmarshal([]byte(`{"service_url":"https://push.example.net",`+
		`"subscription_uri":"https://push.example.net/subscription/abc",`+
		`"push_uri":"https://push.example.net/push/abc",`+
		`"p256dh":"pub","auth":"auth","private_key":"priv"}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.PushURI != sub.PushURI || back.PrivateKey != sub.PrivateKey {
		t.Error("legacy document decoded incorrectly")
	}
}
