package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/service"
	"github.com/fenthope/tsukasa-push/vapid"
)

// newTestStack starts a push service and returns its URL.
func newTestStack(t *testing.T, opts ...service.Option) string {
	t.Helper()
	engine := touka.Default()
	svc := service.New(opts...)
	svc.Register(engine)
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSubscribeAndUnsubscribe(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sub.SubscriptionURI, url+"/subscription/") {
		t.Errorf("subscription uri = %q", sub.SubscriptionURI)
	}
	if !strings.HasPrefix(sub.PushURI, url+"/push/") {
		t.Errorf("push uri = %q", sub.PushURI)
	}
	keys, err := sub.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.AuthSecret) != pushmsg.AuthSecretSize {
		t.Errorf("auth secret size %d", len(keys.AuthSecret))
	}
	if !keys.Public.Equal(keys.Private.PublicKey()) {
		t.Error("key pair mismatch")
	}

	app, err := sub.AppSubscription()
	if err != nil {
		t.Fatal(err)
	}
	if app.Endpoint != sub.PushURI {
		t.Errorf("endpoint = %q", app.Endpoint)
	}

	if err := r.Unsubscribe(context.Background(), sub); err != nil {
		t.Fatal(err)
	}
	if err := r.Unsubscribe(context.Background(), sub); !errors.Is(err, ErrSubscriptionGone) {
		t.Errorf("want ErrSubscriptionGone, got %v", err)
	}
}

func TestPollReportsExpiredSubscription(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Remove the subscription behind the receiver's back.
	req, err := http.NewRequest(http.MethodDelete, sub.SubscriptionURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if _, err := r.Poll(context.Background(), sub); !errors.Is(err, ErrSubscriptionExpired) {
		t.Errorf("want ErrSubscriptionExpired, got %v", err)
	}
}

func TestRestrictedSubscriptionIsAccepted(t *testing.T) {
	url := newTestStack(t)
	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(url, WithRestrictedKey(signer))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sub.PushURI == "" {
		t.Fatal("missing push uri")
	}
}

func TestSubscriptionJSONRoundTrip(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	var back KeyedSubscription
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.PushURI != sub.PushURI || back.PrivateKey != sub.PrivateKey {
		t.Error("subscription round trip mismatch")
	}
	keys, err := back.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Public.Equal(keys.Private.PublicKey()) {
		t.Error("restored key pair mismatch")
	}
}

func TestPushLinkParsing(t *testing.T) {
	header := `<https://push.example.net/push/abc>; rel="urn:ietf:params:push", ` +
		`<https://push.example.net/set/xyz>; rel="urn:ietf:params:push:set"`
	got, err := pushLink(header)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://push.example.net/push/abc" {
		t.Errorf("push uri = %q", got)
	}
	if _, err := pushLink(`<https://x>; rel="other"`); !errors.Is(err, ErrMalformedLink) {
		t.Errorf("want ErrMalformedLink, got %v", err)
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		base, ref, want string
	}{
		{"https://push.example.net", "/subscription/abc", "https://push.example.net/subscription/abc"},
		{"https://push.example.net", "subscription/abc", "https://push.example.net/subscription/abc"},
		{"https://push.example.net", "https://other/x", "https://other/x"},
	}
	for _, tc := range cases {
		if got := resolve(tc.base, tc.ref); got != tc.want {
			t.Errorf("resolve(%q, %q) = %q, want %q", tc.base, tc.ref, got, tc.want)
		}
	}
}

func TestPollTimeoutIsReported(t *testing.T) {
	url := newTestStack(t)
	r, err := New(url)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := r.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := r.Poll(ctx, sub); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want deadline exceeded, got %v", err)
	}
}
