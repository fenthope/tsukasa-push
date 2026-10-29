package receiver

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

// testSigner creates a VAPID signer for the mock tests.
func testSigner(t *testing.T) *vapid.Signer {
	t.Helper()
	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// mockSubscription builds a subscription with valid key material for the
// mock server tests.
func mockSubscription(t *testing.T, base string) (*KeyedSubscription, *pushmsg.UAKeys) {
	t.Helper()
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	return &KeyedSubscription{
		Subscription: Subscription{
			ServiceURL:      base,
			SubscriptionURI: base + "/subscription/abc",
			PushURI:         base + "/push/abc",
		},
		P256DH:     base64.RawURLEncoding.EncodeToString(keys.Public.Bytes()),
		Auth:       base64.RawURLEncoding.EncodeToString(keys.AuthSecret),
		PrivateKey: base64.RawURLEncoding.EncodeToString(keys.Private.Bytes()),
	}, keys
}

// mockService starts a server with the given handler and a receiver for it.
func mockService(t *testing.T, handler http.HandlerFunc) (*Receiver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	r, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return r, srv
}

func TestNewValidatesURL(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("empty URL must be rejected")
	}
	if _, err := New("://broken"); err == nil {
		t.Error("broken URL must be rejected")
	}
}

func TestSubscribeServerError(t *testing.T) {
	r, _ := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	})
	_, err := r.Subscribe(context.Background())
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want status in error, got %v", err)
	}
}

func TestSubscribeWithoutLocation(t *testing.T) {
	r, _ := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	if _, err := r.Subscribe(context.Background()); err == nil {
		t.Error("missing Location must be reported")
	}
}

func TestSubscribeWithoutPushLink(t *testing.T) {
	r, _ := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Location", "/subscription/abc")
		w.WriteHeader(http.StatusCreated)
	})
	if _, err := r.Subscribe(context.Background()); !errors.Is(err, ErrMalformedLink) {
		t.Errorf("want ErrMalformedLink, got %v", err)
	}
}

func TestSubscribeSendsRestriction(t *testing.T) {
	var body string
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		buf := make([]byte, 512)
		n, _ := req.Body.Read(buf)
		body = string(buf[:n])
		contentType = req.Header.Get("Content-Type")
		w.Header().Set("Location", "/subscription/abc")
		w.Header().Set("Link", `<http://x/push/abc>; rel="urn:ietf:params:push"`)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	r, err := New(srv.URL, WithRestrictedKey(testSigner(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Subscribe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if contentType != pushmsg.OptionsMediaType {
		t.Errorf("content type = %q", contentType)
	}
	if !strings.Contains(body, `"vapid"`) {
		t.Errorf("body = %q", body)
	}
}

func TestPollNoMessage(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	sub, _ := mockSubscription(t, srv.URL)
	if _, err := r.Poll(context.Background(), sub); !errors.Is(err, ErrNoMessage) {
		t.Errorf("want ErrNoMessage, got %v", err)
	}
}

func TestPollSubscriptionGone(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusGone)
	})
	sub, _ := mockSubscription(t, srv.URL)
	if _, err := r.Poll(context.Background(), sub); !errors.Is(err, ErrSubscriptionGone) {
		t.Errorf("want ErrSubscriptionGone, got %v", err)
	}
}

func TestPollServerError(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("upstream is down"))
	})
	sub, _ := mockSubscription(t, srv.URL)
	_, err := r.Poll(context.Background(), sub)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("want status in error, got %v", err)
	}
}

func TestPollDecryptFailure(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("not an aes128gcm body"))
	})
	sub, _ := mockSubscription(t, srv.URL)
	if _, err := r.Poll(context.Background(), sub); err == nil {
		t.Error("garbage body must be reported")
	}
}

func TestPollWithoutMessageURI(t *testing.T) {
	sub, keys := mockSubscription(t, "https://push.example.net")
	body, err := pushmsg.Encrypt([]byte("payload"), keys.AuthSecret, keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.Write(body)
	})
	sub.SubscriptionURI = r.serviceURL + "/subscription/abc"
	msg, err := r.Poll(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Payload) != "payload" {
		t.Errorf("payload = %q", msg.Payload)
	}
	if msg.URI != "" {
		t.Errorf("URI = %q, want empty", msg.URI)
	}
	if msg.ReceivedAt.IsZero() {
		t.Error("missing receive time")
	}
}

func TestPollRequiresSubscription(t *testing.T) {
	r, _ := mockService(t, func(w http.ResponseWriter, req *http.Request) {})
	if _, err := r.Poll(context.Background(), nil); err == nil {
		t.Error("nil subscription must be rejected")
	}
}

func TestAckErrors(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusGone)
	})
	if err := r.Ack(context.Background(), nil); err == nil {
		t.Error("nil message must be rejected")
	}
	if err := r.Ack(context.Background(), &Message{}); err == nil {
		t.Error("message without URI must be rejected")
	}
	if err := r.Ack(context.Background(), &Message{URI: srv.URL + "/message/x"}); !errors.Is(err, ErrSubscriptionGone) {
		t.Errorf("want ErrSubscriptionGone, got %v", err)
	}
}

func TestAckServerError(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := r.Ack(context.Background(), &Message{URI: srv.URL + "/message/x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want status in error, got %v", err)
	}
}

func TestAckAcceptsOK(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if err := r.Ack(context.Background(), &Message{URI: srv.URL + "/message/x"}); err != nil {
		t.Fatal(err)
	}
}

func TestUnsubscribeErrors(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	if err := r.Unsubscribe(context.Background(), nil); err == nil {
		t.Error("nil subscription must be rejected")
	}
	sub, _ := mockSubscription(t, srv.URL)
	if err := r.Unsubscribe(context.Background(), sub); !errors.Is(err, ErrSubscriptionGone) {
		t.Errorf("want ErrSubscriptionGone, got %v", err)
	}
}

func TestUnsubscribeServerError(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	sub, _ := mockSubscription(t, srv.URL)
	err := r.Unsubscribe(context.Background(), sub)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("want status in error, got %v", err)
	}
}

func TestRequestErrorKeepsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := requestError(ctx, errors.New("transport failed"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
	if !strings.Contains(err.Error(), "transport failed") {
		t.Errorf("want the transport error in the message, got %v", err)
	}
	if got := requestError(context.Background(), nil); got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestSplitLinksHandlesNestedCommas(t *testing.T) {
	links := splitLinks(`<http://a/1>; rel="x", <http://b/2>; title="a,b", <http://c/3>; rel="urn:ietf:params:push"`)
	if len(links) != 3 {
		t.Fatalf("got %d links: %q", len(links), links)
	}
}

func TestSubscriptionKeysRejectGarbage(t *testing.T) {
	sub := &KeyedSubscription{P256DH: "!!!", Auth: "!!!", PrivateKey: "!!!"}
	if _, err := sub.Keys(); err == nil {
		t.Error("garbage keys must be rejected")
	}
	sub = &KeyedSubscription{P256DH: base64.RawURLEncoding.EncodeToString(make([]byte, 65)), Auth: "AA", PrivateKey: "AA"}
	if _, err := sub.Keys(); err == nil {
		t.Error("invalid point must be rejected")
	}
}

func TestAppSubscriptionRejectsGarbage(t *testing.T) {
	sub := &KeyedSubscription{P256DH: "!!!", Auth: "AA", PrivateKey: "AA"}
	if _, err := sub.AppSubscription(); err == nil {
		t.Error("garbage keys must be rejected")
	}
}

func TestPollTimeoutIsReportedByClient(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(2 * time.Second)
	})
	sub, _ := mockSubscription(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := r.Poll(ctx, sub); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want deadline exceeded, got %v", err)
	}
}
