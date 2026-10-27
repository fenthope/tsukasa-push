package sender

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

func testSubscription(t *testing.T) (*pushmsg.Subscription, *pushmsg.UAKeys) {
	t.Helper()
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	return &pushmsg.Subscription{
		Endpoint:   "https://push.example.net/p/abc123",
		Public:     keys.Public,
		AuthSecret: keys.AuthSecret,
	}, keys
}

func TestSendDeliversEncryptedMessage(t *testing.T) {
	sub, keys := testSubscription(t)

	var gotHeader http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotBody = readAll(t, r)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc123"

	s := New()
	if err := s.Send(context.Background(), sub, Message{Payload: []byte("hello push"), TTL: 60}); err != nil {
		t.Fatal(err)
	}

	if got := gotHeader.Get(pushmsg.HeaderTTL); got != "60" {
		t.Errorf("TTL = %q", got)
	}
	if got := gotHeader.Get("Content-Encoding"); got != pushmsg.ContentCoding {
		t.Errorf("Content-Encoding = %q", got)
	}
	if got := gotHeader.Get("Authorization"); got != "" {
		t.Errorf("unexpected Authorization %q", got)
	}
	plain, err := pushmsg.Decrypt(gotBody, keys.AuthSecret, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "hello push" {
		t.Errorf("payload = %q", plain)
	}
}

func TestSendWithVAPID(t *testing.T) {
	sub, keys := testSubscription(t)

	var gotHeader http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotBody = readAll(t, r)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc123"

	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	s := New(WithVAPID(signer, "mailto:ops@example.com"))
	if err := s.Send(context.Background(), sub, Message{Payload: []byte("x"), TTL: 10}); err != nil {
		t.Fatal(err)
	}

	cred := gotHeader.Get("Authorization")
	if !strings.HasPrefix(cred, "vapid t=") || !strings.Contains(cred, ", k=") {
		t.Fatalf("Authorization = %q", cred)
	}
	claims, pub, err := vapid.Verify(cred, "http://"+strings.TrimPrefix(srv.URL, "http://"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "mailto:ops@example.com" {
		t.Errorf("sub = %q", claims.Subject)
	}
	if vapid.EncodeKeyB64(pub) != signer.PublicKeyB64() {
		t.Error("token signed by unexpected key")
	}
	if _, err := pushmsg.Decrypt(gotBody, keys.AuthSecret, keys.Private); err != nil {
		t.Fatal(err)
	}
}

func TestSendUrgencyAndTopic(t *testing.T) {
	sub, _ := testSubscription(t)
	var gotHeader http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		readAll(t, r)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc123"

	s := New()
	if err := s.Send(context.Background(), sub, Message{TTL: 5, Urgency: pushmsg.UrgencyHigh, Topic: "inbox"}); err != nil {
		t.Fatal(err)
	}
	if got := gotHeader.Get(pushmsg.HeaderUrgency); got != "high" {
		t.Errorf("Urgency = %q", got)
	}
	if got := gotHeader.Get(pushmsg.HeaderTopic); got != "inbox" {
		t.Errorf("Topic = %q", got)
	}

	// Unset urgency and empty topic must not emit the headers.
	if err := s.Send(context.Background(), sub, Message{TTL: 5}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotHeader[http.CanonicalHeaderKey(pushmsg.HeaderUrgency)]; ok {
		t.Error("Urgency header must be omitted")
	}
	if _, ok := gotHeader[http.CanonicalHeaderKey(pushmsg.HeaderTopic)]; ok {
		t.Error("Topic header must be omitted")
	}
}

func TestSendErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusNotFound, ErrSubscriptionNotFound},
		{http.StatusGone, ErrSubscriptionGone},
		{http.StatusBadRequest, ErrBadRequest},
		{http.StatusForbidden, ErrVAPIDRejected},
		{http.StatusTooManyRequests, ErrTooManyRequests},
		{http.StatusRequestEntityTooLarge, pushmsg.ErrPayloadTooLarge},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			readAll(t, r)
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(tc.status)
			w.Write([]byte("error-code=Test"))
		}))
		sub, _ := testSubscription(t)
		sub.Endpoint = srv.URL + "/p/abc"

		err := New().Send(context.Background(), sub, Message{TTL: 1})
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d: err = %v, want %v", tc.status, err, tc.want)
		}
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) {
			t.Errorf("status %d: want *HTTPError", tc.status)
			continue
		}
		if httpErr.StatusCode != tc.status {
			t.Errorf("status %d: got %d", tc.status, httpErr.StatusCode)
		}
		if httpErr.Body != "error-code=Test" {
			t.Errorf("body = %q", httpErr.Body)
		}
		if tc.status == http.StatusTooManyRequests && httpErr.RetryAfter != 120*time.Second {
			t.Errorf("RetryAfter = %v", httpErr.RetryAfter)
		}
		srv.Close()
	}
}

func TestSendRejectsInvalidInput(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	sub, _ := testSubscription(t)
	sub.Endpoint = srv.URL + "/p/abc"
	s := New()

	if err := s.Send(context.Background(), sub, Message{Payload: make([]byte, pushmsg.MaxPlaintextSize+1), TTL: 1}); !errors.Is(err, pushmsg.ErrPayloadTooLarge) {
		t.Errorf("want ErrPayloadTooLarge, got %v", err)
	}
	if err := s.Send(context.Background(), sub, Message{TTL: 1, Topic: "bad topic"}); !errors.Is(err, pushmsg.ErrInvalidTopic) {
		t.Errorf("want ErrInvalidTopic, got %v", err)
	}
	if err := s.Send(context.Background(), sub, Message{TTL: pushmsg.MaxTTL + 1}); !errors.Is(err, pushmsg.ErrInvalidTTL) {
		t.Errorf("want ErrInvalidTTL, got %v", err)
	}
	if err := s.Send(context.Background(), nil, Message{TTL: 1}); err == nil {
		t.Error("nil subscription must be rejected")
	}
	if calls != 0 {
		t.Errorf("service was contacted %d times", calls)
	}
}

func TestVAPIDTokenIsReused(t *testing.T) {
	sub, _ := testSubscription(t)
	var creds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		creds = append(creds, r.Header.Get("Authorization"))
		readAll(t, r)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc"

	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	s := New(WithVAPID(signer, "mailto:ops@example.com"), WithTokenTTL(time.Hour))

	for range 3 {
		if err := s.Send(context.Background(), sub, Message{TTL: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if creds[0] != creds[1] || creds[1] != creds[2] {
		t.Error("token must be reused while it is fresh")
	}

	// Past half the token lifetime a fresh token is signed.
	s.now = func() time.Time { return time.Now().Add(40 * time.Minute) }
	if err := s.Send(context.Background(), sub, Message{TTL: 1}); err != nil {
		t.Fatal(err)
	}
	if creds[3] == creds[2] {
		t.Error("token must be renewed after half its lifetime")
	}
}

func readAll(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

func TestSubscriptionJSONInterop(t *testing.T) {
	sub, _ := testSubscription(t)
	sub.Endpoint = "https://push.example.net/p/abc123"
	data, err := sub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"p256dh":"`+base64.RawURLEncoding.EncodeToString(sub.Public.Bytes())+`"`) {
		t.Errorf("unexpected json: %s", data)
	}
	back, err := pushmsg.ParseSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Endpoint != sub.Endpoint || !back.Public.Equal(sub.Public) || string(back.AuthSecret) != string(sub.AuthSecret) {
		t.Error("subscription round trip mismatch")
	}
}
