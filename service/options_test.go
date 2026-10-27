package service

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// failingStore fails the creation of subscriptions.
type failingStore struct {
	*MemoryStore
	createErr error
}

func (f *failingStore) CreateSubscription(_ context.Context, sub Subscription) (Subscription, error) {
	return Subscription{}, f.createErr
}

// enqueueFailStore fails the delivery of messages.
type enqueueFailStore struct {
	*MemoryStore
	err error
}

func (f *enqueueFailStore) Enqueue(_ context.Context, msg Message) error {
	return f.err
}

// pollFailStore fails the polling of messages.
type pollFailStore struct {
	*MemoryStore
	err error
}

func (f *pollFailStore) Poll(_ context.Context, id string, minUrgency pushmsg.Urgency) (*Message, error) {
	return nil, f.err
}

func TestWithStoreUsesTheGivenStore(t *testing.T) {
	store := &failingStore{MemoryStore: NewMemoryStore(), createErr: errors.New("disk full")}
	svc, srv := newTestService(t, WithStore(store))
	if svc.Store() != store {
		t.Error("the service does not use the given store")
	}
	resp, err := http.Post(srv.URL+"/subscribe", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestWithStoreIgnoresNil(t *testing.T) {
	svc := New(WithStore(nil))
	if svc.Store() == nil {
		t.Fatal("the store must not be nil")
	}
}

func TestWithPrefixMountsTheRoutes(t *testing.T) {
	_, srv := newTestService(t, WithPrefix("/api/v1/"))
	resp, err := http.Post(srv.URL+"/api/v1/subscribe", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, "/api/v1/subscription/") {
		t.Errorf("unexpected location %q", location)
	}
	link := resp.Header.Get("Link")
	if !strings.Contains(link, "/api/v1/push/") {
		t.Errorf("unexpected link %q", link)
	}
}

func TestWithSubscriptionTTL(t *testing.T) {
	svc := New(WithSubscriptionTTL(0))
	if !svc.expiry(time.Now()).IsZero() {
		t.Error("a zero TTL must not expire the subscriptions")
	}
	svc = New(WithSubscriptionTTL(time.Hour))
	if got := svc.expiry(time.Now()); got.IsZero() {
		t.Error("the subscriptions must expire")
	}
	// A negative TTL is ignored.
	svc = New(WithSubscriptionTTL(-time.Second))
	if svc.subscriptionTTL != 30*24*time.Hour {
		t.Errorf("ttl = %v", svc.subscriptionTTL)
	}
}

func TestSubscribeRejectsInvalidOptions(t *testing.T) {
	_, srv := newTestService(t)
	for _, body := range []string{"{", `{"vapid":"not-a-key"}`} {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/subscribe", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", pushmsg.OptionsMediaType)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestSubscribeAcceptsEmptyOptionsBody(t *testing.T) {
	_, srv := newTestService(t)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/subscribe", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", pushmsg.OptionsMediaType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, want 201", resp.StatusCode)
	}
}

func TestSubscribeReportsStoreFailure(t *testing.T) {
	store := &failingStore{MemoryStore: NewMemoryStore(), createErr: errors.New("disk full")}
	_, srv := newTestService(t, WithStore(store))
	resp, err := http.Post(srv.URL+"/subscribe", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", resp.StatusCode)
	}
}

func TestPushReportsStoreFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"not found": {ErrSubscriptionNotFound, http.StatusNotFound},
		"expired":   {ErrSubscriptionExpired, http.StatusNotFound},
		"other":     {errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			store := &enqueueFailStore{MemoryStore: NewMemoryStore(), err: tc.err}
			_, srv := newTestService(t, WithStore(store))
			_, pushURI := subscribe(t, srv, "")
			req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("body"))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(pushmsg.HeaderTTL, "60")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestPollReportsStoreFailure(t *testing.T) {
	store := &pollFailStore{MemoryStore: NewMemoryStore(), err: ErrSubscriptionExpired}
	_, srv := newTestService(t, WithStore(store))
	sub, err := store.CreateSubscription(context.Background(), Subscription{ID: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(srv.URL + "/subscription/" + sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
	if resp.Header.Get(pushmsg.HeaderTTLExpired) != "true" {
		t.Error("the expired subscription must be reported")
	}
}

func TestPollRejectsInvalidUrgency(t *testing.T) {
	_, srv := newTestService(t)
	location, _ := subscribe(t, srv, "")
	req, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderUrgency, "urgent-ish")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestPushWithTruncatedBody(t *testing.T) {
	_, srv := newTestService(t)
	_, pushURI := subscribe(t, srv, "")
	status := rawRequest(t, "POST", pushURI, map[string]string{
		"Content-Type":   "application/octet-stream",
		"Content-Length": "100",
	}, "short")
	if status != http.StatusBadRequest {
		t.Errorf("status %d, want 400", status)
	}
}

func TestSubscribeWithTruncatedBody(t *testing.T) {
	_, srv := newTestService(t)
	status := rawRequest(t, "POST", srv.URL+"/subscribe", map[string]string{
		"Content-Type":   pushmsg.OptionsMediaType,
		"Content-Length": "100",
	}, "short")
	if status != http.StatusBadRequest {
		t.Errorf("status %d, want 400", status)
	}
}

// rawRequest sends a request with a truncated body and returns the status
// code of the response.
func rawRequest(t *testing.T, method, rawURL string, headers map[string]string, body string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var req strings.Builder
	fmt.Fprintf(&req, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, u.RequestURI(), u.Host)
	for k, v := range headers {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	req.WriteString(body)
	if _, err := conn.Write([]byte(req.String())); err != nil {
		t.Fatal(err)
	}
	// The server waits for the announced bytes, closing the write side ends
	// the request with an unexpected EOF.
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestPushWithoutBody(t *testing.T) {
	engine := touka.Default()
	svc := New()
	svc.Register(engine)
	sub, err := svc.Store().CreateSubscription(context.Background(), Subscription{ID: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{
		Method:     http.MethodPost,
		URL:        &url.URL{Path: "/push/" + sub.ID},
		Host:       "push.example.com",
		Header:     http.Header{},
		RemoteAddr: "127.0.0.1:1234",
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	// The body is empty, so only the missing TTL header is reported.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", rec.Code)
	}
}

func TestBaseURLHelpers(t *testing.T) {
	svc := New()
	req := httptest.NewRequest(http.MethodPost, "http://push.example.com/push/1", nil)
	if got := svc.base(req); got != "http://push.example.com" {
		t.Errorf("base = %q", got)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := svc.base(req); got != "https://push.example.com" {
		t.Errorf("base = %q", got)
	}
	secure := httptest.NewRequest(http.MethodPost, "https://push.example.com/push/1", nil)
	secure.TLS = &tls.ConnectionState{}
	if got := svc.base(secure); got != "https://push.example.com" {
		t.Errorf("base = %q", got)
	}
	svc = New(WithBaseURL("https://push.example.com/"))
	if got := svc.base(req); got != "https://push.example.com" {
		t.Errorf("base = %q", got)
	}
}

func TestOriginOfBrokenBaseURL(t *testing.T) {
	svc := New(WithBaseURL("://broken"))
	req := httptest.NewRequest(http.MethodPost, "http://push.example.com/push/1", nil)
	if got := svc.origin(req); got != "" {
		t.Errorf("origin = %q, want an empty origin", got)
	}
}

func TestNewIDFallsBackWhenRandomFails(t *testing.T) {
	original := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = original }()
	if id := newID(); id == "" {
		t.Error("the fallback identifier must not be empty")
	}
}

// failingReader always fails.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("no entropy")
}
