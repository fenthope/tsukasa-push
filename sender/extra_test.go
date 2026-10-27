package sender

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/WJQSERVER-STUDIO/httpc"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

func TestHTTPErrorMessage(t *testing.T) {
	withBody := &HTTPError{StatusCode: 500, Status: "500 Internal Server Error", Body: "boom"}
	if !strings.Contains(withBody.Error(), "boom") {
		t.Errorf("error = %q", withBody.Error())
	}
	withoutBody := &HTTPError{StatusCode: 500, Status: "500 Internal Server Error"}
	if strings.Contains(withoutBody.Error(), "Error:") {
		t.Errorf("error = %q", withoutBody.Error())
	}
	if withoutBody.Unwrap() != nil {
		t.Error("an unmapped status must not unwrap to a sentinel")
	}
}

func TestWithHTTPClient(t *testing.T) {
	sub, _ := testSubscription(t)
	var used bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		used = true
		readAll(t, r)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc"

	client := httpc.New(httpc.WithUserAgent("tsukasa-test"))
	s := New(WithHTTPClient(client), WithHTTPClient(nil))
	if s.client != client {
		t.Error("the custom client must be used")
	}
	if err := s.Send(context.Background(), sub, Message{TTL: 1}); err != nil {
		t.Fatal(err)
	}
	if !used {
		t.Error("the request did not reach the server")
	}
}

func TestSendRejectsBrokenSubscription(t *testing.T) {
	sub, _ := testSubscription(t)
	s := New()

	noEndpoint := *sub
	noEndpoint.Endpoint = ""
	if err := s.Send(context.Background(), &noEndpoint, Message{TTL: 1}); err == nil {
		t.Error("missing endpoint must be rejected")
	}

	noPublic := *sub
	noPublic.Public = nil
	if err := s.Send(context.Background(), &noPublic, Message{TTL: 1}); err == nil {
		t.Error("missing public key must be rejected")
	}

	shortAuth := *sub
	shortAuth.AuthSecret = []byte("too short")
	if err := s.Send(context.Background(), &shortAuth, Message{TTL: 1}); err == nil {
		t.Error("short auth secret must be rejected")
	}
}

func TestSendRejectsUnknownUrgency(t *testing.T) {
	sub, _ := testSubscription(t)
	err := New().Send(context.Background(), sub, Message{TTL: 1, Urgency: pushmsg.Urgency(99)})
	if !errors.Is(err, pushmsg.ErrInvalidUrgency) {
		t.Errorf("want ErrInvalidUrgency, got %v", err)
	}
}

func TestSendWithBrokenEndpointURL(t *testing.T) {
	sub, _ := testSubscription(t)
	sub.Endpoint = "://broken"
	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	err = New(WithVAPID(signer, "mailto:ops@example.com")).Send(context.Background(), sub, Message{TTL: 1})
	if err == nil || !strings.Contains(err.Error(), "endpoint url") {
		t.Errorf("want an endpoint url error, got %v", err)
	}
}

func TestSendReportsCancelledContext(t *testing.T) {
	sub, _ := testSubscription(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New().Send(ctx, sub, Message{TTL: 1})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("120"); got != 120*time.Second {
		t.Errorf("seconds: %v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("empty: %v", got)
	}
	if got := parseRetryAfter("not a date"); got != 0 {
		t.Errorf("garbage: %v", got)
	}
	if got := parseRetryAfter("Wed, 21 Oct 2015 07:28:00 GMT"); got != 0 {
		t.Errorf("past date: %v", got)
	}
	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	got := parseRetryAfter(future)
	if got <= 0 || got > 90*time.Second {
		t.Errorf("future date: %v", got)
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

func TestSendUnmappedStatus(t *testing.T) {
	sub, _ := testSubscription(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readAll(t, r)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc"

	err := New().Send(context.Background(), sub, Message{TTL: 1})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %v", err)
	}
	if httpErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d", httpErr.StatusCode)
	}
	for _, sentinel := range []error{ErrSubscriptionNotFound, ErrSubscriptionGone, ErrBadRequest, ErrVAPIDRequired, ErrVAPIDRejected, ErrTooManyRequests} {
		if errors.Is(err, sentinel) {
			t.Errorf("status 500 must not unwrap to %v", sentinel)
		}
	}
}

func TestSendConcurrent(t *testing.T) {
	sub, _ := testSubscription(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readAll(t, r)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sub.Endpoint = srv.URL + "/p/abc"

	s := New()
	done := make(chan error, 8)
	for range 8 {
		go func() {
			done <- s.Send(context.Background(), sub, Message{Payload: []byte("x"), TTL: 1})
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
