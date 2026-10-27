package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

func newTestService(t *testing.T, opts ...Option) (*Service, *httptest.Server) {
	t.Helper()
	engine := touka.Default()
	svc := New(opts...)
	svc.Register(engine)
	srv := httptest.NewServer(engine)
	t.Cleanup(srv.Close)
	return svc, srv
}

func subscribe(t *testing.T, srv *httptest.Server, body string) (location, pushURI string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/subscribe", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", pushmsg.OptionsMediaType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("subscribe status %d: %s", resp.StatusCode, body)
	}
	location = resp.Header.Get("Location")
	link := resp.Header.Get("Link")
	pushURI = link[strings.Index(link, "<")+1 : strings.Index(link, ">")]
	return location, pushURI
}

func TestSubscribeCreatesSubscription(t *testing.T) {
	_, srv := newTestService(t)
	location, pushURI := subscribe(t, srv, "")
	if !strings.HasPrefix(location, srv.URL+"/subscription/") {
		t.Errorf("unexpected location %q", location)
	}
	id := strings.TrimPrefix(location, srv.URL+"/subscription/")
	if id == "" || strings.Contains(id, "/") {
		t.Errorf("unexpected subscription id %q", id)
	}
	if !strings.HasPrefix(pushURI, srv.URL+"/push/") {
		t.Errorf("unexpected push uri %q", pushURI)
	}
	if strings.TrimPrefix(pushURI, srv.URL+"/push/") != id {
		t.Errorf("push uri %q does not belong to subscription %q", pushURI, id)
	}
}

func TestPushAndPoll(t *testing.T) {
	svc, srv := newTestService(t)
	location, pushURI := subscribe(t, srv, "")

	body := []byte("encrypted payload")
	req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderTTL, "60")
	req.Header.Set("Content-Encoding", pushmsg.ContentCoding)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		out, _ := io.ReadAll(resp.Body)
		t.Fatalf("push status %d: %s", resp.StatusCode, out)
	}
	messageURI := resp.Header.Get("Location")
	if messageURI == "" {
		t.Fatal("missing message location")
	}

	// The user agent polls the subscription and receives the message.
	pollReq, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	pollResp, err := http.DefaultClient.Do(pollReq)
	if err != nil {
		t.Fatal(err)
	}
	defer pollResp.Body.Close()
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll status %d", pollResp.StatusCode)
	}
	got, _ := io.ReadAll(pollResp.Body)
	if string(got) != string(body) {
		t.Errorf("body = %q", got)
	}
	if loc := pollResp.Header.Get("Location"); loc != messageURI {
		t.Errorf("location = %q, want %q", loc, messageURI)
	}
	if link := pollResp.Header.Get("Link"); !strings.Contains(link, pushmsg.RelPush) {
		t.Errorf("link = %q", link)
	}

	// Acknowledging the message removes it.
	ackReq, err := http.NewRequest(http.MethodDelete, messageURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	ackResp, err := http.DefaultClient.Do(ackReq)
	if err != nil {
		t.Fatal(err)
	}
	defer ackResp.Body.Close()
	if ackResp.StatusCode != http.StatusNoContent {
		t.Errorf("ack status %d", ackResp.StatusCode)
	}

	// A second acknowledgement is gone.
	ackResp2, err := http.DefaultClient.Do(ackReq)
	if err != nil {
		t.Fatal(err)
	}
	defer ackResp2.Body.Close()
	if ackResp2.StatusCode != http.StatusGone {
		t.Errorf("second ack status %d, want 410", ackResp2.StatusCode)
	}

	// The subscription is gone after the unsubscribe.
	delReq, err := http.NewRequest(http.MethodDelete, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("unsubscribe status %d", delResp.StatusCode)
	}
	delResp2, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	defer delResp2.Body.Close()
	if delResp2.StatusCode != http.StatusGone {
		t.Errorf("second unsubscribe status %d, want 410", delResp2.StatusCode)
	}
	_ = svc
}

func TestPushValidation(t *testing.T) {
	_, srv := newTestService(t)
	_, pushURI := subscribe(t, srv, "")

	post := func(t *testing.T, ttl string, body string, headers map[string]string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if ttl != "" {
			req.Header.Set(pushmsg.HeaderTTL, ttl)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if code := post(t, "", "x", nil); code != http.StatusBadRequest {
		t.Errorf("missing TTL: %d, want 400", code)
	}
	if code := post(t, "abc", "x", nil); code != http.StatusBadRequest {
		t.Errorf("invalid TTL: %d, want 400", code)
	}
	if code := post(t, "60", strings.Repeat("x", pushmsg.MaxPayloadSize+1), nil); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized payload: %d, want 413", code)
	}
	if code := post(t, "60", "x", map[string]string{pushmsg.HeaderUrgency: "urgent"}); code != http.StatusBadRequest {
		t.Errorf("invalid urgency: %d, want 400", code)
	}
	if code := post(t, "60", "x", map[string]string{pushmsg.HeaderTopic: "bad topic"}); code != http.StatusBadRequest {
		t.Errorf("invalid topic: %d, want 400", code)
	}
	if code := post(t, "60", "x", nil); code != http.StatusCreated {
		t.Errorf("valid push: %d, want 201", code)
	}
}

func TestPushToUnknownSubscription(t *testing.T) {
	_, srv := newTestService(t)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/push/unknown", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderTTL, "60")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
}

func TestRestrictedSubscription(t *testing.T) {
	_, srv := newTestService(t)

	key, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	options, err := json.Marshal(map[string]string{"vapid": signer.PublicKeyB64()})
	if err != nil {
		t.Fatal(err)
	}
	_, pushURI := subscribe(t, srv, string(options))

	post := func(t *testing.T, cred string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(pushmsg.HeaderTTL, "60")
		if cred != "" {
			req.Header.Set("Authorization", cred)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if code := post(t, ""); code != http.StatusUnauthorized {
		t.Errorf("missing vapid: %d, want 401", code)
	}

	other, err := vapid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := vapid.NewSigner(other)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := otherSigner.Authorization("http://"+strings.TrimPrefix(srv.URL, "http://"), "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, wrong); code != http.StatusForbidden {
		t.Errorf("wrong vapid key: %d, want 403", code)
	}

	good, err := signer.Authorization("http://"+strings.TrimPrefix(srv.URL, "http://"), "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if code := post(t, good); code != http.StatusCreated {
		t.Errorf("valid vapid: %d, want 201", code)
	}
}

func TestPollFiltersByUrgency(t *testing.T) {
	_, srv := newTestService(t)
	location, pushURI := subscribe(t, srv, "")

	// A low urgency message is stored.
	req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("low"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderTTL, "60")
	req.Header.Set(pushmsg.HeaderUrgency, "low")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// The user agent only accepts high urgency messages, the low urgency
	// message must not be delivered (RFC 8030 §5.3).
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	pollReq, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	pollReq.Header.Set(pushmsg.HeaderUrgency, "high")
	if _, err := http.DefaultClient.Do(pollReq); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want deadline exceeded, got %v", err)
	}

	// Without the filter the message is delivered.
	pollReq2, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	pollResp2, err := http.DefaultClient.Do(pollReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer pollResp2.Body.Close()
	if pollResp2.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", pollResp2.StatusCode)
	}
	out, _ := io.ReadAll(pollResp2.Body)
	if string(out) != "low" {
		t.Errorf("body = %q", out)
	}
}

func TestPollImmediateReturnsNoContent(t *testing.T) {
	_, srv := newTestService(t)
	location, _ := subscribe(t, srv, "")
	req, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Prefer", "wait=0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status %d, want 204", resp.StatusCode)
	}
}

func TestPollUnknownSubscription(t *testing.T) {
	_, srv := newTestService(t)
	resp, err := http.Get(srv.URL + "/subscription/unknown")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", resp.StatusCode)
	}
	if resp.Header.Get(pushmsg.HeaderTTLExpired) == "" {
		t.Error("missing TTL-Expired header")
	}
}

func TestMemoryStoreExpiry(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now()
	store.now = func() time.Time { return now }

	sub, err := store.CreateSubscription(context.Background(), Subscription{ID: "a", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID != "a" {
		t.Errorf("subscription = %+v", sub)
	}
	if err := store.Enqueue(context.Background(), Message{ID: "m", SubscriptionID: "a", TTL: 60, Body: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	msg, err := store.Poll(context.Background(), "a", pushmsg.DefaultUrgency)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Body) != "x" {
		t.Errorf("body = %q", msg.Body)
	}
	if err := store.Ack(context.Background(), "m"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ack(context.Background(), "m"); !errors.Is(err, ErrMessageNotFound) {
		t.Errorf("want ErrMessageNotFound, got %v", err)
	}

	// The subscription expires.
	now = now.Add(2 * time.Minute)
	if _, err := store.GetSubscription(context.Background(), "a"); !errors.Is(err, ErrSubscriptionExpired) {
		t.Errorf("want ErrSubscriptionExpired, got %v", err)
	}
}

func TestMemoryStoreZeroTTL(t *testing.T) {
	store := NewMemoryStore()
	if _, err := store.CreateSubscription(context.Background(), Subscription{ID: "a"}); err != nil {
		t.Fatal(err)
	}
	// Without a waiting user agent a zero TTL message expires at once.
	if err := store.Enqueue(context.Background(), Message{ID: "m", SubscriptionID: "a", TTL: 0}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := store.Poll(ctx, "a", pushmsg.DefaultUrgency); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want deadline exceeded, got %v", err)
	}
}

func TestServiceBaseURL(t *testing.T) {
	svc := New(WithBaseURL("https://push.example.com/"))
	if got := svc.base(nil); got != "https://push.example.com" {
		t.Errorf("base = %q", got)
	}
	if got := svc.origin(nil); got != "https://push.example.com" {
		t.Errorf("origin = %q", got)
	}
}

func TestServiceTTLHeaderEcho(t *testing.T) {
	_, srv := newTestService(t)
	_, pushURI := subscribe(t, srv, "")
	req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderTTL, "120")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get(pushmsg.HeaderTTL); got != strconv.Itoa(120) {
		t.Errorf("TTL = %q", got)
	}
}
