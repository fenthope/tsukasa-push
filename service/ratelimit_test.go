package service

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/fenthope/ikumi"
	"golang.org/x/time/rate"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

func TestRateLimitProtectsPushResource(t *testing.T) {
	_, srv := newTestService(t, WithRateLimit(ikumi.TokenRateLimiterOptions{
		Limit: rate.Limit(1),
		Burst: 1,
	}))
	_, pushURI := subscribe(t, srv, "")

	post := func() int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(pushmsg.HeaderTTL, "60")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if code := post(); code != http.StatusCreated {
		t.Fatalf("first push: %d, want 201", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Errorf("second push: %d, want 429", code)
	}
}

func TestRateLimitDoesNotBlockSubscriptionPolling(t *testing.T) {
	_, srv := newTestService(t, WithRateLimit(ikumi.TokenRateLimiterOptions{
		Limit: rate.Limit(1),
		Burst: 1,
	}))
	location, _ := subscribe(t, srv, "")

	// The subscription resource is not rate limited: a user agent may hold
	// the request open without consuming tokens.
	for range 3 {
		req, err := http.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Prefer", "wait=0")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("poll status %d, want 204", resp.StatusCode)
		}
	}
}

func TestRateLimitRetryAfterHeader(t *testing.T) {
	_, srv := newTestService(t, WithRateLimit(ikumi.TokenRateLimiterOptions{
		Limit: rate.Limit(1),
		Burst: 1,
	}))
	_, pushURI := subscribe(t, srv, "")

	for range 2 {
		req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(pushmsg.HeaderTTL, "60")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			if resp.Header.Get("Retry-After") == "" {
				t.Error("missing Retry-After header")
			}
			return
		}
	}
	t.Error("the second push was not rate limited")
}

func TestServiceWithoutRateLimitIsUnlimited(t *testing.T) {
	_, srv := newTestService(t)
	_, pushURI := subscribe(t, srv, "")
	for range 5 {
		req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(pushmsg.HeaderTTL, "60")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("push status %d, want 201", resp.StatusCode)
		}
	}
}
