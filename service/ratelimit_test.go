package service

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fenthope/ikumi"
	"golang.org/x/time/rate"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
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

// pushWithVAPID sends a message with the given VAPID signer and returns the
// status code.
func pushWithVAPID(t *testing.T, pushURI string, signer *vapid.Signer) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderTTL, "60")
	if signer != nil {
		cred, err := signer.Authorization(originOf(t, pushURI), "mailto:ops@example.com", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
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

// originOf returns the origin of an URL, the audience of a VAPID token.
func originOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return vapid.Origin(u)
}

func TestRateLimitIsKeyedByVAPIDIdentity(t *testing.T) {
	_, srv := newTestService(t, WithRateLimit(ikumi.TokenRateLimiterOptions{
		Limit: rate.Limit(1),
		Burst: 1,
	}))
	_, pushURI := subscribe(t, srv, "")

	first := newSigner(t)
	second := newSigner(t)

	if code := pushWithVAPID(t, pushURI, first); code != http.StatusCreated {
		t.Fatalf("first application server: %d, want 201", code)
	}
	if code := pushWithVAPID(t, pushURI, first); code != http.StatusTooManyRequests {
		t.Errorf("second request of the same application server: %d, want 429", code)
	}
	// A different application server has its own budget.
	if code := pushWithVAPID(t, pushURI, second); code != http.StatusCreated {
		t.Errorf("second application server: %d, want 201", code)
	}
}

func TestRateLimitFallsBackToIPForInvalidCredentials(t *testing.T) {
	_, srv := newTestService(t, WithRateLimit(ikumi.TokenRateLimiterOptions{
		Limit: rate.Limit(1),
		Burst: 1,
	}))
	_, pushURI := subscribe(t, srv, "")

	// Requests without credentials share the bucket of the client IP.
	if code := pushWithVAPID(t, pushURI, nil); code != http.StatusCreated {
		t.Fatalf("first request: %d, want 201", code)
	}
	if code := pushWithVAPID(t, pushURI, nil); code != http.StatusTooManyRequests {
		t.Errorf("second request: %d, want 429", code)
	}
}

func TestRateLimitIgnoresForgedVAPIDKeys(t *testing.T) {
	_, srv := newTestService(t, WithRateLimit(ikumi.TokenRateLimiterOptions{
		Limit: rate.Limit(1),
		Burst: 1,
	}))
	_, pushURI := subscribe(t, srv, "")

	// A forged credential must not open a new bucket for every attempt.
	for i := range 3 {
		req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(pushmsg.HeaderTTL, "60")
		req.Header.Set("Authorization", "vapid t=forged.token.value, k="+newSigner(t).PublicKeyB64())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if i == 0 && resp.StatusCode != http.StatusForbidden {
			t.Errorf("forged credential: %d, want 403", resp.StatusCode)
		}
		if i > 0 && resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("forged credential %d: %d, want 429", i, resp.StatusCode)
		}
	}
}

// newSigner creates a VAPID signer for the tests.
func newSigner(t *testing.T) *vapid.Signer {
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
