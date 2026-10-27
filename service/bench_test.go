package service

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// benchmarkService starts a push service and returns its server.
func benchmarkService(b *testing.B) *httptest.Server {
	b.Helper()
	engine := touka.Default()
	svc := New()
	svc.Register(engine)
	srv := httptest.NewServer(engine)
	b.Cleanup(srv.Close)
	return srv
}

// benchmarkSubscription creates a subscription and returns the URI of the
// subscription and of the push resource.
func benchmarkSubscription(b *testing.B, srv *httptest.Server) (location, pushURI string) {
	b.Helper()
	resp, err := http.Post(srv.URL+"/subscribe", "text/plain", nil)
	if err != nil {
		b.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	location = resp.Header.Get("Location")
	link := resp.Header.Get("Link")
	start := strings.Index(link, "<")
	end := strings.Index(link, ">")
	if start < 0 || end < start {
		b.Fatalf("unexpected Link header %q", link)
	}
	return location, link[start+1 : end]
}

// benchmarkPush queues a message for the push resource.
func benchmarkPush(b *testing.B, pushURI string, body []byte) {
	b.Helper()
	req, err := http.NewRequest(http.MethodPost, pushURI, strings.NewReader(string(body)))
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set(pushmsg.HeaderTTL, "60")
	req.Header.Set("Content-Encoding", pushmsg.ContentCoding)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b.Fatalf("status %d", resp.StatusCode)
	}
}

// BenchmarkHandlePush measures the push request path of the service.
func BenchmarkHandlePush(b *testing.B) {
	srv := benchmarkService(b)
	_, pushURI := benchmarkSubscription(b, srv)
	body := make([]byte, 1024)
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkPush(b, pushURI, body)
	}
}

// BenchmarkHandlePoll measures the delivery of a message to a waiting user
// agent.
func BenchmarkHandlePoll(b *testing.B) {
	srv := benchmarkService(b)
	location, pushURI := benchmarkSubscription(b, srv)
	body := make([]byte, 1024)
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		benchmarkPush(b, pushURI, body)

		req, err := http.NewRequest(http.MethodGet, location, nil)
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Prefer", "wait=0")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
}
