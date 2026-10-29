package receiver

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/WJQSERVER-STUDIO/httpc"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

func TestWithHTTPClientUsesTheGivenClient(t *testing.T) {
	client := httpc.New(httpc.WithUserAgent("tsukasa-test"))
	withClient, err := New("https://push.example.com", WithHTTPClient(client), WithHTTPClient(nil))
	if err != nil {
		t.Fatal(err)
	}
	if withClient.client != client {
		t.Error("the custom client must be used")
	}
}

func TestSubscriptionKeysRejectBrokenFields(t *testing.T) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	valid := base64.RawURLEncoding.EncodeToString(keys.Public.Bytes())
	validAuth := base64.RawURLEncoding.EncodeToString(keys.AuthSecret)
	validPriv := base64.RawURLEncoding.EncodeToString(keys.Private.Bytes())

	// A broken public key encoding.
	sub := &KeyedSubscription{P256DH: "!!!", Auth: validAuth, PrivateKey: validPriv}
	if _, err := sub.Keys(); err == nil || !strings.Contains(err.Error(), "p256dh") {
		t.Errorf("want a p256dh error, got %v", err)
	}
	// A broken auth encoding.
	sub = &KeyedSubscription{P256DH: valid, Auth: "!!!", PrivateKey: validPriv}
	if _, err := sub.Keys(); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Errorf("want an auth error, got %v", err)
	}
}

func TestSubscribeReportsTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	r, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if _, err := r.Subscribe(context.Background()); err == nil {
		t.Error("the transport error must be reported")
	}
}

func TestPollReportsBrokenSubscriptions(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("body"))
	})
	sub, _ := mockSubscription(t, srv.URL)
	sub.P256DH = "!!!"
	if _, err := r.Poll(context.Background(), sub); err == nil {
		t.Error("the broken subscription must be reported")
	}
}

func TestPollReportsTruncatedBodies(t *testing.T) {
	r, srv := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the server does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"))
		conn.Close()
	})
	sub, _ := mockSubscription(t, srv.URL)
	if _, err := r.Poll(context.Background(), sub); err == nil {
		t.Error("the truncated body must be reported")
	}
}

func TestPollResolvesRelativeMessageURIs(t *testing.T) {
	sub, keys := mockSubscription(t, "https://push.example.net")
	body, err := pushmsg.Encrypt([]byte("payload"), keys.AuthSecret, keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := mockService(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Location", "/message/abc")
		w.Write(body)
	})
	sub.SubscriptionURI = r.serviceURL + "/subscription/abc"
	msg, err := r.Poll(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	if msg.URI != r.serviceURL+"/message/abc" {
		t.Errorf("URI = %q", msg.URI)
	}
}

func TestAckReportsTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	r, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if err := r.Ack(context.Background(), &Message{URI: srv.URL + "/message/x"}); err == nil {
		t.Error("the transport error must be reported")
	}
}

func TestUnsubscribeReportsTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}))
	r, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := mockSubscription(t, srv.URL)
	srv.Close()
	if err := r.Unsubscribe(context.Background(), sub); err == nil {
		t.Error("the transport error must be reported")
	}
}

func TestPushLinkIgnoresForeignLinks(t *testing.T) {
	for name, header := range map[string]string{
		"no parameters":   "http://push.example.com/push/abc",
		"no angle":        `http://push.example.com/push/abc; rel="urn:ietf:params:push"`,
		"no equals":       `<http://push.example.com/push/abc>; rel`,
		"other parameter": `<http://push.example.com/push/abc>; title="a"`,
		"other relation":  `<http://push.example.com/push/abc>; rel="alternate"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pushLink(header); !errors.Is(err, ErrMalformedLink) {
				t.Errorf("want ErrMalformedLink, got %v", err)
			}
		})
	}
}

func TestPushLinkFindsThePushRelation(t *testing.T) {
	uri, err := pushLink(`<http://a/1>; rel="alternate", <http://b/2>; rel="urn:ietf:params:push"`)
	if err != nil {
		t.Fatal(err)
	}
	if uri != "http://b/2" {
		t.Errorf("uri = %q", uri)
	}
}

func TestResolveKeepsBrokenReferences(t *testing.T) {
	if got := resolve("://broken", "/message/abc"); got != "/message/abc" {
		t.Errorf("resolved = %q", got)
	}
	if got := resolve("https://push.example.com", "://broken"); got != "://broken" {
		t.Errorf("resolved = %q", got)
	}
	if got := resolve("https://push.example.com", "/message/abc"); got != "https://push.example.com/message/abc" {
		t.Errorf("resolved = %q", got)
	}
}
