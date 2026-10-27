package sender

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

// BenchmarkSend measures the complete send path: payload encryption
// (RFC 8291), the optional VAPID signature (RFC 8292) and the HTTP request
// to the push service.
func BenchmarkSend(b *testing.B) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	sub := &pushmsg.Subscription{
		Endpoint:   srv.URL + "/p/abc123",
		Public:     keys.Public,
		AuthSecret: keys.AuthSecret,
	}
	payload := make([]byte, 1024)
	s := New()
	ctx := context.Background()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if err := s.Send(ctx, sub, Message{Payload: payload, TTL: 60}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSendWithVAPID measures the send path including the signature of
// the VAPID token.
func BenchmarkSendWithVAPID(b *testing.B) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	key, err := vapid.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	signer, err := vapid.NewSigner(key)
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	sub := &pushmsg.Subscription{
		Endpoint:   srv.URL + "/p/abc123",
		Public:     keys.Public,
		AuthSecret: keys.AuthSecret,
	}
	payload := make([]byte, 1024)
	s := New(WithVAPID(signer, "mailto:ops@example.com"))
	ctx := context.Background()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if err := s.Send(ctx, sub, Message{Payload: payload, TTL: 60}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSendLargePayload measures the send path with a payload at the
// maximum size of RFC 8291 §4.
func BenchmarkSendLargePayload(b *testing.B) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	sub := &pushmsg.Subscription{
		Endpoint:   srv.URL + "/p/abc123",
		Public:     keys.Public,
		AuthSecret: keys.AuthSecret,
	}
	payload := make([]byte, pushmsg.MaxPlaintextSize)
	s := New()
	ctx := context.Background()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if err := s.Send(ctx, sub, Message{Payload: payload, TTL: 60}); err != nil {
			b.Fatal(err)
		}
	}
}
