package receiver

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// BenchmarkPoll measures the delivery path of the user agent: the HTTP
// request to the push service and the decryption of the message
// (RFC 8291).
func BenchmarkPoll(b *testing.B) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	body, err := pushmsg.Encrypt(make([]byte, 1024), keys.AuthSecret, keys.Public)
	if err != nil {
		b.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	r, err := New(srv.URL)
	if err != nil {
		b.Fatal(err)
	}
	sub := &Subscription{
		ServiceURL:      srv.URL,
		SubscriptionURI: srv.URL + "/subscription/abc",
		PushURI:         srv.URL + "/push/abc",
		P256DH:          base64.RawURLEncoding.EncodeToString(keys.Public.Bytes()),
		Auth:            base64.RawURLEncoding.EncodeToString(keys.AuthSecret),
		PrivateKey:      base64.RawURLEncoding.EncodeToString(keys.Private.Bytes()),
	}
	ctx := context.Background()
	b.SetBytes(1024)
	for b.Loop() {
		msg, err := r.Poll(ctx, sub)
		if err != nil {
			b.Fatal(err)
		}
		if len(msg.Payload) != 1024 {
			b.Fatalf("payload = %d bytes", len(msg.Payload))
		}
	}
}

// BenchmarkDecryptOnly measures the decryption of a message without the
// HTTP round trip.
func BenchmarkDecryptOnly(b *testing.B) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		b.Fatal(err)
	}
	body, err := pushmsg.Encrypt(make([]byte, 1024), keys.AuthSecret, keys.Public)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(1024)
	for b.Loop() {
		if _, err := pushmsg.Decrypt(body, keys.AuthSecret, keys.Private); err != nil {
			b.Fatal(err)
		}
	}
}
