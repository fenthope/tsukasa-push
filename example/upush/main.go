// Command upush-demo demonstrates sending a push message through a
// UnifiedPush-aligned flow: a Web Push service, a receiver-style subscription,
// and an application server delivering via the upush package.
//
// UnifiedPush itself is Web Push on the wire between the application server
// and the push server; the end user application obtains the endpoint and key
// material from a UnifiedPush connector and delivers them to the application
// server out of band.
//
//	go run ./example/upush
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/receiver"
	"github.com/fenthope/tsukasa-push/sender"
	"github.com/fenthope/tsukasa-push/service"
	"github.com/fenthope/tsukasa-push/upush"
	"github.com/fenthope/tsukasa-push/vapid"
)

func main() {
	// A free port keeps the demo independent of the machine it runs on.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	baseURL := "http://" + listener.Addr().String()

	// The push service: a touka engine with the service mounted.
	engine := touka.Default()
	pushService := service.New(service.WithBaseURL(baseURL))
	pushService.Register(engine)

	server := &http.Server{Handler: engine}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("push service: %v", err)
		}
	}()
	defer server.Close()
	log.Printf("push service listening on %s", baseURL)

	// The user agent subscribes. In a real UnifiedPush deployment the
	// connector library obtains the endpoint and keys from a distributor;
	// here the receiver package plays the role of the end user application.
	ua, err := receiver.New(baseURL)
	if err != nil {
		log.Fatalf("receiver: %v", err)
	}
	sub, err := ua.Subscribe(context.Background())
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Printf("push resource: %s", sub.PushURI)

	// Convert the receiver subscription into an upush.Subscription, the
	// shape a UnifiedPush client would report to its application server.
	appSub, err := sub.AppSubscription()
	if err != nil {
		log.Fatalf("application subscription: %v", err)
	}
	upSub := &upush.Subscription{
		Endpoint:  appSub.Endpoint,
		P256DHB64: base64.RawURLEncoding.EncodeToString(appSub.Public.Bytes()),
		AuthB64:   base64.RawURLEncoding.EncodeToString(appSub.AuthSecret),
	}
	if err := upSub.Validate(); err != nil {
		log.Fatalf("validate subscription: %v", err)
	}

	// A VAPID key identifies the application server at the push service.
	vapidKey, err := vapid.GenerateKey()
	if err != nil {
		log.Fatalf("vapid key: %v", err)
	}
	signer, err := vapid.NewSigner(vapidKey)
	if err != nil {
		log.Fatalf("vapid signer: %v", err)
	}
	app := sender.New(sender.WithVAPID(signer, "mailto:ops@example.com"))

	// The user agent waits for a message in the background.
	type received struct {
		msg *receiver.Message
		err error
	}
	messages := make(chan received, 1)
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			msg, err := ua.Poll(ctx, sub)
			cancel()
			if err != nil {
				messages <- received{err: err}
				return
			}
			messages <- received{msg: msg}
		}
	}()

	// The application server sends a message through upush.Push.
	payload := []byte(`{"title":"upush-demo","body":"hello from Go"}`)
	if err := upush.Push(context.Background(), app, upSub, sender.Message{
		Payload: payload,
		TTL:     60,
		Urgency: pushmsg.UrgencyHigh,
		Topic:   "demo",
	}); err != nil {
		log.Fatalf("push: %v", err)
	}
	log.Printf("message sent (%d bytes of plaintext)", len(payload))

	// Wait for the delivery.
	select {
	case result := <-messages:
		if result.err != nil {
			log.Fatalf("poll: %v", result.err)
		}
		fmt.Printf("received: %s\n", result.msg.Payload)
		if err := ua.Ack(context.Background(), result.msg); err != nil {
			log.Fatalf("ack: %v", err)
		}
		log.Println("message acknowledged")
	case <-time.After(10 * time.Second):
		log.Fatal("timeout waiting for the message")
	}

	if err := ua.Unsubscribe(context.Background(), sub); err != nil {
		log.Fatalf("unsubscribe: %v", err)
	}
	log.Println("subscription removed")

	// Shut the service down on Ctrl-C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	server.Close()
}
