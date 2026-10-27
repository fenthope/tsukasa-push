// Command demo runs a complete Web Push round trip: a push service built
// with the service package, a user agent with the receiver package and an
// application server with the sender package.
//
//	go run ./example
package main

import (
	"context"
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

	// The user agent subscribes and receives messages.
	ua, err := receiver.New(baseURL)
	if err != nil {
		log.Fatalf("receiver: %v", err)
	}
	sub, err := ua.Subscribe(context.Background())
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Printf("subscription: %s", sub.SubscriptionURI)
	log.Printf("push resource: %s", sub.PushURI)

	// The application server only needs the push resource and the keys.
	appSub, err := sub.AppSubscription()
	if err != nil {
		log.Fatalf("application subscription: %v", err)
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

	// The application server sends a message.
	payload := []byte(`{"title":"tsukasa-push","body":"hello from Go"}`)
	if err := app.Send(context.Background(), appSub, sender.Message{
		Payload: payload,
		TTL:     60,
		Urgency: pushmsg.UrgencyHigh,
		Topic:   "demo",
	}); err != nil {
		log.Fatalf("send: %v", err)
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
