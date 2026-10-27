package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

func TestMemoryStoreEnqueueRejectsUnknownSubscription(t *testing.T) {
	store := NewMemoryStore()
	err := store.Enqueue(context.Background(), Message{ID: "m1", SubscriptionID: "missing"})
	if !errors.Is(err, ErrSubscriptionNotFound) {
		t.Errorf("err = %v, want ErrSubscriptionNotFound", err)
	}
}

func TestMemoryStoreEnqueueRejectsExpiredSubscription(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.CreateSubscription(context.Background(), Subscription{
		ID:        "sub-1",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Enqueue(context.Background(), Message{ID: "m1", SubscriptionID: "sub-1"})
	if !errors.Is(err, ErrSubscriptionExpired) {
		t.Errorf("err = %v, want ErrSubscriptionExpired", err)
	}
}

func TestMemoryStoreZeroTTLIsDeliveredToAWaitingUserAgent(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.CreateSubscription(context.Background(), Subscription{ID: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		msg *Message
		err error
	}
	results := make(chan result, 1)
	go func() {
		msg, err := store.Poll(context.Background(), "sub-1", pushmsg.UrgencyVeryLow)
		results <- result{msg, err}
	}()

	// The user agent must be waiting before the message is queued, otherwise
	// a message with a zero TTL expires immediately.
	deadline := time.Now().Add(2 * time.Second)
	for {
		store.mu.Lock()
		polling := store.subs["sub-1"].polling
		store.mu.Unlock()
		if polling > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the user agent did not start polling")
		}
		time.Sleep(time.Millisecond)
	}

	if err := store.Enqueue(context.Background(), Message{ID: "m1", SubscriptionID: "sub-1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-results:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.msg == nil || got.msg.ID != "m1" {
			t.Fatalf("message = %v", got.msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the message was not delivered")
	}
}

func TestMemoryStoreZeroTTLIsDroppedWithoutAWaitingUserAgent(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.CreateSubscription(context.Background(), Subscription{ID: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(context.Background(), Message{ID: "m1", SubscriptionID: "sub-1"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := store.Poll(ctx, "sub-1", pushmsg.UrgencyVeryLow); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want a timeout", err)
	}
}

func TestMemoryStorePollRejectsUnknownSubscription(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.Poll(context.Background(), "missing", pushmsg.UrgencyVeryLow)
	if !errors.Is(err, ErrSubscriptionNotFound) {
		t.Errorf("err = %v, want ErrSubscriptionNotFound", err)
	}
}

func TestMemoryStorePollRejectsExpiredSubscription(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.CreateSubscription(context.Background(), Subscription{
		ID:        "sub-1",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Poll(context.Background(), "sub-1", pushmsg.UrgencyVeryLow)
	if !errors.Is(err, ErrSubscriptionExpired) {
		t.Errorf("err = %v, want ErrSubscriptionExpired", err)
	}
}

func TestMemoryStorePollDropsExpiredMessages(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.CreateSubscription(context.Background(), Subscription{ID: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	// The message expired before it was queued.
	err = store.Enqueue(context.Background(), Message{
		ID:             "m1",
		SubscriptionID: "sub-1",
		TTL:            1,
		CreatedAt:      time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := store.Poll(ctx, "sub-1", pushmsg.UrgencyVeryLow); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want a timeout", err)
	}
	// The expired message was dropped, not kept in the queue.
	store.mu.Lock()
	queued := len(store.subs["sub-1"].queue)
	store.mu.Unlock()
	if queued != 0 {
		t.Errorf("%d messages are still queued", queued)
	}
}

func TestMemoryStorePollWithoutMinimumUrgency(t *testing.T) {
	store := NewMemoryStore()
	_, err := store.CreateSubscription(context.Background(), Subscription{ID: "sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Enqueue(context.Background(), Message{
		ID:             "m1",
		SubscriptionID: "sub-1",
		TTL:            60,
		Urgency:        pushmsg.UrgencyVeryLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	// An unset minimum means very low (RFC 8030 §5.3).
	msg, err := store.Poll(context.Background(), "sub-1", pushmsg.UrgencyUnset)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil || msg.ID != "m1" {
		t.Fatalf("message = %v", msg)
	}
}
