package service

import (
	"context"
	"sync"
	"time"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// zeroTTLLifetime bounds how long a message with a zero TTL may stay in the
// queue. Such a message is only delivered while a user agent is waiting
// (RFC 8030 §5.2), the window only prevents unbounded growth when the user
// agent disappears between the enqueue and the delivery.
const zeroTTLLifetime = 30 * time.Second

// MemoryStore is an in-memory Store. It is the default store of a Service
// and is meant for single process deployments and tests; a host that needs
// durability provides its own Store implementation.
type MemoryStore struct {
	mu   sync.Mutex
	subs map[string]*memorySubscription
	now  func() time.Time
}

type memorySubscription struct {
	sub       Subscription
	queue     []*Message
	delivered map[string]time.Time
	notify    chan struct{}
	polling   int
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		subs: make(map[string]*memorySubscription),
		now:  time.Now,
	}
}

// CreateSubscription stores a new subscription.
func (m *MemoryStore) CreateSubscription(_ context.Context, sub Subscription) (Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = m.now()
	}
	ms := &memorySubscription{
		sub:       sub,
		delivered: make(map[string]time.Time),
		notify:    make(chan struct{}, 1),
	}
	m.subs[sub.ID] = ms
	return sub, nil
}

// GetSubscription returns a subscription.
func (m *MemoryStore) GetSubscription(_ context.Context, id string) (Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ms, ok := m.subs[id]
	if !ok {
		return Subscription{}, ErrSubscriptionNotFound
	}
	if ms.sub.Expired(m.now()) {
		delete(m.subs, id)
		return Subscription{}, ErrSubscriptionExpired
	}
	return ms.sub, nil
}

// DeleteSubscription removes a subscription and its messages.
func (m *MemoryStore) DeleteSubscription(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ms, ok := m.subs[id]
	if !ok {
		return ErrSubscriptionNotFound
	}
	delete(m.subs, id)
	m.signal(ms)
	return nil
}

// Enqueue stores a message for delivery.
//
// A message with a zero TTL is only kept while a user agent is waiting for
// messages, otherwise it expires immediately (RFC 8030 §5.2).
func (m *MemoryStore) Enqueue(_ context.Context, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ms, ok := m.subs[msg.SubscriptionID]
	if !ok {
		return ErrSubscriptionNotFound
	}
	if ms.sub.Expired(m.now()) {
		delete(m.subs, msg.SubscriptionID)
		return ErrSubscriptionExpired
	}
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = m.now()
	}
	if msg.TTL == 0 {
		if ms.polling == 0 {
			return nil // no user agent is waiting, the message expires now
		}
		msg.ExpiresAt = msg.CreatedAt.Add(zeroTTLLifetime)
	} else {
		msg.ExpiresAt = msg.CreatedAt.Add(time.Duration(msg.TTL) * time.Second)
	}
	stored := msg
	ms.queue = append(ms.queue, &stored)
	m.signal(ms)
	return nil
}

// Poll waits for a message of the subscription.
func (m *MemoryStore) Poll(ctx context.Context, subscriptionID string, minUrgency pushmsg.Urgency) (*Message, error) {
	for {
		m.mu.Lock()
		ms, ok := m.subs[subscriptionID]
		if !ok {
			m.mu.Unlock()
			return nil, ErrSubscriptionNotFound
		}
		if ms.sub.Expired(m.now()) {
			delete(m.subs, subscriptionID)
			m.mu.Unlock()
			return nil, ErrSubscriptionExpired
		}
		ms.polling++
		msg := ms.pop(m.now(), minUrgency)
		if msg != nil {
			ms.delivered[msg.ID] = m.now()
			ms.polling--
			m.mu.Unlock()
			return msg, nil
		}
		notify := ms.notify
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			m.mu.Lock()
			if cur, ok := m.subs[subscriptionID]; ok && cur == ms {
				cur.polling--
			}
			m.mu.Unlock()
			return nil, ctx.Err()
		case <-notify:
		}
	}
}

// Ack removes a delivered message.
func (m *MemoryStore) Ack(_ context.Context, messageID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ms := range m.subs {
		if _, ok := ms.delivered[messageID]; ok {
			delete(ms.delivered, messageID)
			return nil
		}
	}
	return ErrMessageNotFound
}

// pop returns the first message that satisfies the urgency filter and drops
// expired messages. The caller must hold the lock.
func (ms *memorySubscription) pop(now time.Time, minUrgency pushmsg.Urgency) *Message {
	kept := ms.queue[:0]
	var found *Message
	for _, msg := range ms.queue {
		if found == nil && !msg.ExpiresAt.IsZero() && !now.Before(msg.ExpiresAt) {
			continue // expired, drop it
		}
		if found == nil && urgencyAtLeast(msg.Urgency, minUrgency) {
			found = msg
			continue
		}
		kept = append(kept, msg)
	}
	ms.queue = kept
	return found
}

// urgencyAtLeast reports whether urgency satisfies the minimum.
func urgencyAtLeast(urgency, minimum pushmsg.Urgency) bool {
	if urgency == pushmsg.UrgencyUnset {
		urgency = pushmsg.DefaultUrgency
	}
	if minimum == pushmsg.UrgencyUnset {
		minimum = pushmsg.UrgencyVeryLow
	}
	return urgency >= minimum
}

// signal wakes up a waiting poller. The caller must hold the lock.
func (m *MemoryStore) signal(ms *memorySubscription) {
	select {
	case ms.notify <- struct{}{}:
	default:
	}
}
