package service

import (
	"context"
	"errors"
	"time"

	"github.com/fenthope/tsukasa-push/pushmsg"
)

// Errors reported by a Store.
var (
	// ErrSubscriptionNotFound means the subscription does not exist.
	ErrSubscriptionNotFound = errors.New("service: subscription not found")

	// ErrSubscriptionExpired means the subscription existed but is gone.
	ErrSubscriptionExpired = errors.New("service: subscription expired")

	// ErrMessageNotFound means the message does not exist or was already
	// acknowledged.
	ErrMessageNotFound = errors.New("service: message not found")
)

// Subscription is a push message subscription held by the service
// (RFC 8030 §4).
type Subscription struct {
	// ID identifies the subscription and is part of its resource URIs.
	ID string

	// CreatedAt is the creation time of the subscription.
	CreatedAt time.Time

	// ExpiresAt is the time the subscription expires. The zero value means
	// the subscription does not expire.
	ExpiresAt time.Time

	// RestrictedKey holds the uncompressed P-256 public key of the
	// application server the subscription is restricted to
	// (RFC 8292 §4.1). A nil value means an unrestricted subscription.
	RestrictedKey []byte
}

// Expired reports whether the subscription is expired at the given time.
func (s Subscription) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt)
}

// Message is a push message accepted by the service (RFC 8030 §5).
type Message struct {
	// ID identifies the message and is part of its resource URI.
	ID string

	// SubscriptionID is the subscription the message belongs to.
	SubscriptionID string

	// Body is the encrypted payload of the message.
	Body []byte

	// TTL is the requested lifetime of the message in seconds.
	TTL uint32

	// Urgency is the delivery priority of the message (RFC 8030 §5.3).
	Urgency pushmsg.Urgency

	// Topic is the topic of the message (RFC 8030 §5.4). It is never
	// forwarded to the user agent.
	Topic string

	// CreatedAt is the time the message was accepted.
	CreatedAt time.Time

	// ExpiresAt is the time the message expires. After that the service
	// must not attempt delivery any more (RFC 8030 §5.2).
	ExpiresAt time.Time
}

// Store keeps the subscriptions of a push service and the messages waiting
// for delivery. Implementations must be safe for concurrent use.
//
// Poll blocks until a message is available, the subscription is gone or the
// context is cancelled. minUrgency is the lowest urgency the caller is
// willing to receive; pushmsg.UrgencyVeryLow accepts every message.
type Store interface {
	// CreateSubscription stores a new subscription and returns it.
	CreateSubscription(ctx context.Context, sub Subscription) (Subscription, error)

	// GetSubscription returns a subscription, or ErrSubscriptionNotFound
	// resp. ErrSubscriptionExpired.
	GetSubscription(ctx context.Context, id string) (Subscription, error)

	// DeleteSubscription removes a subscription and its pending messages.
	DeleteSubscription(ctx context.Context, id string) error

	// Enqueue stores a message for delivery to its subscription.
	Enqueue(ctx context.Context, msg Message) error

	// Poll waits for a message of the subscription that satisfies
	// minUrgency.
	Poll(ctx context.Context, subscriptionID string, minUrgency pushmsg.Urgency) (*Message, error)

	// Ack removes a delivered message after the user agent acknowledged
	// it (RFC 8030 §6.2).
	Ack(ctx context.Context, messageID string) error
}
