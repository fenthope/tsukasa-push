// Package service implements the push service side of the Web Push
// protocol (RFC 8030): subscription creation, message acceptance and
// delivery to a waiting user agent.
//
// The service is a component, not a program: it is mounted into a touka
// engine with Register and keeps its state in a Store, which the host may
// replace with a durable implementation.
package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fenthope/ikumi"
	"github.com/infinite-iroha/touka"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

// Service is a push service implementation.
type Service struct {
	store           Store
	baseURL         string
	prefix          string
	subscriptionTTL time.Duration
	now             func() time.Time
	rateLimit       touka.HandlerFunc
}

// Option configures a Service.
type Option func(*Service)

// WithStore sets the store keeping subscriptions and pending messages. The
// default is an in-memory store.
func WithStore(store Store) Option {
	return func(s *Service) {
		if store != nil {
			s.store = store
		}
	}
}

// WithBaseURL sets the public base URL of the push service, e.g.
// "https://push.example.com". It is used to build the absolute resource
// URIs and to derive the origin a VAPID token must be bound to. When it is
// not set, the base URL is derived from the incoming request.
func WithBaseURL(rawURL string) Option {
	return func(s *Service) {
		s.baseURL = strings.TrimRight(rawURL, "/")
	}
}

// WithPrefix sets a path prefix for all routes of the service.
func WithPrefix(prefix string) Option {
	return func(s *Service) {
		s.prefix = strings.TrimRight(prefix, "/")
	}
}

// WithSubscriptionTTL sets how long a subscription is kept. Zero means the
// subscriptions never expire. A push service may expire subscriptions at
// any time (RFC 8030 §7.3).
func WithSubscriptionTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl >= 0 {
			s.subscriptionTTL = ttl
		}
	}
}

// WithRateLimit protects the push resource with a token bucket rate
// limiter. Application servers are the untrusted part of a push service,
// RFC 8030 §8.4 describes the denial of service risk they pose.
//
// The limiter is not applied to the subscription resource: a user agent
// holds that request open while it waits for messages and must not consume
// tokens for it.
func WithRateLimit(opts ikumi.TokenRateLimiterOptions) Option {
	return func(s *Service) {
		s.rateLimit = ikumi.TokenRateLimit(opts)
	}
}

// New creates a Service.
func New(opts ...Option) *Service {
	s := &Service{
		store:           NewMemoryStore(),
		subscriptionTTL: 30 * 24 * time.Hour,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Store returns the store of the service.
func (s *Service) Store() Store { return s.store }

// Register mounts the routes of the push service into a touka router.
//
//	POST   {prefix}/subscribe          create a subscription
//	POST   {prefix}/push/:id           request delivery of a push message
//	GET    {prefix}/subscription/:id   monitor a subscription for messages
//	DELETE {prefix}/subscription/:id   remove a subscription
//	DELETE {prefix}/message/:id        acknowledge a delivered message
func (s *Service) Register(r touka.Router) {
	group := r.Group(s.prefix)
	if s.rateLimit != nil {
		group.POST("/push/:id", s.rateLimit, s.handlePush)
	} else {
		group.POST("/push/:id", s.handlePush)
	}
	group.POST("/subscribe", s.handleSubscribe)
	group.GET("/subscription/:id", s.handlePoll)
	group.DELETE("/subscription/:id", s.handleUnsubscribe)
	group.DELETE("/message/:id", s.handleAck)
}

// handleSubscribe creates a push message subscription (RFC 8030 §4).
func (s *Service) handleSubscribe(c *touka.Context) {
	key, err := s.parseRestriction(c)
	if err != nil {
		s.writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	now := s.now()
	sub, err := s.store.CreateSubscription(c.Context(), Subscription{
		ID:            newID(),
		CreatedAt:     now,
		ExpiresAt:     s.expiry(now),
		RestrictedKey: key,
	})
	if err != nil {
		s.writeError(c, http.StatusInternalServerError, "cannot store subscription")
		return
	}
	base := s.base(c.Request)
	header := c.Writer.Header()
	header.Set("Location", base+s.prefix+"/subscription/"+sub.ID)
	header.Set("Link", fmt.Sprintf("<%s%s/push/%s>; rel=%q", base, s.prefix, sub.ID, pushmsg.RelPush))
	c.Raw(http.StatusCreated, "text/plain; charset=utf-8", nil)
}

// parseRestriction reads the optional restricted subscription body
// (RFC 8292 §4.1). A body with another media type is ignored.
func (s *Service) parseRestriction(c *touka.Context) ([]byte, error) {
	if !strings.HasPrefix(c.Request.Header.Get("Content-Type"), pushmsg.OptionsMediaType) {
		return nil, nil
	}
	body, err := c.GetReqBodyFull()
	if err != nil {
		return nil, errors.New("cannot read request body")
	}
	if len(body) == 0 {
		return nil, nil
	}
	var options struct {
		VAPID string `json:"vapid"`
	}
	if err := json.Unmarshal(body, &options); err != nil {
		return nil, errors.New("invalid subscription options")
	}
	if options.VAPID == "" {
		return nil, nil
	}
	pub, err := vapid.DecodeKeyB64(options.VAPID)
	if err != nil {
		return nil, errors.New("invalid vapid key")
	}
	return vapid.PublicKeyBytes(pub), nil
}

// handlePush accepts a push message for delivery (RFC 8030 §5).
func (s *Service) handlePush(c *touka.Context) {
	id := c.Param("id")
	sub, err := s.store.GetSubscription(c.Context(), id)
	if err != nil {
		// An expired or unknown subscription is reported as 404
		// (RFC 8030 §7.3).
		s.writeError(c, http.StatusNotFound, "unknown subscription")
		return
	}

	body, err := readBody(c)
	if err != nil {
		s.writeError(c, http.StatusBadRequest, "cannot read request body")
		return
	}
	if len(body) > pushmsg.MaxPayloadSize {
		s.writeError(c, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}

	ttl, err := pushmsg.ParseTTL(c.Request.Header.Get(pushmsg.HeaderTTL))
	if err != nil {
		s.writeError(c, http.StatusBadRequest, err.Error())
		return
	}
	urgency := pushmsg.DefaultUrgency
	if raw := c.Request.Header.Get(pushmsg.HeaderUrgency); raw != "" {
		u, err := pushmsg.ParseUrgency(raw)
		if err != nil {
			s.writeError(c, http.StatusBadRequest, err.Error())
			return
		}
		urgency = u
	}
	topic := c.Request.Header.Get(pushmsg.HeaderTopic)
	if topic != "" {
		if err := pushmsg.ValidTopic(topic); err != nil {
			s.writeError(c, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.checkVAPID(c, sub); err != nil {
		return
	}

	msg := Message{
		ID:             newID(),
		SubscriptionID: sub.ID,
		Body:           body,
		TTL:            ttl,
		Urgency:        urgency,
		Topic:          topic,
		CreatedAt:      s.now(),
	}
	if err := s.store.Enqueue(c.Context(), msg); err != nil {
		if errors.Is(err, ErrSubscriptionNotFound) || errors.Is(err, ErrSubscriptionExpired) {
			s.writeError(c, http.StatusNotFound, "unknown subscription")
			return
		}
		s.writeError(c, http.StatusInternalServerError, "cannot store message")
		return
	}
	base := s.base(c.Request)
	header := c.Writer.Header()
	header.Set("Location", base+s.prefix+"/message/"+msg.ID)
	header.Set(pushmsg.HeaderTTL, strconv.FormatUint(uint64(ttl), 10))
	c.Raw(http.StatusCreated, "text/plain; charset=utf-8", nil)
}

// checkVAPID validates the VAPID credentials of a push request
// (RFC 8292 §4.2).
func (s *Service) checkVAPID(c *touka.Context, sub Subscription) error {
	auth := c.Request.Header.Get("Authorization")
	if auth == "" {
		if sub.RestrictedKey != nil {
			s.writeError(c, http.StatusUnauthorized, "vapid credentials required")
			return errors.New("vapid credentials required")
		}
		return nil
	}
	_, pub, err := vapid.Verify(auth, s.origin(c.Request), s.now())
	if err != nil {
		s.writeError(c, http.StatusForbidden, "invalid vapid credentials")
		return err
	}
	if sub.RestrictedKey != nil && !bytes.Equal(vapid.PublicKeyBytes(pub), sub.RestrictedKey) {
		s.writeError(c, http.StatusForbidden, "vapid key does not match the subscription")
		return errors.New("vapid key mismatch")
	}
	return nil
}

// handlePoll waits for a message of a subscription (RFC 8030 §6).
//
// The user agent may request a minimum urgency, which the service must not
// undercut, and may ask for an immediate answer with "Prefer: wait=0".
func (s *Service) handlePoll(c *touka.Context) {
	id := c.Param("id")
	if _, err := s.store.GetSubscription(c.Context(), id); err != nil {
		header := c.Writer.Header()
		header.Set(pushmsg.HeaderTTLExpired, "true")
		s.writeError(c, http.StatusNotFound, "unknown subscription")
		return
	}
	// Without an Urgency header field the user agent receives messages of
	// any urgency (RFC 8030 §5.3).
	minimum := pushmsg.UrgencyVeryLow
	if raw := c.Request.Header.Get(pushmsg.HeaderUrgency); raw != "" {
		u, err := pushmsg.ParseUrgency(raw)
		if err != nil {
			s.writeError(c, http.StatusBadRequest, err.Error())
			return
		}
		minimum = u
	}

	ctx := c.Context()
	immediate := false
	if prefer := c.Request.Header.Get("Prefer"); strings.Contains(prefer, "wait=0") {
		immediate = true
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}

	msg, err := s.store.Poll(ctx, id, minimum)
	if err != nil {
		switch {
		case immediate && errors.Is(err, context.Canceled):
			// No message is presently available (RFC 8030 §6).
			c.Status(http.StatusNoContent)
			return
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return // the user agent is gone
		case errors.Is(err, ErrSubscriptionExpired):
			c.Writer.Header().Set(pushmsg.HeaderTTLExpired, "true")
			s.writeError(c, http.StatusNotFound, "subscription expired")
			return
		default:
			s.writeError(c, http.StatusNotFound, "unknown subscription")
			return
		}
	}

	base := s.base(c.Request)
	header := c.Writer.Header()
	header.Set("Location", base+s.prefix+"/message/"+msg.ID)
	header.Set("Link", fmt.Sprintf("<%s%s/push/%s>; rel=%q", base, s.prefix, msg.SubscriptionID, pushmsg.RelPush))
	c.Raw(http.StatusOK, "application/octet-stream", msg.Body)
}

// handleUnsubscribe removes a subscription (RFC 8030 §7.2).
func (s *Service) handleUnsubscribe(c *touka.Context) {
	if err := s.store.DeleteSubscription(c.Context(), c.Param("id")); err != nil {
		s.writeError(c, http.StatusGone, "unknown subscription")
		return
	}
	c.Status(http.StatusNoContent)
}

// handleAck acknowledges a delivered message (RFC 8030 §6.2).
func (s *Service) handleAck(c *touka.Context) {
	if err := s.store.Ack(c.Context(), c.Param("id")); err != nil {
		s.writeError(c, http.StatusGone, "unknown message")
		return
	}
	c.Status(http.StatusNoContent)
}

// readBody reads the request body, limited to the maximum payload size.
func readBody(c *touka.Context) ([]byte, error) {
	body := c.GetReqBody()
	if body == nil {
		return nil, nil
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, pushmsg.MaxPayloadSize+1))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// writeError writes an error response with a short text body.
func (s *Service) writeError(c *touka.Context, code int, reason string) {
	c.Raw(code, "text/plain; charset=utf-8", []byte(reason))
}

// expiry returns the expiration time of a new subscription.
func (s *Service) expiry(now time.Time) time.Time {
	if s.subscriptionTTL <= 0 {
		return time.Time{}
	}
	return now.Add(s.subscriptionTTL)
}

// base returns the public base URL of the service.
func (s *Service) base(r *http.Request) string {
	if s.baseURL != "" {
		return s.baseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

// origin returns the origin a VAPID token must be bound to
// (RFC 8292 §2).
func (s *Service) origin(r *http.Request) string {
	u, err := url.Parse(s.base(r))
	if err != nil {
		return ""
	}
	return vapid.Origin(u)
}

// newID returns a random identifier for a resource.
func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand does not fail in practice; fall back to a time based
		// identifier rather than panicking in a request handler.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}
