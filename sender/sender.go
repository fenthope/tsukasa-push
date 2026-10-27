// Package sender implements the application server side of the Web Push
// protocol (RFC 8030 §5): encrypting a payload for a subscription, signing
// a VAPID token (RFC 8292) and delivering the message to the push resource
// endpoint of a push service.
package sender

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WJQSERVER-STUDIO/httpc"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

// Sentinel errors for the protocol level failures an application server can
// act upon. HTTPError unwraps to the matching sentinel.
var (
	// ErrSubscriptionNotFound is returned when the push service does not
	// know the subscription (HTTP 404, RFC 8030 §5.2).
	ErrSubscriptionNotFound = errors.New("sender: push subscription not found")

	// ErrSubscriptionGone is returned when the subscription has expired or
	// been deleted (HTTP 410, RFC 8030 §5.2).
	ErrSubscriptionGone = errors.New("sender: push subscription gone")

	// ErrBadRequest is returned for a malformed request, e.g. a missing or
	// invalid TTL (HTTP 400).
	ErrBadRequest = errors.New("sender: push service rejected the request")

	// ErrVAPIDRejected is returned when the push service refuses the VAPID
	// credentials (HTTP 403, RFC 8292 §4.2).
	ErrVAPIDRejected = errors.New("sender: vapid credentials rejected")

	// ErrVAPIDRequired is returned when the push service requires VAPID
	// credentials but none were sent (HTTP 401, RFC 8292 §4.2).
	ErrVAPIDRequired = errors.New("sender: vapid credentials required")

	// ErrTooManyRequests is returned when the push service is rate
	// limiting the application server (HTTP 429).
	ErrTooManyRequests = errors.New("sender: push service rate limited")
)

// HTTPError describes a non 2xx response of the push service.
type HTTPError struct {
	StatusCode int
	Status     string
	Header     http.Header
	Body       string
	// RetryAfter holds the parsed Retry-After header of a 429 response.
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("sender: push service returned %s: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("sender: push service returned %s", e.Status)
}

// Unwrap maps the status code to the matching sentinel error.
func (e *HTTPError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusNotFound:
		return ErrSubscriptionNotFound
	case http.StatusGone:
		return ErrSubscriptionGone
	case http.StatusBadRequest:
		return ErrBadRequest
	case http.StatusUnauthorized:
		return ErrVAPIDRequired
	case http.StatusForbidden:
		return ErrVAPIDRejected
	case http.StatusTooManyRequests:
		return ErrTooManyRequests
	case http.StatusRequestEntityTooLarge:
		return pushmsg.ErrPayloadTooLarge
	default:
		return nil
	}
}

// Message is a push message to deliver.
type Message struct {
	// Payload is the plaintext to deliver, at most pushmsg.MaxPlaintextSize
	// octets. An empty payload is a valid, silent push.
	Payload []byte

	// TTL is the message lifetime in seconds (RFC 8030 §5). Zero means the
	// message is only delivered while the user agent is connected.
	TTL uint32

	// Urgency is the optional delivery priority (RFC 8030 §5.3). The
	// header is omitted when Urgency is pushmsg.UrgencyUnset.
	Urgency pushmsg.Urgency

	// Topic is the optional topic of the message (RFC 8030 §5.3). The
	// header is omitted for the empty string.
	Topic string
}

// Sender delivers push messages to push services. It is safe for concurrent
// use.
type Sender struct {
	client   *httpc.Client
	signer   *vapid.Signer
	subject  string
	tokenTTL time.Duration
	now      func() time.Time

	mu     sync.Mutex
	tokens map[string]vapidToken
}

type vapidToken struct {
	credential string
	expiry     time.Time
}

// Option configures a Sender.
type Option func(*Sender)

// WithHTTPClient sets the HTTP client used for delivery. The client also
// carries the retry policy of the host application.
func WithHTTPClient(c *httpc.Client) Option {
	return func(s *Sender) {
		if c != nil {
			s.client = c
		}
	}
}

// WithVAPID enables voluntary application server identification: every
// request carries an ES256 token identifying the application server
// (RFC 8292). subject is the contact URI of the operator, e.g.
// "mailto:ops@example.com".
func WithVAPID(signer *vapid.Signer, subject string) Option {
	return func(s *Sender) {
		s.signer = signer
		s.subject = subject
	}
}

// WithTokenTTL sets the lifetime of the generated VAPID tokens. It must be
// positive and at most 24 hours (RFC 8292 §2). Tokens are reused until half
// of their lifetime has elapsed, so a steady stream of messages needs only
// one signature per twelve hours by default.
func WithTokenTTL(ttl time.Duration) Option {
	return func(s *Sender) {
		if ttl > 0 && ttl <= vapid.MaxTokenLifetime {
			s.tokenTTL = ttl
		}
	}
}

// New creates a Sender.
//
// The default HTTP client does not retry: a push delivery is not silently
// repeated, the host decides how to handle a rate limit or a transport
// error. Pass a client with httpc.WithRetryOptions to enable retries.
func New(opts ...Option) *Sender {
	s := &Sender{
		client: httpc.New(
			httpc.WithTimeout(30*time.Second),
			httpc.WithRetryOptions(httpc.RetryOptions{}),
		),
		tokenTTL: 12 * time.Hour,
		now:      time.Now,
		tokens:   make(map[string]vapidToken),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Send encrypts and delivers a message to the push resource of a
// subscription.
//
// The returned error is an *HTTPError for any non 2xx response of the push
// service; use errors.Is to distinguish a gone subscription from a rate
// limit.
func (s *Sender) Send(ctx context.Context, sub *pushmsg.Subscription, msg Message) error {
	if sub == nil || sub.Endpoint == "" || sub.Public == nil {
		return errors.New("sender: incomplete subscription")
	}
	if len(sub.AuthSecret) != pushmsg.AuthSecretSize {
		return fmt.Errorf("sender: auth secret must be %d bytes, got %d", pushmsg.AuthSecretSize, len(sub.AuthSecret))
	}
	if msg.TTL > pushmsg.MaxTTL {
		return fmt.Errorf("%w: ttl %d exceeds %d", pushmsg.ErrInvalidTTL, msg.TTL, pushmsg.MaxTTL)
	}
	if msg.Topic != "" {
		if err := pushmsg.ValidTopic(msg.Topic); err != nil {
			return err
		}
	}
	if msg.Urgency != pushmsg.UrgencyUnset {
		if _, err := pushmsg.ParseUrgency(msg.Urgency.String()); err != nil {
			return err
		}
	}

	body, err := pushmsg.Encrypt(msg.Payload, sub.AuthSecret, sub.Public)
	if err != nil {
		return err
	}

	rb := s.client.POST(sub.Endpoint).WithContext(ctx)
	rb.SetHeader(pushmsg.HeaderTTL, strconv.FormatUint(uint64(msg.TTL), 10))
	rb.SetHeader("Content-Encoding", pushmsg.ContentCoding)
	if msg.Urgency != pushmsg.UrgencyUnset {
		rb.SetHeader(pushmsg.HeaderUrgency, msg.Urgency.String())
	}
	if msg.Topic != "" {
		rb.SetHeader(pushmsg.HeaderTopic, msg.Topic)
	}
	if s.signer != nil {
		cred, err := s.vapidCredential(sub.Endpoint)
		if err != nil {
			return err
		}
		rb.SetHeader("Authorization", cred)
	}

	resp, err := rb.SetRawBody(body).Execute()
	if err != nil {
		return fmt.Errorf("sender: deliver: %w", requestError(ctx, err))
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &HTTPError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     resp.Header,
		Body:       strings.TrimSpace(string(payload)),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
}

// vapidCredential returns the cached Authorization credential for the origin
// of an endpoint, signing a fresh token when needed.
func (s *Sender) vapidCredential(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("sender: endpoint url: %w", err)
	}
	origin := vapid.Origin(u)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if tok, ok := s.tokens[origin]; ok && now.Add(s.tokenTTL/2).Before(tok.expiry) {
		return tok.credential, nil
	}
	expiry := now.Add(s.tokenTTL)
	cred, err := s.signer.Authorization(origin, s.subject, expiry)
	if err != nil {
		return "", fmt.Errorf("sender: vapid token: %w", err)
	}
	s.tokens[origin] = vapidToken{credential: cred, expiry: expiry}
	return cred, nil
}

// requestError combines the error of the context with the error of the HTTP
// client. The client reports a cancelled request as a timeout without
// preserving the context error in its error chain, so the context error is
// joined here to keep errors.Is usable.
func requestError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, err)
	}
	return err
}

// parseRetryAfter interprets a Retry-After header field value, either
// delta-seconds or an HTTP date.
func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}
	if secs, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}
