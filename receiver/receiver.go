// Package receiver implements the user agent side of the Web Push protocol:
// it creates a subscription at a push service, monitors the subscription for
// push messages, decrypts them and acknowledges their receipt.
package receiver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WJQSERVER-STUDIO/httpc"

	"github.com/fenthope/tsukasa-push/pushmsg"
	"github.com/fenthope/tsukasa-push/vapid"
)

// Errors reported by a Receiver.
var (
	// ErrSubscriptionExpired means the push service does not know the
	// subscription any more (RFC 8030 §7.3).
	ErrSubscriptionExpired = errors.New("receiver: subscription expired")

	// ErrSubscriptionGone means the subscription was removed.
	ErrSubscriptionGone = errors.New("receiver: subscription gone")

	// ErrNoMessage means no message is presently available.
	ErrNoMessage = errors.New("receiver: no message available")

	// ErrMalformedLink means the push service did not return the push
	// resource URI (RFC 8030 §4).
	ErrMalformedLink = errors.New("receiver: missing push resource link")
)

// Subscription is the user agent's view of a push message subscription.
type Subscription struct {
	// ServiceURL is the base URL of the push service.
	ServiceURL string `json:"service_url"`

	// SubscriptionURI is the URI of the subscription resource. The user
	// agent monitors it for push messages.
	SubscriptionURI string `json:"subscription_uri"`

	// PushURI is the URI of the push resource. It is handed to the
	// application server, which delivers messages to it.
	PushURI string `json:"push_uri"`

	// P256DH is the base64url encoded public key of the subscription.
	P256DH string `json:"p256dh"`

	// Auth is the base64url encoded authentication secret of the
	// subscription.
	Auth string `json:"auth"`

	// PrivateKey is the base64url encoded private key of the subscription.
	// The user agent needs it to decrypt the messages of the subscription,
	// so it must be kept together with the subscription.
	PrivateKey string `json:"private_key"`
}

// Keys returns the key material of the subscription.
func (s *Subscription) Keys() (*pushmsg.UAKeys, error) {
	privRaw, err := base64.RawURLEncoding.DecodeString(s.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("receiver: private key encoding: %w", err)
	}
	priv, err := pushmsg.NewPrivateKey(privRaw)
	if err != nil {
		return nil, err
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(s.P256DH)
	if err != nil {
		return nil, fmt.Errorf("receiver: p256dh encoding: %w", err)
	}
	pub, err := pushmsg.NewPublicKey(pubRaw)
	if err != nil {
		return nil, err
	}
	auth, err := base64.RawURLEncoding.DecodeString(s.Auth)
	if err != nil {
		return nil, fmt.Errorf("receiver: auth encoding: %w", err)
	}
	return &pushmsg.UAKeys{Private: priv, Public: pub, AuthSecret: auth}, nil
}

// AppSubscription returns the subscription in the shape an application
// server needs: the push resource endpoint and the key material to encrypt
// messages.
func (s *Subscription) AppSubscription() (*pushmsg.Subscription, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	return &pushmsg.Subscription{
		Endpoint:   s.PushURI,
		Public:     keys.Public,
		AuthSecret: keys.AuthSecret,
	}, nil
}

// Message is a push message received by the user agent.
type Message struct {
	// URI is the URI of the push message resource, used to acknowledge
	// the message (RFC 8030 §6.2).
	URI string

	// Payload is the decrypted payload of the message.
	Payload []byte

	// ReceivedAt is the time the message was received.
	ReceivedAt time.Time
}

// Receiver is a user agent talking to a push service.
type Receiver struct {
	client        *httpc.Client
	serviceURL    string
	restrictedKey string
}

// Option configures a Receiver.
type Option func(*Receiver)

// WithHTTPClient sets the HTTP client used for the requests to the push
// service.
func WithHTTPClient(c *httpc.Client) Option {
	return func(r *Receiver) {
		if c != nil {
			r.client = c
		}
	}
}

// WithRestrictedKey restricts the subscription to an application server
// (RFC 8292 §4.1). Only requests signed with the corresponding key are
// accepted by the push service.
func WithRestrictedKey(signer *vapid.Signer) Option {
	return func(r *Receiver) {
		if signer != nil {
			r.restrictedKey = signer.PublicKeyB64()
		}
	}
}

// New creates a Receiver for a push service.
func New(serviceURL string, opts ...Option) (*Receiver, error) {
	if serviceURL == "" {
		return nil, errors.New("receiver: missing push service URL")
	}
	if _, err := url.Parse(serviceURL); err != nil {
		return nil, fmt.Errorf("receiver: push service URL: %w", err)
	}
	r := &Receiver{
		client: httpc.New(
			httpc.WithTimeout(30*time.Second),
			httpc.WithRetryOptions(httpc.RetryOptions{}),
		),
		serviceURL: strings.TrimRight(serviceURL, "/"),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Subscribe creates a push message subscription at the push service
// (RFC 8030 §4).
func (r *Receiver) Subscribe(ctx context.Context) (*Subscription, error) {
	keys, err := pushmsg.GenerateUAKeys()
	if err != nil {
		return nil, err
	}
	rb := r.client.POST(r.serviceURL + "/subscribe").WithContext(ctx)
	var body []byte
	if r.restrictedKey != "" {
		options, err := json.Marshal(map[string]string{"vapid": r.restrictedKey})
		if err != nil {
			return nil, err
		}
		body = options
		rb.SetHeader("Content-Type", pushmsg.OptionsMediaType)
	}
	resp, err := rb.SetRawBody(body).Execute()
	if err != nil {
		return nil, fmt.Errorf("receiver: subscribe: %w", requestError(ctx, err))
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("receiver: subscribe failed with %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, errors.New("receiver: missing subscription location")
	}
	location = resolve(r.serviceURL, location)
	pushURI, err := pushLink(resp.Header.Get("Link"))
	if err != nil {
		return nil, err
	}
	pushURI = resolve(r.serviceURL, pushURI)

	return &Subscription{
		ServiceURL:      r.serviceURL,
		SubscriptionURI: location,
		PushURI:         pushURI,
		P256DH:          base64.RawURLEncoding.EncodeToString(keys.Public.Bytes()),
		Auth:            base64.RawURLEncoding.EncodeToString(keys.AuthSecret),
		PrivateKey:      base64.RawURLEncoding.EncodeToString(keys.Private.Bytes()),
	}, nil
}

// Poll waits for a push message and decrypts it (RFC 8030 §6).
//
// The call blocks until a message arrives, the context is cancelled or the
// subscription is gone. A push service that has no message available
// answers with 204, which is reported as ErrNoMessage.
func (r *Receiver) Poll(ctx context.Context, sub *Subscription) (*Message, error) {
	if sub == nil {
		return nil, errors.New("receiver: missing subscription")
	}
	rb := r.client.GET(sub.SubscriptionURI).WithContext(ctx)
	resp, err := rb.Execute()
	if err != nil {
		return nil, fmt.Errorf("receiver: poll: %w", requestError(ctx, err))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNoContent:
		return nil, ErrNoMessage
	case http.StatusNotFound:
		return nil, ErrSubscriptionExpired
	case http.StatusGone:
		return nil, ErrSubscriptionGone
	default:
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("receiver: poll failed with %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, pushmsg.MaxPayloadSize))
	if err != nil {
		return nil, fmt.Errorf("receiver: read message: %w", err)
	}
	keys, err := sub.Keys()
	if err != nil {
		return nil, err
	}
	plain, err := pushmsg.Decrypt(body, keys.AuthSecret, keys.Private)
	if err != nil {
		return nil, fmt.Errorf("receiver: decrypt: %w", err)
	}
	messageURI := resp.Header.Get("Location")
	if messageURI != "" {
		messageURI = resolve(r.serviceURL, messageURI)
	}
	return &Message{URI: messageURI, Payload: plain, ReceivedAt: time.Now()}, nil
}

// Ack acknowledges a received message (RFC 8030 §6.2).
func (r *Receiver) Ack(ctx context.Context, msg *Message) error {
	if msg == nil || msg.URI == "" {
		return errors.New("receiver: missing message URI")
	}
	resp, err := r.client.DELETE(msg.URI).WithContext(ctx).Execute()
	if err != nil {
		return fmt.Errorf("receiver: acknowledge: %w", requestError(ctx, err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusGone:
		return ErrSubscriptionGone
	default:
		return fmt.Errorf("receiver: acknowledge failed with %d", resp.StatusCode)
	}
}

// Unsubscribe removes the subscription at the push service (RFC 8030 §7.2).
func (r *Receiver) Unsubscribe(ctx context.Context, sub *Subscription) error {
	if sub == nil {
		return errors.New("receiver: missing subscription")
	}
	resp, err := r.client.DELETE(sub.SubscriptionURI).WithContext(ctx).Execute()
	if err != nil {
		return fmt.Errorf("receiver: unsubscribe: %w", requestError(ctx, err))
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
		return nil
	case http.StatusGone, http.StatusNotFound:
		return ErrSubscriptionGone
	default:
		return fmt.Errorf("receiver: unsubscribe failed with %d", resp.StatusCode)
	}
}

// requestError combines the error of the context with the error of the
// HTTP client. The client reports a cancelled request as a timeout without
// preserving the context error in its error chain, so the context error is
// joined here to keep errors.Is usable.
func requestError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, err)
	}
	return err
}

// pushLink extracts the URI of the push resource from a Link header field
// (RFC 8030 §4).
func pushLink(header string) (string, error) {
	for _, link := range splitLinks(header) {
		target, params, ok := strings.Cut(link, ";")
		if !ok {
			continue
		}
		target = strings.TrimSpace(target)
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		target = target[1 : len(target)-1]
		for _, param := range strings.Split(params, ";") {
			key, value, ok := strings.Cut(param, "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "rel") {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"`)
			if value == pushmsg.RelPush {
				return target, nil
			}
		}
	}
	return "", ErrMalformedLink
}

// splitLinks splits a Link header field into its link values. Commas inside
// a URI reference or a quoted parameter do not separate links (RFC 8288).
func splitLinks(header string) []string {
	var links []string
	depth := 0
	quoted := false
	start := 0
	for i, r := range header {
		switch r {
		case '"':
			if depth == 0 {
				quoted = !quoted
			}
		case '<':
			if !quoted {
				depth++
			}
		case '>':
			if !quoted && depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 && !quoted {
				links = append(links, header[start:i])
				start = i + 1
			}
		}
	}
	if start < len(header) {
		links = append(links, header[start:])
	}
	return links
}

// resolve turns a possibly relative URI into an absolute one.
func resolve(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
