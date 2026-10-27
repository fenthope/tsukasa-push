package pushmsg

import (
	"errors"
	"fmt"
	"strconv"
)

// Header field names defined by RFC 8030.
const (
	HeaderTTL     = "TTL"
	HeaderUrgency = "Urgency"
	HeaderTopic   = "Topic"

	// HeaderTTLExpired is the informational header a push service returns
	// with a 404 when messages expired (RFC 8030 §5.2).
	HeaderTTLExpired = "TTL-Expired"

	// OptionsMediaType is the media type of a VAPID restricted subscription
	// body (RFC 8292 §4.1).
	OptionsMediaType = "application/webpush-options+json"
)

// errors for header validation
var (
	// ErrMissingTTL indicates a request without a TTL header field, which
	// RFC 8030 §5 requires.
	ErrMissingTTL = errors.New("pushmsg: missing TTL header")

	// ErrInvalidTTL indicates a malformed or out-of-range TTL value.
	ErrInvalidTTL = errors.New("pushmsg: invalid TTL")

	// ErrInvalidUrgency indicates an unknown Urgency value (RFC 8030 §5.3).
	ErrInvalidUrgency = errors.New("pushmsg: invalid Urgency")

	// ErrInvalidTopic indicates a Topic that is not a non-empty token of
	// at most 32 characters (RFC 8030 §5.3).
	ErrInvalidTopic = errors.New("pushmsg: invalid Topic")
)

// MaxTTL is the longest accepted TTL: four weeks, the ceiling the Push API
// (W3C Push API §ttl) permits user agents to request.
const MaxTTL uint32 = 2419200

// MaxTopicLength is the Topic maximum length in characters (RFC 8030 §5.3).
const MaxTopicLength = 32

// ParseTTL validates a TTL header field value: a non-negative decimal
// integer no greater than MaxTTL. A zero TTL means "deliver only if the
// user agent is currently connected".
func ParseTTL(value string) (uint32, error) {
	if value == "" {
		return 0, ErrMissingTTL
	}
	if value[0] < '0' || value[0] > '9' {
		return 0, fmt.Errorf("%w: %q", ErrInvalidTTL, value)
	}
	ttl, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalidTTL, value)
	}
	if uint32(ttl) > MaxTTL {
		return 0, fmt.Errorf("%w: %d exceeds %d", ErrInvalidTTL, ttl, MaxTTL)
	}
	return uint32(ttl), nil
}

// Urgency is the value of the Urgency header field (RFC 8030 §5.3). The
// zero value UrgencyUnset means the header is absent; the default urgency
// of an absent header is UrgencyNormal per RFC.
type Urgency uint8

// Urgency values in ascending order of delivery priority.
const (
	UrgencyUnset Urgency = iota
	UrgencyVeryLow
	UrgencyLow
	UrgencyNormal
	UrgencyHigh
)

// DefaultUrgency applies when no Urgency header field is present.
const DefaultUrgency = UrgencyNormal

// ParseUrgency maps an Urgency header field value to its Urgency. Values
// are compared case-sensitively as exact tokens.
func ParseUrgency(value string) (Urgency, error) {
	switch value {
	case "very-low":
		return UrgencyVeryLow, nil
	case "low":
		return UrgencyLow, nil
	case "normal":
		return UrgencyNormal, nil
	case "high":
		return UrgencyHigh, nil
	default:
		return UrgencyUnset, fmt.Errorf("%w: %q", ErrInvalidUrgency, value)
	}
}

// String returns the wire representation, or "" for UrgencyUnset.
func (u Urgency) String() string {
	switch u {
	case UrgencyVeryLow:
		return "very-low"
	case UrgencyLow:
		return "low"
	case UrgencyNormal:
		return "normal"
	case UrgencyHigh:
		return "high"
	default:
		return ""
	}
}

// ValidTopic checks a Topic header field value: a non-empty RFC 7230 token
// of at most MaxTopicLength characters.
func ValidTopic(topic string) error {
	if topic == "" || len(topic) > MaxTopicLength {
		return fmt.Errorf("%w: %q", ErrInvalidTopic, topic)
	}
	for i := 0; i < len(topic); i++ {
		if !isTokenChar(topic[i]) {
			return fmt.Errorf("%w: %q", ErrInvalidTopic, topic)
		}
	}
	return nil
}

// isTokenChar implements the tchar production of RFC 7230 §3.2.6.
func isTokenChar(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}
