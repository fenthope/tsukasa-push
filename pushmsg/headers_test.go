package pushmsg

import (
	"errors"
	"strings"
	"testing"
)

func TestParseTTL(t *testing.T) {
	for _, ok := range []struct {
		in   string
		want uint32
	}{{"0", 0}, {"10", 10}, {"2419200", MaxTTL}, {"007", 7}} {
		got, err := ParseTTL(ok.in)
		if err != nil {
			t.Errorf("ParseTTL(%q): %v", ok.in, err)
			continue
		}
		if got != ok.want {
			t.Errorf("ParseTTL(%q) = %d, want %d", ok.in, got, ok.want)
		}
	}

	for _, bad := range []string{"", "-1", "abc", "1e3", " 10", "10 ", "+5", "2419201", "99999999999999999999", "0x10"} {
		_, err := ParseTTL(bad)
		if bad == "" {
			if !errors.Is(err, ErrMissingTTL) {
				t.Errorf("ParseTTL(\"\") err = %v, want ErrMissingTTL", err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalidTTL) {
			t.Errorf("ParseTTL(%q) err = %v, want ErrInvalidTTL", bad, err)
		}
	}
}

func TestUrgency(t *testing.T) {
	for in, want := range map[string]Urgency{
		"very-low": UrgencyVeryLow,
		"low":      UrgencyLow,
		"normal":   UrgencyNormal,
		"high":     UrgencyHigh,
	} {
		got, err := ParseUrgency(in)
		if err != nil {
			t.Errorf("ParseUrgency(%q): %v", in, err)
			continue
		}
		if got != want || got.String() != in {
			t.Errorf("ParseUrgency(%q) = %v, round trip %q", in, got, got.String())
		}
	}

	for _, bad := range []string{"", "NORMAL", "Normal", "urgent", "very low", "very-high"} {
		if _, err := ParseUrgency(bad); !errors.Is(err, ErrInvalidUrgency) {
			t.Errorf("ParseUrgency(%q) err = %v, want ErrInvalidUrgency", bad, err)
		}
	}

	if UrgencyUnset.String() != "" {
		t.Error("UrgencyUnset must have empty wire value")
	}
}

func TestValidTopic(t *testing.T) {
	valid := []string{
		"upd",
		"a!#$%&'*+-.^_`|~09AZaz",
		strings.Repeat("t", MaxTopicLength),
	}
	for _, ok := range valid {
		if err := ValidTopic(ok); err != nil {
			t.Errorf("ValidTopic(%q): %v", ok, err)
		}
	}

	invalid := []string{
		"",
		strings.Repeat("t", MaxTopicLength+1),
		"has space",
		"with,comma",
		"with\"quote",
		"tab\there",
		"\x00nul",
	}
	for _, bad := range invalid {
		if err := ValidTopic(bad); !errors.Is(err, ErrInvalidTopic) {
			t.Errorf("ValidTopic(%q) err = %v, want ErrInvalidTopic", bad, err)
		}
	}
}
