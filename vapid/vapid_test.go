package vapid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 8292 §2.4 Figure 1: a complete Authorization value from the RFC.
// The signature verification against the embedded key is a true
// interoperability check of the hand rolled JWS layer.
const (
	rfcExampleToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9." +
		"eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0." +
		"i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA"
	rfcExampleKey = "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs"
	rfcExampleAud = "https://push.example.net"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRFC8292Example(t *testing.T) {
	claims, pub, err := Verify("vapid t="+rfcExampleToken+", k="+rfcExampleKey, rfcExampleAud, time.Unix(1453523768-3600, 0))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != rfcExampleAud {
		t.Errorf("aud = %q", claims.Audience)
	}
	if claims.Expiry != 1453523768 {
		t.Errorf("exp = %d", claims.Expiry)
	}
	if claims.Subject != "mailto:push@example.com" {
		t.Errorf("sub = %q", claims.Subject)
	}
	if EncodeKeyB64(pub) != rfcExampleKey {
		t.Errorf("re-encoded key mismatch: %s", EncodeKeyB64(pub))
	}

	// The header must carry typ JWT / alg ES256 (Figure 2).
	headerB64, _, _ := strings.Cut(rfcExampleToken, ".")
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatal(err)
	}
	var head map[string]string
	if err := json.Unmarshal(raw, &head); err != nil {
		t.Fatal(err)
	}
	if head["typ"] != "JWT" || head["alg"] != "ES256" {
		t.Errorf("header = %v", head)
	}
}

func TestRFC8292ExampleChecks(t *testing.T) {
	valid := time.Unix(1453523768-3600, 0)
	t.Run("expired", func(t *testing.T) {
		_, _, err := Verify("vapid t="+rfcExampleToken+", k="+rfcExampleKey, rfcExampleAud, time.Unix(1453523768+1, 0))
		if !errors.Is(err, ErrExpired) {
			t.Errorf("want ErrExpired, got %v", err)
		}
	})
	t.Run("lifetime beyond 24h", func(t *testing.T) {
		_, _, err := Verify("vapid t="+rfcExampleToken+", k="+rfcExampleKey, rfcExampleAud, valid.Add(-25*time.Hour))
		if !errors.Is(err, ErrLifetimeTooLong) {
			t.Errorf("want ErrLifetimeTooLong, got %v", err)
		}
	})
	t.Run("foreign audience", func(t *testing.T) {
		_, _, err := Verify("vapid t="+rfcExampleToken+", k="+rfcExampleKey, "https://evil.example", valid)
		if !errors.Is(err, ErrAudience) {
			t.Errorf("want ErrAudience, got %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other := testSigner(t)
		_, _, err := Verify("vapid t="+rfcExampleToken+", k="+other.PublicKeyB64(), rfcExampleAud, valid)
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("want ErrBadSignature, got %v", err)
		}
	})
	t.Run("tampered token", func(t *testing.T) {
		bad := strings.Replace(rfcExampleToken, ".i3CYb", ".x3CYb", 1)
		_, _, err := Verify("vapid t="+bad+", k="+rfcExampleKey, rfcExampleAud, valid)
		if !errors.Is(err, ErrBadCredential) && !errors.Is(err, ErrBadSignature) {
			t.Errorf("want bad encoding/signature, got %v", err)
		}
	})
}

func TestParseAuthorization(t *testing.T) {
	cred := `vapid t=abc.def.ghi, k=` + rfcExampleKey
	tok, key, err := ParseAuthorization(cred)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "abc.def.ghi" || key != rfcExampleKey {
		t.Errorf("got %q, %q", tok, key)
	}

	// Quoted parameters and extra whitespace / unknown params are fine.
	if _, _, err := ParseAuthorization(`VAPID t="abc.def.ghi", junk="x",  k="` + rfcExampleKey + `" `); err != nil {
		t.Errorf("quoted/unknown params: %v", err)
	}
	for _, bad := range []string{
		"", "Basic abc", "vapid", "vapid t=only", "vapid k=only",
		"vapid t=a, t=b, k=c",
	} {
		if _, _, err := ParseAuthorization(bad); !errors.Is(err, ErrBadCredential) {
			t.Errorf("ParseAuthorization(%q) err = %v, want ErrBadCredential", bad, err)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)
	now := time.Now().UTC().Truncate(time.Second)
	cred, err := s.Authorization("https://push.example.net", "mailto:push@example.com", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claims, pub, err := Verify(cred, "https://push.example.net", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "mailto:push@example.com" || claims.Expiry != now.Add(time.Hour).Unix() {
		t.Errorf("claims = %+v", claims)
	}
	if EncodeKeyB64(pub) != s.PublicKeyB64() {
		t.Error("embedded key differs from signer key")
	}

	// exp too far ahead must be refused at signing time (=24h is allowed).
	if _, err := s.Token("https://p", "", now.Add(24*time.Hour+time.Second)); !errors.Is(err, ErrLifetimeTooLong) {
		t.Errorf("want ErrLifetimeTooLong, got %v", err)
	}
	if _, err := s.Token("https://p", "", now.Add(-time.Minute)); !errors.Is(err, ErrLifetimeTooLong) {
		t.Errorf("want ErrLifetimeTooLong for past expiry, got %v", err)
	}
}

func TestVerifyTokenAlg(t *testing.T) {
	s := testSigner(t)
	tok, err := s.Token("https://p.example", "", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := VerifyToken(tok, s.Public(), "https://p.example", now); err != nil {
		t.Fatal(err)
	}
	// Swap the alg field to "HS256" in the header.
	headerB64, rest, _ := strings.Cut(tok, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(headerB64)
	var head map[string]string
	if err := json.Unmarshal(raw, &head); err != nil {
		t.Fatal(err)
	}
	head["alg"] = "HS256"
	forged, _ := json.Marshal(head)
	bad := base64.RawURLEncoding.EncodeToString(forged) + "." + rest
	if _, err := VerifyToken(bad, s.Public(), "https://p.example", now); !errors.Is(err, ErrBadAlg) {
		t.Errorf("want ErrBadAlg, got %v", err)
	}
}

func TestKeyB64RoundTrip(t *testing.T) {
	s := testSigner(t)
	pub, err := DecodeKeyB64(s.PublicKeyB64())
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(s.Public().X) != 0 || pub.Y.Cmp(s.Public().Y) != 0 {
		t.Error("key round trip mismatch")
	}
	for _, bad := range []string{"", "!!!!", strings.Repeat("A", 86), base64.RawURLEncoding.EncodeToString(make([]byte, 65))} {
		if _, err := DecodeKeyB64(bad); !errors.Is(err, ErrBadCredential) {
			t.Errorf("DecodeKeyB64(%q) err = %v, want ErrBadCredential", bad, err)
		}
	}
}

func TestSignerRejectsWrongKey(t *testing.T) {
	if _, err := NewSigner(nil); err == nil {
		t.Error("nil key must be rejected")
	}
}

func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://Push.Example.Net/p/xyz?a=1": "https://push.example.net",
		"https://push.example.net:443/p":     "https://push.example.net",
		"http://push.example.net:80/":        "http://push.example.net",
		"https://push.example.net:8443/p/1":  "https://push.example.net:8443",
		"http://localhost:3000/subscribe":    "http://localhost:3000",
	} {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := Origin(u); got != want {
			t.Errorf("Origin(%s) = %s, want %s", in, got, want)
		}
	}
}
