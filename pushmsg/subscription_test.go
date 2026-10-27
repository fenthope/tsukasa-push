package pushmsg

import (
	"encoding/base64"
	"testing"
)

func TestParseSubscription(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	sub := &Subscription{
		Endpoint:   "https://push.example.net/p/abc123",
		Public:     keys.Public,
		AuthSecret: keys.AuthSecret,
	}
	data, err := sub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Endpoint != sub.Endpoint {
		t.Errorf("endpoint = %q", back.Endpoint)
	}
	if !back.Public.Equal(sub.Public) {
		t.Error("public key mismatch")
	}
	if string(back.AuthSecret) != string(sub.AuthSecret) {
		t.Error("auth secret mismatch")
	}
}

func TestParseSubscriptionRejects(t *testing.T) {
	keys, err := GenerateUAKeys()
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(keys.Public.Bytes())
	auth := base64.RawURLEncoding.EncodeToString(keys.AuthSecret)

	for name, doc := range map[string]string{
		"not json":     `{`,
		"no endpoint":  `{"keys":{"p256dh":"` + pub + `","auth":"` + auth + `"}}`,
		"bad p256dh":   `{"endpoint":"https://x","keys":{"p256dh":"!!!","auth":"` + auth + `"}}`,
		"off curve":    `{"endpoint":"https://x","keys":{"p256dh":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 65)) + `","auth":"` + auth + `"}}`,
		"short auth":   `{"endpoint":"https://x","keys":{"p256dh":"` + pub + `","auth":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 8)) + `"}}`,
		"bad auth b64": `{"endpoint":"https://x","keys":{"p256dh":"` + pub + `","auth":"***"}}`,
	} {
		if _, err := ParseSubscription([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
