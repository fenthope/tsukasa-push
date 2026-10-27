// Package pushmsg implements the Web Push message content coding and the
// protocol primitives shared by the sender, receiver and service packages.
//
// Encryption follows RFC 8188 ("aes128gcm" content coding) as restricted by
// RFC 8291: a single AEAD_AES_128_GCM record with a fixed 86-octet header
// (salt||rs||idlen||keyid), padding delimiter 0x02 and empty additional
// data. Key derivation uses ECDH over P-256 combined with the authentication
// secret via HKDF-SHA-256. Only the standard library is used.
package pushmsg

import "crypto/ecdh"

const (
	// ContentCoding is the sole permitted content coding for push messages
	// (RFC 8291 §4).
	ContentCoding = "aes128gcm"

	// MaxPayloadSize is the payload size a push service is required to
	// support (RFC 8030 §7.2).
	MaxPayloadSize = 4096

	// HeaderSize is the aes128gcm content header size:
	// salt(16) || rs(4) || idlen(1) || keyid(65).
	HeaderSize = 86

	// TagSize is the AEAD_AES_128_GCM authentication tag length.
	TagSize = 16

	// MaxPlaintextSize is the largest plaintext that fits into a single
	// 4096-octet payload (RFC 8291 §4).
	MaxPlaintextSize = MaxPayloadSize - HeaderSize - 1 - TagSize // 3993

	// AuthSecretSize is the size of the user agent authentication secret
	// (RFC 8291 §3.2).
	AuthSecretSize = 16

	// KeyIDSize is the size of the uncompressed P-256 public key carried in
	// the keyid field (RFC 8291 §4).
	KeyIDSize = 65

	// RecordSize is the rs value this implementation writes (RFC 8291 §4
	// permits any value larger than the single record).
	RecordSize = MaxPayloadSize
)

// Link relation URNs defined by RFC 8030 §9.2. The URI of a push message
// resource is conveyed via the Location header field, not a link relation.
const (
	RelPush    = "urn:ietf:params:push"
	RelSet     = "urn:ietf:params:push:set"
	RelReceipt = "urn:ietf:params:push:receipt"
)

// UAKeys holds the key material a user agent associates with a push
// subscription: an ephemeral-static ECDH key pair and the authentication
// secret (RFC 8291 §2, §3.1, §3.2).
type UAKeys struct {
	Private    *ecdh.PrivateKey
	Public     *ecdh.PublicKey
	AuthSecret []byte
}
