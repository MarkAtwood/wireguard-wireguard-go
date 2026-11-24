// Package handshakename parses and builds the WireGuard handshake name when it
// is carried on the wire rather than compiled in.
//
// WireGuard hashes a fixed string into the initial chaining key, for example
// "Noise_IKpsk2_SECP256R1_AesGcm_SHA256" in wolfGuard or
// "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" in stock. That string already names
// the key exchange, the AEAD and the hash. Agility therefore does not need a
// new identifier: it needs that string to travel with the handshake, so both
// ends hash the same bytes without having agreed a code point in advance.
//
// A dynamic name leads with a colon and then names three primitives:
//
//	:P-256:HKDF-SHA-256:AEAD_AES_256_GCM
//
// The leading colon is what distinguishes a dynamic name from the legacy fixed
// strings, so a peer that receives no name at all falls back to its compiled-in
// constant and deployed peers are unaffected.
//
// Three properties follow from hashing the received bytes directly, and the API
// is shaped to protect them:
//
// No table. The name is at once the identifier, the description and the domain
// separator. Nothing has to be registered, allocated or version-bumped to add a
// primitive; a new primitive is a new name from a public standard.
//
// Self-binding. Altering the name in flight changes the initial chaining key,
// so every key derived afterwards is wrong and the handshake fails to
// authenticate. No separate binding or transcript field is needed.
//
// Hash what you received. Raw returns the exact bytes the peer sent, never a
// re-rendering of the parsed fields, because a re-rendering that differed by
// one byte would silently derive a different chaining key.
//
// Parsing happens before the handshake is authenticated, since mac1 is keyed on
// the responder's static public key and that key is not secret. So the grammar
// is deliberately hostile: a hard length cap, a restricted character set, an
// exact field count, and a copy of the input rather than a reference into the
// packet buffer.
//
// The design is DESIGN-2026-runtime-multisuite.md in the WOLFGUARD-AGILITY
// project. Resolving names to implementations is a separate concern, as is
// computing the chaining key.
package handshakename

import (
	"errors"
	"fmt"
)

// Lead is the first byte of every dynamic name. A name that does not start
// with it is either a legacy fixed string or malformed.
const Lead = ':'

// MaxLen caps the encoded length. Three names from the public registries run
// to roughly forty bytes; the cap leaves room for hybrid key exchange names
// such as "X25519+ML-KEM-768" without inviting a peer to spend the receiver's
// budget on an unauthenticated path.
const MaxLen = 96

// MinLen is the shortest syntactically possible name: a lead and three
// single-character fields separated by colons.
const MinLen = len(":a:b:c")

// fields is how many primitives a name carries: key exchange, KDF, AEAD.
const fields = 3

// Errors reported when parsing or building a name. A peer that sends anything
// rejected here is malformed or hostile, so callers should drop rather than
// attempt recovery.
var (
	ErrNoLead       = errors.New("handshakename: name does not start with the lead byte")
	ErrTooShort     = errors.New("handshakename: name is shorter than the minimum")
	ErrTooLong      = errors.New("handshakename: name exceeds the maximum length")
	ErrFieldCount   = errors.New("handshakename: name does not carry exactly three primitives")
	ErrEmptyField   = errors.New("handshakename: name contains an empty primitive")
	ErrBadCharacter = errors.New("handshakename: name contains a disallowed character")
)

// permitted reports whether b may appear inside a primitive name. The set
// covers every character used by the public registries this targets, including
// the plus sign for hybrid key exchanges, and nothing else. Notably it excludes
// the colon, which keeps field splitting unambiguous, and every byte outside
// printable ASCII.
func permitted(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '-' || b == '_' || b == '.' || b == '+':
		return true
	default:
		return false
	}
}

// Name is a parsed dynamic handshake name holding the exact bytes that must be
// hashed, together with the bounds of each primitive within them.
//
// The zero Name is not valid; obtain one from Parse or Build.
type Name struct {
	raw    []byte
	bounds [fields][2]int
}

// Parse validates a dynamic handshake name and returns it.
//
// The returned Name owns a copy of raw, so the caller may reuse or overwrite
// its packet buffer immediately. This matters because the alternative, holding
// a subslice, would both alias a buffer destined for reuse and keep the whole
// packet alive for the lifetime of the handshake.
func Parse(raw []byte) (Name, error) {
	switch {
	case len(raw) > MaxLen:
		return Name{}, fmt.Errorf("name is %d bytes, limit is %d: %w", len(raw), MaxLen, ErrTooLong)
	case len(raw) < MinLen:
		return Name{}, fmt.Errorf("name is %d bytes, minimum is %d: %w", len(raw), MinLen, ErrTooShort)
	case raw[0] != Lead:
		return Name{}, fmt.Errorf("name starts with %#02x, want %#02x: %w", raw[0], Lead, ErrNoLead)
	}

	var (
		n      Name
		field  int
		start  = 1
		seen   = 0
		colons = 0
	)
	for i := 1; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == Lead:
			colons++
			if field >= fields-1 {
				return Name{}, fmt.Errorf("found %d separators, want %d: %w", colons+1, fields-1, ErrFieldCount)
			}
			if i == start {
				return Name{}, fmt.Errorf("primitive %d is empty: %w", field, ErrEmptyField)
			}
			n.bounds[field] = [2]int{start, i}
			field++
			start = i + 1
			seen++
		case !permitted(c):
			return Name{}, fmt.Errorf("byte %#02x at offset %d: %w", c, i, ErrBadCharacter)
		}
	}

	if field != fields-1 {
		return Name{}, fmt.Errorf("found %d separators, want %d: %w", field+1, fields-1, ErrFieldCount)
	}
	if start == len(raw) {
		return Name{}, fmt.Errorf("primitive %d is empty: %w", field, ErrEmptyField)
	}
	n.bounds[field] = [2]int{start, len(raw)}

	n.raw = make([]byte, len(raw))
	copy(n.raw, raw)
	return n, nil
}

// Build assembles a dynamic name from three primitive names, for the initiating
// side. It applies the same grammar Parse enforces, so a name this package
// produces is one it will also accept.
func Build(kex, kdf, aead string) (Name, error) {
	raw := make([]byte, 0, MaxLen)
	for _, part := range [fields]string{kex, kdf, aead} {
		if part == "" {
			return Name{}, fmt.Errorf("building %q/%q/%q: %w", kex, kdf, aead, ErrEmptyField)
		}
		raw = append(raw, Lead)
		raw = append(raw, part...)
	}
	return Parse(raw)
}

// Raw returns the exact bytes to hash into the initial chaining key, or to
// place on the wire.
//
// The slice aliases the Name's own storage and must not be modified. It is
// returned rather than copied because every caller hashes it immediately.
func (n Name) Raw() []byte {
	return n.raw
}

// Len is the encoded length of the name.
func (n Name) Len() int {
	return len(n.raw)
}

// String renders the name for logs and diagnostics. It is byte-identical to
// Raw for any Name obtained from Parse or Build, but Raw is what callers must
// hash: a future change here must never become the source of a chaining key.
func (n Name) String() string {
	return string(n.raw)
}

// KEX, KDF and AEAD return the primitive names as received.
//
// They are returned unresolved and uninterpreted. Deciding whether a primitive
// is supported, and whether local policy permits it, belongs to the caller: a
// syntactically valid name is not an authorised one.
func (n Name) KEX() string  { return n.field(0) }
func (n Name) KDF() string  { return n.field(1) }
func (n Name) AEAD() string { return n.field(2) }

func (n Name) field(i int) string {
	b := n.bounds[i]
	return string(n.raw[b[0]:b[1]])
}
