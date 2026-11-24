// Package namedalgo implements the Named-Algo v3 wire encoding for WireGuard
// crypto agility: an ordered, fixed-width vector of algorithm offers in which
// each primitive is identified by a truncated hash of its canonical public
// name.
//
// The encoding is fixed-width on purpose. A responder decodes an offer vector
// before the handshake is authenticated, because mac1 is keyed on the
// responder's static public key and that key is not secret from anyone who
// intends to talk to it. Decoding therefore has to be a bounds check and a
// loop rather than a parser.
//
// Identifying a primitive by the hash of its registry name, rather than by an
// assigned number, means no authority has to allocate code points: any
// implementation computes the same eight bytes from the same public string.
//
// The design this implements is DESIGN-2026-named-algo-v3.md in the
// WOLFGUARD-AGILITY project.
package namedalgo

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// IDLen is the encoded length of a PrimitiveID.
//
// Eight bytes is an identifier, not a security boundary. The suite actually in
// force is bound into the handshake transcript over the wire bytes, so a name
// collision cannot shift the negotiated suite without breaking that binding.
// What truncation does require is that no two entries in a given
// implementation's own dispatch table collide, which CheckCollisions asserts.
const IDLen = 8

// MaxOffers bounds how many offers a vector may carry, so that a peer cannot
// force unbounded work on an unauthenticated path.
const MaxOffers = 8

// OfferLen is the encoded length of one offer: a key exchange, a KDF and an
// AEAD identifier, in that order.
const OfferLen = 3 * IDLen

// Name is a canonical primitive name, taken verbatim from a public registry.
// Only these exact strings are hashed onto the wire. Synonyms are mapped to
// canonical form before hashing and are never emitted, so that "secp256r1" and
// "P-256" cannot produce two different identifiers for one primitive.
type Name string

// Canonical key exchange names.
const (
	KEXX25519   Name = "X25519"     // RFC 7748
	KEXP256     Name = "P-256"      // FIPS 186-5
	KEXP384     Name = "P-384"      // FIPS 186-5
	KEXMLKEM768 Name = "ML-KEM-768" // FIPS 203
)

// Canonical KDF names.
const (
	KDFHKDFSHA256     Name = "HKDF-SHA-256"     // RFC 5869
	KDFHKDFSHA384     Name = "HKDF-SHA-384"     // RFC 5869
	KDFHKDFBLAKE2s256 Name = "HKDF-BLAKE2S-256" // RFC 5869 over RFC 7693, non-FIPS
)

// Canonical AEAD names.
const (
	AEADAES128GCM        Name = "AEAD_AES_128_GCM"       // RFC 5116
	AEADAES256GCM        Name = "AEAD_AES_256_GCM"       // RFC 5116
	AEADChaCha20Poly1305 Name = "AEAD_CHACHA20_POLY1305" // RFC 8439
)

// Registry is every canonical name this package knows. It is the set
// CheckCollisions is expected to be run over at init.
var Registry = []Name{
	KEXX25519, KEXP256, KEXP384, KEXMLKEM768,
	KDFHKDFSHA256, KDFHKDFSHA384, KDFHKDFBLAKE2s256,
	AEADAES128GCM, AEADAES256GCM, AEADChaCha20Poly1305,
}

// Errors reported when decoding or encoding an offer vector. Callers match on
// these to distinguish a malformed peer from a local programming error.
var (
	ErrEmptyVector   = errors.New("namedalgo: offer vector is empty")
	ErrTooManyOffers = errors.New("namedalgo: offer count exceeds maximum")
	ErrShortBuffer   = errors.New("namedalgo: buffer too short for offer vector")
	ErrCollision     = errors.New("namedalgo: distinct names share a truncated id")
)

// PrimitiveID identifies one primitive by the first IDLen bytes of the
// SHA-256 of its canonical name.
type PrimitiveID [IDLen]byte

// IDFor returns the identifier for a canonical name.
func IDFor(n Name) PrimitiveID {
	sum := sha256.Sum256([]byte(n))
	var id PrimitiveID
	copy(id[:], sum[:IDLen])
	return id
}

// idFor is the indirection CheckCollisions uses, so that the collision branch
// is reachable in tests without having to craft a real 8-byte SHA-256
// collision. Production code calls IDFor.
var idFor = IDFor

// Offer is one candidate suite: a key exchange, a KDF and an AEAD chosen
// independently of each other.
type Offer struct {
	KEX  PrimitiveID
	KDF  PrimitiveID
	AEAD PrimitiveID
}

// OfferFor builds an Offer from canonical names.
func OfferFor(kex, kdf, aead Name) Offer {
	return Offer{KEX: IDFor(kex), KDF: IDFor(kdf), AEAD: IDFor(aead)}
}

// Vector is an ordered list of offers, most preferred first. Order is the
// sender's preference and carries no other meaning; duplicates are permitted
// on the wire and are the sender's problem, not the receiver's.
type Vector []Offer

// EncodedLen is the number of bytes Append will add.
func (v Vector) EncodedLen() int {
	return 1 + len(v)*OfferLen
}

// Append encodes v onto dst and returns the extended slice. It reports
// ErrEmptyVector or ErrTooManyOffers rather than emitting a vector a conforming
// peer would refuse.
func (v Vector) Append(dst []byte) ([]byte, error) {
	switch {
	case len(v) == 0:
		return nil, ErrEmptyVector
	case len(v) > MaxOffers:
		return nil, fmt.Errorf("encoding %d offers, limit is %d: %w", len(v), MaxOffers, ErrTooManyOffers)
	}

	dst = append(dst, byte(len(v)))
	for _, o := range v {
		dst = append(dst, o.KEX[:]...)
		dst = append(dst, o.KDF[:]...)
		dst = append(dst, o.AEAD[:]...)
	}
	return dst, nil
}

// Parse decodes an offer vector from the front of b and reports how many bytes
// it consumed.
//
// The byte count matters to the caller: the ephemeral public key that follows
// has a length determined by the selected key exchange, so the vector has to be
// decoded before the rest of the message can be located at all.
func Parse(b []byte) (Vector, int, error) {
	if len(b) < 1 {
		return nil, 0, fmt.Errorf("reading offer count from %d bytes: %w", len(b), ErrShortBuffer)
	}

	n := int(b[0])
	switch {
	case n == 0:
		return nil, 0, ErrEmptyVector
	case n > MaxOffers:
		return nil, 0, fmt.Errorf("peer offered %d, limit is %d: %w", n, MaxOffers, ErrTooManyOffers)
	}

	size := 1 + n*OfferLen
	if len(b) < size {
		return nil, 0, fmt.Errorf("%d offers need %d bytes, have %d: %w", n, size, len(b), ErrShortBuffer)
	}

	v := make(Vector, 0, n)
	for i := 0; i < n; i++ {
		off := 1 + i*OfferLen
		var o Offer
		copy(o.KEX[:], b[off:off+IDLen])
		copy(o.KDF[:], b[off+IDLen:off+2*IDLen])
		copy(o.AEAD[:], b[off+2*IDLen:off+OfferLen])
		v = append(v, o)
	}
	return v, size, nil
}

// CheckCollisions reports an error if two distinct names in the set share a
// truncated identifier. An implementation calls this at init over its own
// dispatch table: truncation is only safe while the local table is
// collision-free, and that is a property of the table rather than of the
// encoding.
//
// The same name appearing twice is not a collision.
func CheckCollisions(names []Name) error {
	seen := make(map[PrimitiveID]Name, len(names))
	for _, n := range names {
		id := idFor(n)
		if prev, ok := seen[id]; ok && prev != n {
			return fmt.Errorf("%q and %q both hash to %x: %w", prev, n, id, ErrCollision)
		}
		seen[id] = n
	}
	return nil
}
