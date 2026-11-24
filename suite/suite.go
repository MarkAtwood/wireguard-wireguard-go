// Package suite resolves a handshake name into the primitives it names, and
// holds the suites a device accepts.
//
// This is the only mapping the design keeps, and it is the one the 2025
// proposal explicitly sanctioned: "the dispatch table is the only mapping you
// maintain (string to function pointers), and it's 1:1 with public names". It
// is not a registry. Nothing here assigns an identifier, allocates a code
// point or has to be agreed between peers. Two implementations that have never
// exchanged configuration resolve the same public name to their own local
// implementation of the same primitive, and derive the same keys.
//
// Dynamic names are self-describing, so Accept parses one and resolves it.
// Legacy names are not: "Noise_IKpsk2_SECP256R1_AesGcm_SHA256" says SECP256R1
// where the registries say P-256, and AesGcm where they say AEAD_AES_256_GCM.
// A legacy suite's primitives therefore cannot be read out of its name and must
// be stated explicitly, which is what AcceptLegacy is for.
//
// The implementations wired here are Go's standard library and x/crypto. They
// prove the mechanism and are not a FIPS path: a FIPS build must resolve the
// same names to wolfCrypt. The Suite fields are function values precisely so
// that swap needs no change here.
//
// See DESIGN-2026-runtime-multisuite.md in the WOLFGUARD-AGILITY project.
package suite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"sync"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"golang.zx2c4.com/wireguard/handshakename"
	"golang.zx2c4.com/wireguard/initialstate"
)

// Errors reported when a name cannot be resolved. A peer naming a primitive
// this build does not implement is an ordinary outcome, not an attack, and the
// handshake is dropped.
var (
	ErrUnknownKEX  = errors.New("suite: key exchange is not implemented")
	ErrUnknownKDF  = errors.New("suite: kdf is not implemented")
	ErrUnknownAEAD = errors.New("suite: aead is not implemented")
	ErrKeySize     = errors.New("suite: key length does not match the named aead")
)

// KEX is the key exchange of a suite.
//
// The sizes are carried rather than computed because the wire layout depends on
// them: a message's ephemeral field is PublicKeySize bytes, so struct sizing
// reads this. They are checked against a freshly generated key in the tests, so
// a wrong constant here cannot pass silently.
type KEX struct {
	Curve          ecdh.Curve
	PublicKeySize  int
	PrivateKeySize int
}

// Suite is everything a handshake needs once the name is known.
type Suite struct {
	// NewHash constructs the suite's hash. The KDF name selects it, since what
	// the Noise handshake needs from "HKDF-SHA-256" is SHA-256 itself.
	NewHash func() hash.Hash
	// NewAEAD constructs the suite's AEAD from a key of AEADKeySize bytes.
	NewAEAD func(key []byte) (cipher.AEAD, error)
	// AEADKeySize is the AEAD's key length in bytes.
	AEADKeySize int
	// KEX is the key exchange.
	KEX KEX
	// State is the precomputed Noise initial state for this suite.
	State initialstate.State

	name []byte
}

// Name returns the handshake name this suite was resolved from, as the bytes
// that are hashed and placed on the wire.
func (s *Suite) Name() []byte { return s.name }

// kexByName, hashByName and aeadByName are the dispatch tables. Keys are
// canonical public names, exactly as they appear on the wire.
var (
	kexByName = map[string]KEX{
		"X25519": {Curve: ecdh.X25519(), PublicKeySize: 32, PrivateKeySize: 32},
		"P-256":  {Curve: ecdh.P256(), PublicKeySize: 65, PrivateKeySize: 32},
		"P-384":  {Curve: ecdh.P384(), PublicKeySize: 97, PrivateKeySize: 48},
	}

	hashByName = map[string]func() hash.Hash{
		"HKDF-SHA-256": sha256.New,
		"HKDF-SHA-384": sha512.New384,
		"HKDF-BLAKE2S-256": func() hash.Hash {
			// blake2s.New256 only fails for an oversized key, and the key is nil.
			h, err := blake2s.New256(nil)
			if err != nil {
				panic("suite: blake2s.New256(nil) cannot fail: " + err.Error())
			}
			return h
		},
	}

	aeadByName = map[string]aeadSpec{
		"AEAD_AES_128_GCM":       {keySize: 16, new: exactKey(16, newAESGCM)},
		"AEAD_AES_256_GCM":       {keySize: 32, new: exactKey(32, newAESGCM)},
		"AEAD_CHACHA20_POLY1305": {keySize: 32, new: exactKey(32, chacha20poly1305.New)},
	}
)

type aeadSpec struct {
	keySize int
	new     func(key []byte) (cipher.AEAD, error)
}

// exactKey binds a constructor to one key length.
//
// This is load-bearing, not belt and braces. aes.NewCipher accepts 16, 24 or 32
// bytes and picks the variant from the length, so a single shared constructor
// would let AEAD_AES_256_GCM run AES-128 on a short key, and
// AEAD_AES_128_GCM run AES-256 on a long one. Either way the suite in force
// would stop matching the name that was hashed into the chaining key, and the
// short-key direction is a silent downgrade.
func exactKey(n int, f func(key []byte) (cipher.AEAD, error)) func(key []byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		if len(key) != n {
			return nil, fmt.Errorf("got %d bytes, need exactly %d: %w", len(key), n, ErrKeySize)
		}
		return f(key)
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher from a %d byte key: %w", len(key), err)
	}
	return cipher.NewGCM(block)
}

// Resolve turns three canonical primitive names into a Suite, without a
// handshake name or initial state. It is the dispatch step on its own, for
// callers assembling a suite from configuration rather than from the wire.
func Resolve(kex, kdf, aead string) (*Suite, error) {
	k, ok := kexByName[kex]
	if !ok {
		return nil, fmt.Errorf("%q: %w", kex, ErrUnknownKEX)
	}
	newHash, ok := hashByName[kdf]
	if !ok {
		return nil, fmt.Errorf("%q: %w", kdf, ErrUnknownKDF)
	}
	a, ok := aeadByName[aead]
	if !ok {
		return nil, fmt.Errorf("%q: %w", aead, ErrUnknownAEAD)
	}
	return &Suite{NewHash: newHash, NewAEAD: a.new, AEADKeySize: a.keySize, KEX: k}, nil
}

// Registry holds the suites a device accepts, keyed by handshake name.
//
// Safe for concurrent use. Use NewRegistry; a Registry carries a lock and must
// be passed by pointer.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]*Suite
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]*Suite)}
}

// Accept resolves a dynamic handshake name, derives its initial state, and
// stores the suite so Lookup can find it. It returns the stored suite.
//
// identifier is per-peer configuration distributed out of band, not wire data.
func (r *Registry) Accept(name, identifier []byte) (*Suite, error) {
	parsed, err := handshakename.Parse(name)
	if err != nil {
		return nil, fmt.Errorf("accepting suite: %w", err)
	}

	s, err := Resolve(parsed.KEX(), parsed.KDF(), parsed.AEAD())
	if err != nil {
		return nil, fmt.Errorf("accepting %q: %w", name, err)
	}
	return r.store(s, parsed.Raw(), identifier)
}

// AcceptLegacy stores a suite whose handshake name is a compiled-in constant
// rather than a dynamic name, so its primitives are stated rather than parsed.
//
// The name is used verbatim as the hash input, which is what keeps a legacy
// peer's chaining key byte-identical to what it computes today.
func (r *Registry) AcceptLegacy(name []byte, kex, kdf, aead string, identifier []byte) (*Suite, error) {
	s, err := Resolve(kex, kdf, aead)
	if err != nil {
		return nil, fmt.Errorf("accepting legacy %q: %w", name, err)
	}
	owned := make([]byte, len(name))
	copy(owned, name)
	return r.store(s, owned, identifier)
}

func (r *Registry) store(s *Suite, name, identifier []byte) (*Suite, error) {
	st, err := initialstate.Derive(s.NewHash, name, identifier)
	if err != nil {
		return nil, fmt.Errorf("deriving initial state for %q: %w", name, err)
	}
	s.State = st
	s.name = name

	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName[string(name)] = s
	return s, nil
}

// Lookup returns the accepted suite for a handshake name.
//
// A miss means this device does not accept that suite. That is an ordinary
// outcome on an unauthenticated path, since a peer may name anything, so it is
// reported as absence rather than as an error.
func (r *Registry) Lookup(name []byte) (*Suite, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byName[string(name)]
	return s, ok
}

// Len is how many suites the Registry accepts.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byName)
}
