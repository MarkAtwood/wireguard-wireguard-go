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
	"crypto/rand"
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
// It is an interface so a wolfCrypt-backed implementation can replace the
// stdlib one without touching Resolve, Registry or anything that consumes a
// Suite. The interface is declared here, where it is consumed, rather than
// beside either implementation.
//
// Everything is plain bytes, in the encoding that goes on the wire, because
// that is what both backends already speak. The existing wolfCrypt path in
// device/noise-helpers.go imports a raw private key with
// Wc_ecc_import_private_key_ex and a peer's X9.63 point with
// Wc_ecc_import_x963_ex on every operation, and X9.63 uncompressed is
// byte-identical to what crypto/ecdh produces for P-256. An opaque key handle
// would be a different design than this codebase has, where private keys are
// already byte arrays, and would buy nothing today.
//
// GenerateKey deliberately takes no io.Reader. A FIPS implementation must draw
// from the validated module's own DRBG, so handing it an external entropy
// source would be wrong rather than merely unused.
type KEX interface {
	// PublicKeySize is the wire length of a public key. The wire layout
	// depends on it: a message's ephemeral field is this many bytes.
	PublicKeySize() int
	// PrivateKeySize is the length of a private key.
	PrivateKeySize() int
	// GenerateKey returns a fresh private key and its public key.
	GenerateKey() (priv, pub []byte, err error)
	// PublicKey derives the public key for a configured private key, which is
	// how a device learns its own static public key.
	PublicKey(priv []byte) (pub []byte, err error)
	// SharedSecret computes the shared secret from a private key and a peer's
	// wire-encoded public key.
	SharedSecret(priv, peerPub []byte) (ss []byte, err error)
}

// ecdhKEX implements KEX over crypto/ecdh. It is the prototype backend; a FIPS
// build registers a wolfCrypt implementation of the same interface instead.
type ecdhKEX struct {
	curve   ecdh.Curve
	pubLen  int
	privLen int
}

var _ KEX = ecdhKEX{}

func (k ecdhKEX) PublicKeySize() int  { return k.pubLen }
func (k ecdhKEX) PrivateKeySize() int { return k.privLen }

func (k ecdhKEX) GenerateKey() (priv, pub []byte, err error) {
	sk, err := k.curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	return sk.Bytes(), sk.PublicKey().Bytes(), nil
}

func (k ecdhKEX) PublicKey(priv []byte) ([]byte, error) {
	sk, err := k.curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("loading a %d byte private key: %w", len(priv), err)
	}
	return sk.PublicKey().Bytes(), nil
}

func (k ecdhKEX) SharedSecret(priv, peerPub []byte) ([]byte, error) {
	sk, err := k.curve.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("loading a %d byte private key: %w", len(priv), err)
	}
	pk, err := k.curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("loading a %d byte peer public key: %w", len(peerPub), err)
	}
	ss, err := sk.ECDH(pk)
	if err != nil {
		return nil, fmt.Errorf("computing shared secret: %w", err)
	}
	return ss, nil
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

// tablesMu guards the dispatch tables. Registration is expected at init, but
// the tables are read by handshake goroutines, so the lock is not optional.
var tablesMu sync.RWMutex

// RegisterKEX installs a key exchange implementation under a canonical public
// name, replacing any existing entry.
//
// This is how a FIPS build routes the same public names to wolfCrypt: it
// registers its own KEX implementations at init, and nothing in this package
// changes. The name is the public one, so a peer naming "P-256" interoperates
// whichever backend each end happens to use.
func RegisterKEX(name string, k KEX) {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	kexByName[name] = k
}

// RegisterHash installs a hash constructor under a canonical KDF name,
// replacing any existing entry.
func RegisterHash(name string, newHash func() hash.Hash) {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	hashByName[name] = newHash
}

// RegisterAEAD installs an AEAD constructor under a canonical AEAD name,
// replacing any existing entry.
//
// keySize is enforced on every construction, so an implementation cannot be
// driven with a key length its name does not describe.
func RegisterAEAD(name string, keySize int, newAEAD func(key []byte) (cipher.AEAD, error)) {
	tablesMu.Lock()
	defer tablesMu.Unlock()
	aeadByName[name] = aeadSpec{keySize: keySize, new: exactKey(keySize, newAEAD)}
}

// kexByName, hashByName and aeadByName are the dispatch tables. Keys are
// canonical public names, exactly as they appear on the wire. Access them
// under tablesMu.
var (
	kexByName = map[string]KEX{
		"X25519": ecdhKEX{curve: ecdh.X25519(), pubLen: 32, privLen: 32},
		"P-256":  ecdhKEX{curve: ecdh.P256(), pubLen: 65, privLen: 32},
		"P-384":  ecdhKEX{curve: ecdh.P384(), pubLen: 97, privLen: 48},
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
	tablesMu.RLock()
	defer tablesMu.RUnlock()

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
