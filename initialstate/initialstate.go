// Package initialstate derives the Noise initial chaining key and initial hash
// for one cipher suite, and precomputes them for the suites a device accepts.
//
// WireGuard computes these two values once, into package-level variables, from
// constants fixed at compile time:
//
//	InitialChainKey = H(handshake name)
//	InitialHash     = H(InitialChainKey || identifier)
//
// A device that speaks more than one suite cannot hold them in globals, because
// each suite has its own handshake name and its own H. This package turns that
// pair into a value, derived once per suite rather than once per process, so a
// handshake selects a precomputed pair instead of hashing anything.
//
// The derivation is deliberately hash-agnostic: H arrives as a constructor, so
// a suite naming SHA-256 and a suite naming BLAKE2s share this code and differ
// only in what they pass. Resolving a suite's name to that constructor belongs
// elsewhere; so does deciding whether a suite is permitted at all.
//
// The identifier is not derived from anything on the wire. It is per-peer
// configuration distributed out of band, like a public key, which is why it is
// a parameter here rather than a constant.
//
// See DESIGN-2026-runtime-multisuite.md in the WOLFGUARD-AGILITY project.
package initialstate

import (
	"errors"
	"fmt"
	"hash"
	"sync"
)

// Errors reported when a suite's initial state cannot be derived. Each one
// indicates a local wiring mistake rather than a hostile peer: a name reaching
// this package has already been validated as syntax.
var (
	ErrNoHash          = errors.New("initialstate: hash constructor is nil")
	ErrEmptyName       = errors.New("initialstate: handshake name is empty")
	ErrEmptyIdentifier = errors.New("initialstate: identifier is empty")
	ErrNilHash         = errors.New("initialstate: hash constructor returned nil")
)

// State is the precomputed Noise initial state for one suite.
//
// Both slices are owned by the State and must not be modified. A handshake
// copies them into its own working buffers, exactly as the single-suite code
// assigned from the package-level variables.
type State struct {
	// ChainKey is H(handshake name).
	ChainKey []byte
	// Hash is H(ChainKey || identifier).
	Hash []byte
}

// Derive computes the initial state for one suite.
//
// name is the handshake name exactly as it appears on the wire, or the
// compiled-in constant for a peer that sends none. Passing anything other than
// those bytes yields a chaining key that no peer will agree with, which is why
// callers hand over what they received rather than a re-rendering of it.
func Derive(newHash func() hash.Hash, name, identifier []byte) (State, error) {
	switch {
	case newHash == nil:
		return State{}, ErrNoHash
	case len(name) == 0:
		return State{}, ErrEmptyName
	case len(identifier) == 0:
		return State{}, fmt.Errorf("deriving for name %q: %w", name, ErrEmptyIdentifier)
	}

	h := newHash()
	if h == nil {
		return State{}, ErrNilHash
	}
	h.Write(name)
	chainKey := h.Sum(nil)

	h = newHash()
	h.Write(chainKey)
	h.Write(identifier)

	return State{ChainKey: chainKey, Hash: h.Sum(nil)}, nil
}

// Cache holds the initial state for every suite a device accepts, keyed by
// handshake name.
//
// This is a precomputation cache keyed by a self-describing name, not a
// registry: nothing here assigns or agrees an identifier, and two peers that
// have never exchanged configuration still compute the same key from the same
// name. Adding a suite is adding a name.
//
// A Cache is safe for concurrent use. Use NewCache; the zero value is not
// ready, and a Cache must be passed by pointer because it carries a lock.
type Cache struct {
	mu     sync.RWMutex
	byName map[string]State
}

// NewCache returns an empty Cache.
func NewCache() *Cache {
	return &Cache{byName: make(map[string]State)}
}

// Add derives the initial state for name and stores it, returning the derived
// state. Adding the same name twice recomputes and overwrites, so a
// configuration reload does not have to prune first.
func (c *Cache) Add(newHash func() hash.Hash, name, identifier []byte) (State, error) {
	st, err := Derive(newHash, name, identifier)
	if err != nil {
		return State{}, fmt.Errorf("adding suite to cache: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.byName[string(name)] = st
	return st, nil
}

// Get returns the precomputed state for name.
//
// A miss means the device does not accept that suite, which is an ordinary
// outcome on an unauthenticated path and not an error: a peer may offer
// anything. Callers drop the handshake.
func (c *Cache) Get(name []byte) (State, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st, ok := c.byName[string(name)]
	return st, ok
}

// Len is how many suites the Cache holds.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byName)
}
