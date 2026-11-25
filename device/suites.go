/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"sync"

	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/suitewolf"
	"golang.zx2c4.com/wireguard/wire"
)

// LegacyHandshakeName and LegacyIdentifier are the strings this build has
// always hashed into its initial chaining key and hash. They are frozen by
// deployment: a peer in the field computes its keys from exactly these bytes,
// so changing either one makes this device unable to talk to any of them.
//
// They are not parsed. The legacy vocabulary is not the registry vocabulary,
// SECP256R1 against P-256 and AesGcm against AEAD_AES_256_GCM, so the suite's
// primitives are stated in legacySuitePrimitives rather than read out of the
// name.
const (
	LegacyHandshakeName = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
	LegacyIdentifier    = "WolfGuard v1 info@wolfssl.com"
)

// legacySuitePrimitives names, in registry terms, what the legacy handshake
// name means.
var legacySuitePrimitives = struct{ kex, kdf, aead string }{
	kex:  "P-256",
	kdf:  "HKDF-SHA-256",
	aead: "AEAD_AES_256_GCM",
}

// deviceSuites holds the suites a device accepts and the one it initiates with.
//
// The suite supplies the handshake name, the precomputed initial state and the
// message layout. It does NOT supply the primitives the handshake calls: those
// remain wolfCrypt, reached directly. Routing them through a suite's
// implementations would move the FIPS path onto whatever backend the suite
// happens to carry, which is a separate decision with a Security Policy
// attached to it.
type deviceSuites struct {
	sync.RWMutex

	// registry holds every suite this device will accept.
	registry *suite.Registry
	// local is the suite used when initiating, and the default for a peer.
	local *suite.Suite
	// localLayout is local's message layout, cached so the send path does not
	// recompute it per handshake.
	localLayout wire.Layout
	// accepted holds every accepted suite by handshake name.
	accepted map[string]acceptedSuite
	// initiationSizes maps an initiation length to the handshake name of the
	// suite that produces it. The receive path knows a packet's length before
	// it knows which peer sent it, so it cannot ask a peer for its layout.
	initiationSizes map[int]string
	// responseSizes is the same for responses.
	responseSizes map[int]string
}

// acceptedSuite is a suite this device accepts, with its layout computed once.
type acceptedSuite struct {
	suite  *suite.Suite
	layout wire.Layout
}

// errSuiteLengthCollision is reported when a suite cannot be accepted because
// an already-accepted suite produces messages of the same length.
var errSuiteLengthCollision = errors.New("another accepted suite has the same message length")

// accept records a suite as acceptable, refusing one whose message lengths
// collide with a suite already accepted.
//
// The refusal is the point. Inbound handshakes are routed by message length, so
// two accepted suites of equal length would leave the second silently
// unreachable: every packet of that length would be decoded under the first.
// Failing at registration turns that into an error at the moment the mistake is
// made. Re-accepting the same handshake name replaces its entry and is not a
// collision.
//
// Must be called with device.suites held for writing.
func (device *Device) accept(s *suite.Suite) (wire.Layout, error) {
	name := string(s.Name())

	layout, err := wire.LayoutFor(s)
	if err != nil {
		return wire.Layout{}, fmt.Errorf("deriving the layout for %q: %w", name, err)
	}

	for _, c := range []struct {
		kind  string
		size  int
		index map[int]string
	}{
		{"initiation", layout.InitiationSize(), device.suites.initiationSizes},
		{"response", layout.ResponseSize(), device.suites.responseSizes},
	} {
		if owner, ok := c.index[c.size]; ok && owner != name {
			return wire.Layout{}, fmt.Errorf("%q and %q both produce a %d byte %s: %w",
				owner, name, c.size, c.kind, errSuiteLengthCollision)
		}
	}

	device.suites.accepted[name] = acceptedSuite{suite: s, layout: layout}
	device.suites.initiationSizes[layout.InitiationSize()] = name
	device.suites.responseSizes[layout.ResponseSize()] = name
	return layout, nil
}

// AcceptSuite registers a dynamic handshake name as acceptable, so a device
// mid-migration can serve both the old suite and the new one.
//
// It refuses a suite whose message lengths collide with one already accepted.
func (device *Device) AcceptSuite(name, identifier []byte) (*suite.Suite, error) {
	device.suites.Lock()
	defer device.suites.Unlock()

	s, err := device.suites.registry.Accept(name, identifier)
	if err != nil {
		return nil, fmt.Errorf("accepting suite %q: %w", name, err)
	}
	if _, err := device.accept(s); err != nil {
		return nil, err
	}
	return s, nil
}

// initSuites registers the legacy suite and makes it the local one.
//
// This reproduces the single-suite behaviour the build has today: the same
// handshake name, the same initial state, the same message sizes. A second
// suite becomes reachable by registering it here or through configuration,
// without anything else changing.
// registerBackend installs the wolfCrypt implementations into the suite
// package's tables, once per process.
//
// This is what makes the FIPS suite a FIPS path. Without it the suite package's
// stdlib backends would be used, which compute the same answers but not inside
// the validated module. It is explicit rather than an import side effect so
// that which cryptography a build uses is a visible decision.
var registerBackend sync.Once

func (device *Device) initSuites() error {
	registerBackend.Do(suitewolf.Register)

	device.suites.Lock()
	defer device.suites.Unlock()

	device.suites.registry = suite.NewRegistry()
	device.suites.accepted = make(map[string]acceptedSuite)
	device.suites.initiationSizes = make(map[int]string)
	device.suites.responseSizes = make(map[int]string)

	s, err := device.suites.registry.AcceptLegacy(
		[]byte(LegacyHandshakeName),
		legacySuitePrimitives.kex,
		legacySuitePrimitives.kdf,
		legacySuitePrimitives.aead,
		[]byte(LegacyIdentifier),
	)
	if err != nil {
		return fmt.Errorf("registering the legacy suite: %w", err)
	}

	layout, err := device.accept(s)
	if err != nil {
		return fmt.Errorf("accepting the legacy suite: %w", err)
	}

	device.suites.local = s
	device.suites.localLayout = layout
	return nil
}

// localSuite is the suite this device initiates with, and its layout.
func (device *Device) localSuite() (*suite.Suite, wire.Layout) {
	device.suites.RLock()
	defer device.suites.RUnlock()
	return device.suites.local, device.suites.localLayout
}

// acceptsInitiationSize reports whether any accepted suite produces an
// initiation of this length.
//
// This is the pre-authentication length check. It is a set membership test
// rather than an equality test because a device mid-migration accepts more than
// one suite, and the sender is not yet known.
func (device *Device) acceptsInitiationSize(n int) bool {
	device.suites.RLock()
	defer device.suites.RUnlock()
	_, ok := device.suites.initiationSizes[n]
	return ok
}

// acceptsResponseSize reports whether any accepted suite produces a response of
// this length.
func (device *Device) acceptsResponseSize(n int) bool {
	device.suites.RLock()
	defer device.suites.RUnlock()
	_, ok := device.suites.responseSizes[n]
	return ok
}

// maxHandshakeSize is the largest handshake message any accepted suite
// produces, which is what a receive buffer has to accommodate.
func (device *Device) maxHandshakeSize() int {
	device.suites.RLock()
	defer device.suites.RUnlock()
	max := 0
	for n := range device.suites.initiationSizes {
		if n > max {
			max = n
		}
	}
	for n := range device.suites.responseSizes {
		if n > max {
			max = n
		}
	}
	return max
}

// suiteFor returns the suite a peer uses, and its layout.
//
// A peer without an explicitly configured suite uses the device's, which is how
// every peer behaves until an orchestrator sets one.
func (peer *Peer) suiteFor() (*suite.Suite, wire.Layout) {
	peer.suiteMu.RLock()
	s, l := peer.suite, peer.layout
	peer.suiteMu.RUnlock()
	if s != nil {
		return s, l
	}
	return peer.device.localSuite()
}

// SetSuite pins the suite a peer initiates with, which is how an orchestrator
// sequences a migration: it moves peers onto the new suite one at a time, while
// the device continues to accept both.
func (peer *Peer) SetSuite(s *suite.Suite) error {
	if s == nil {
		return fmt.Errorf("peer %v: %w", peer, errNoSuite)
	}
	layout, err := wire.LayoutFor(s)
	if err != nil {
		return fmt.Errorf("peer %v: %w", peer, err)
	}

	peer.suiteMu.Lock()
	peer.suite = s
	peer.layout = layout
	peer.suiteMu.Unlock()
	return nil
}

// suiteForInitiationSize returns the accepted suite whose initiation is n
// bytes, and its layout.
//
// Both are returned because the receive path needs both: the layout to parse
// the packet, and the suite to validate it. Resolving them separately would
// let the two disagree.
//
// Length is a weak discriminator and this is deliberately the narrow version of
// the problem. It is exactly equivalent to the single-constant equality check it
// replaces while one suite is accepted, and it is correct whenever accepted
// suites differ in message length, which the two real suites do, 246 against
// 180. It cannot separate two accepted suites that share a length, for instance
// AES-128-GCM against AES-256-GCM. Settling that is what carrying the handshake
// name on the wire is for; until then, a device must not accept two suites of
// equal length, and registration is where that would be enforced.
func (device *Device) suiteForInitiationSize(n int) (*suite.Suite, wire.Layout, bool) {
	return device.suiteForSize(device.suites.initiationSizes, n)
}

// suiteForResponseSize is the same for responses.
func (device *Device) suiteForResponseSize(n int) (*suite.Suite, wire.Layout, bool) {
	return device.suiteForSize(device.suites.responseSizes, n)
}

func (device *Device) suiteForSize(index map[int]string, n int) (*suite.Suite, wire.Layout, bool) {
	device.suites.RLock()
	defer device.suites.RUnlock()
	name, ok := index[n]
	if !ok {
		return nil, wire.Layout{}, false
	}
	c, ok := device.suites.accepted[name]
	if !ok {
		return nil, wire.Layout{}, false
	}
	return c.suite, c.layout, true
}

// kex is the key exchange of the suite this device initiates with.
func (device *Device) kex() suite.KEX {
	s, _ := device.localSuite()
	if s == nil {
		return nil
	}
	return s.KEX
}

// setSuite records the suite a handshake runs under, and caches its message
// layout beside it so the send path does not derive the layout per packet.
//
// The two are set together because they must not diverge: the layout says how
// long the fields the suite's primitives produce are.
func (h *Handshake) setSuite(s *suite.Suite) error {
	if s == nil {
		return errNoSuite
	}
	layout, err := wire.LayoutFor(s)
	if err != nil {
		return fmt.Errorf("deriving the layout for %q: %w", s.Name(), err)
	}
	h.suite = s
	h.layout = layout
	return nil
}

// beginTranscript sizes the transcript hash and chaining key from the
// handshake's suite and seeds them with that suite's precomputed initial state.
//
// This cannot happen when the Handshake is created. A Handshake is part of a
// Peer, which exists before any suite has been chosen for it, and these two
// buffers are the suite's hash length. An initiator calls this; a responder
// computes the same transcript into scratch before it knows which peer is
// speaking, and installs the result instead.
func (h *Handshake) beginTranscript() error {
	if h.suite == nil {
		return errNoSuite
	}
	h.chainKey = bytes.Clone(h.suite.State.ChainKey)
	h.hash = bytes.Clone(h.suite.State.Hash)
	if len(h.chainKey) == 0 || len(h.hash) != len(h.chainKey) {
		return fmt.Errorf("suite %q has a %d byte chain key and a %d byte hash: %w",
			h.suite.Name(), len(h.chainKey), len(h.hash), errKeySize)
	}
	return nil
}

// suiteInForce is the suite a handshake is running under and that suite's
// layout.
//
// The send path needs both after the message has been built: the layout to
// encode it, and the suite to compute its MACs. They are read together under
// one lock so the packet cannot be encoded under one suite's layout and
// MAC'd under another's.
func (h *Handshake) suiteInForce() (*suite.Suite, wire.Layout) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.suite, h.layout
}

// newHash and newHMAC are the suite's primitives for this handshake.
//
// They fall back to nothing: a handshake with no suite cannot hash, and
// returning a hardcoded primitive would be worse than failing, because it would
// derive keys that do not match the suite the peers agreed on.
func (h *Handshake) newHash() func() hash.Hash {
	if h.suite == nil {
		return nil
	}
	return h.suite.NewHash
}

func (h *Handshake) newHMAC() hmacFunc {
	if h.suite == nil {
		return nil
	}
	return h.suite.NewHMAC
}

// aeadSeal encrypts with the suite's AEAD under the all-zero nonce the
// handshake uses, returning ciphertext with the tag appended.
//
// The handshake's AEAD comes from the suite rather than a hardcoded wolfCrypt
// call, so a suite naming ChaCha20-Poly1305 would encrypt with it.
//
// The nonce is zero because every handshake AEAD key is used exactly once,
// which is the existing protocol's property and not something this changes. Its
// LENGTH comes from the AEAD rather than from a constant: deployed wolfGuard
// uses a 16-byte IV with AES-GCM, while ChaCha20-Poly1305 takes 12 and has no
// 16-byte variant, so a fixed-size nonce cannot serve both.
func aeadSeal(s *suite.Suite, key, plaintext, aad []byte) ([]byte, error) {
	if s == nil {
		return nil, errNoSuite
	}
	aead, err := s.NewAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("constructing the suite's aead: %w", err)
	}
	return aead.Seal(nil, make([]byte, aead.NonceSize()), plaintext, aad), nil
}

// aeadOpen authenticates and decrypts with the suite's AEAD.
//
// A failure is returned rather than logged: the caller drops the handshake, and
// an authentication failure is indistinguishable from a mechanical one by
// design, since neither should tell a peer anything.
func aeadOpen(s *suite.Suite, key, ciphertext, aad []byte) ([]byte, error) {
	if s == nil {
		return nil, errNoSuite
	}
	aead, err := s.NewAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("constructing the suite's aead: %w", err)
	}
	return aead.Open(nil, make([]byte, aead.NonceSize()), ciphertext, aad)
}
