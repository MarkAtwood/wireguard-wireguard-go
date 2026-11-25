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
	"sort"
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
// A suite supplies the handshake name, the precomputed initial state, the
// message layout, and the primitives the handshake runs on: the hash and HMAC
// of its transcript, the AEAD that seals the static key and the timestamp, and
// the key exchange. mac1 and mac2 take their hash and their length from it as
// well. The handshake reaches none of those directly, which is what
// TestHandshakeFileCallsNoCryptoDirectly asserts.
//
// Carrying the primitives does not cost the FIPS path, which was the worry
// while they were still called directly. registerBackend points the suite
// package's tables at wolfCrypt, so a resolved name yields wolfCrypt
// implementations and the validated module computes what the handshake
// computes.
//
// What is still reached directly lies outside the handshake transcript: the
// cookie reply's own AES-GCM and the random bytes it needs (cookie.go), random
// session indices (indextable.go), and constant-time comparison. The cookie
// reply is also still compile-time sized, for a reason of its own (6ytx.18).
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
	/* Static identity before suites, which is the order SetPrivateKey takes
	 * them in: it holds the identity while asking the device for its suite. */
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.suites.Lock()
	defer device.suites.Unlock()

	s, err := device.resolveSuite(name, identifier)
	if err != nil {
		return nil, fmt.Errorf("accepting suite %q: %w", name, err)
	}

	/* A suite whose key exchange is not this device's identity's can never
	 * complete a handshake, so accepting it would do more than waste work: it
	 * takes a message-length routing slot, where it would both swallow every
	 * packet of that length and block a usable suite of the same length
	 * through the collision guard. */
	if err := device.staticIdentityUsableWith(s.KEX); err != nil {
		return nil, fmt.Errorf("accepting suite %q: %w", name, err)
	}

	if _, err := device.accept(s); err != nil {
		return nil, err
	}
	return s, nil
}

// resolveSuite turns a handshake name into a suite, parsing a dynamic name or
// stating the legacy one's primitives.
//
// The legacy name is the exception the suite package documents: "SECP256R1"
// where the registries say P-256, so its primitives cannot be read out of it.
// Keeping that exception here, rather than at the call sites, is what makes the
// accept set expressible as configuration. An operator, and the device's own
// get output, names every accepted suite the same way, and the legacy suite can
// be retired from the accept set and put back like any other.
//
// Must be called with device.suites held for writing.
func (device *Device) resolveSuite(name, identifier []byte) (*suite.Suite, error) {
	if string(name) == LegacyHandshakeName {
		return device.suites.registry.AcceptLegacy(name,
			legacySuitePrimitives.kex,
			legacySuitePrimitives.kdf,
			legacySuitePrimitives.aead,
			identifier)
	}
	return device.suites.registry.Accept(name, identifier)
}

// UnacceptSuite removes a suite from the set this device accepts.
//
// This is the step that ends a migration. Until it runs, a device mid-migration
// serves both suites, and the old one is still reachable by anything that can
// reach the device at all.
//
// It refuses to remove a suite that is still in force, either as this device's
// local suite or as some peer's pinned one. Such a device would go on
// initiating in that suite while no longer being able to route the response
// back, since responses are routed by length out of the accept set, so every
// handshake would fail with nothing in the configuration to say why.
//
// The suite stays resolvable in the registry, which is a factory here rather
// than the accept set: nothing in this package looks a suite up by name through
// it, and leaving the entry makes accepting the suite again a re-derivation
// rather than a re-resolution.
func (device *Device) UnacceptSuite(name string) error {
	/* Peers before suites, which is the order SetPrivateKey takes them in. */
	device.peers.RLock()
	defer device.peers.RUnlock()

	for _, peer := range device.peers.keyMap {
		peer.suiteMu.RLock()
		pinned := peer.suite
		peer.suiteMu.RUnlock()
		if pinned != nil && string(pinned.Name()) == name {
			return fmt.Errorf("%v still initiates with %q: %w", peer, name, errSuiteInForce)
		}
	}

	device.suites.Lock()
	defer device.suites.Unlock()

	c, ok := device.suites.accepted[name]
	if !ok {
		return fmt.Errorf("%q: %w", name, errSuiteNotAccepted)
	}
	if c.suite == device.suites.local {
		return fmt.Errorf("this device initiates with %q: %w", name, errSuiteInForce)
	}

	/* A suite's message lengths are a function of its name, and accept refuses
	 * a second suite of the same length, so these two entries are this
	 * suite's. */
	delete(device.suites.accepted, name)
	delete(device.suites.initiationSizes, c.layout.InitiationSize())
	delete(device.suites.responseSizes, c.layout.ResponseSize())
	return nil
}

// SetLocalSuite chooses the suite this device initiates with, which is also the
// suite every peer that has no pinned suite of its own uses.
//
// The suite must already be accepted. A device has to route the response to its
// own initiation back by length, and the accept set is what the receive path
// routes out of, so initiating in an unaccepted suite could never complete.
//
// Unpinned peers keep the static-static secret they already hold. Every
// accepted suite derives this device's own public key from its own private key,
// which is what staticIdentityUsableWith checks, and two key exchanges cannot
// agree on that unless they are the same curve, so the secret has the same
// value under all of them.
func (device *Device) SetLocalSuite(name string) error {
	/* Static identity before suites, the order AcceptSuite takes them in. */
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.suites.Lock()
	defer device.suites.Unlock()

	c, ok := device.suites.accepted[name]
	if !ok {
		return fmt.Errorf("%q: %w", name, errSuiteNotAccepted)
	}
	if err := device.staticIdentityUsableWith(c.suite.KEX); err != nil {
		return fmt.Errorf("this device cannot initiate with %q: %w", name, err)
	}

	device.suites.local = c.suite
	device.suites.localLayout = c.layout
	return nil
}

// suiteConfig is this device's suite configuration as the configuration surface
// reports it: the accept set, sorted, and the handshake name this device
// initiates with.
//
// The two are read under one lock. Reported separately they could disagree, and
// a local suite absent from the accept set reported beside it is configuration
// that does not re-apply.
//
// Sorting is what makes reading the configuration back deterministic, since the
// accept set is a map.
func (device *Device) suiteConfig() (accepted []string, local string) {
	device.suites.RLock()
	defer device.suites.RUnlock()

	accepted = make([]string, 0, len(device.suites.accepted))
	for name := range device.suites.accepted {
		accepted = append(accepted, name)
	}
	sort.Strings(accepted)

	if device.suites.local != nil {
		local = string(device.suites.local.Name())
	}
	return accepted, local
}

// acceptedSuite returns an accepted suite by handshake name.
//
// Pinning a peer goes through this rather than through the registry, so a peer
// can only be moved onto a suite the device also accepts.
func (device *Device) acceptedSuite(name string) (*suite.Suite, bool) {
	device.suites.RLock()
	defer device.suites.RUnlock()
	c, ok := device.suites.accepted[name]
	return c.suite, ok
}

// deviceIdentifier is the identifier this device derives a suite's initial
// state with when a suite is accepted over the configuration surface.
//
// There is one per device. The design calls for the identifier to be per-peer
// configuration distributed by the orchestrator, like the public key, but a
// suite's initial state is precomputed once per accepted suite and the registry
// is keyed by handshake name alone, so one device cannot presently hold the same
// suite under two identifiers. Every wolfGuard in the field uses the value
// below, so configuring a suite derives the state those peers compute.
func (device *Device) deviceIdentifier() []byte {
	return []byte(LegacyIdentifier)
}

// registerBackend installs the wolfCrypt implementations into the suite
// package's tables, once per process.
//
// This is what makes the FIPS suite a FIPS path. Without it the suite package's
// stdlib backends would be used, which compute the same answers but not inside
// the validated module. It is explicit rather than an import side effect so
// that which cryptography a build uses is a visible decision.
var registerBackend sync.Once

// initSuites registers the legacy suite and makes it the local one.
//
// This reproduces the single-suite behaviour the build has today: the same
// handshake name, the same initial state, the same message sizes. A second
// suite becomes reachable by registering it here or through configuration,
// without anything else changing.
func (device *Device) initSuites() error {
	registerBackend.Do(suitewolf.Register)

	device.suites.Lock()
	defer device.suites.Unlock()

	device.suites.registry = suite.NewRegistry()
	device.suites.accepted = make(map[string]acceptedSuite)
	device.suites.initiationSizes = make(map[int]string)
	device.suites.responseSizes = make(map[int]string)

	s, err := device.resolveSuite([]byte(LegacyHandshakeName), device.deviceIdentifier())
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

// staticIdentityUsableWith reports whether this device's static key pair
// belongs to a key exchange.
//
// It derives the public key from the device's private key under that key
// exchange and compares it against the device's own. Comparing key lengths
// would not be enough: this proves the scalar is a usable private key for that
// curve and that it is the one this device's identity names.
//
// A device with no static key yet is accepted. Peers and suites may be
// configured before the private key is, and the handshake refuses to run on an
// empty static-static secret, so nothing slips through by allowing it here.
//
// Must be called with staticIdentity held, at least for reading.
func (device *Device) staticIdentityUsableWith(kex suite.KEX) error {
	if kex == nil {
		return errNoSuite
	}
	if device.staticIdentity.privateKey.IsZero() {
		return nil
	}

	pub, err := device.staticIdentity.privateKey.publicKey(kex)
	if err != nil {
		return fmt.Errorf("this device's static key is unusable with that key exchange: %w: %w",
			err, errStaticIdentityKEX)
	}
	if !pub.Equals(device.staticIdentity.publicKey) {
		return fmt.Errorf("it derives %d bytes of public key where this device's identity is %d: %w",
			pub.Len(), device.staticIdentity.publicKey.Len(), errStaticIdentityKEX)
	}
	return nil
}

// staticStatic computes the long-term shared secret between this device's
// static private key and a peer's static public key, under a key exchange.
//
// The key exchange is the peer's suite's, not the device's. Every other key
// operation in the handshake comes from the suite in force, and this secret is
// an input to the handshake transcript, so taking it from the device's own
// suite would mix curves as soon as a peer were moved to a suite naming a
// different one.
//
// An empty result is not an error: a device may be given peers before it is
// given a private key, and a peer may exist before its static key is known.
// The handshake refuses to run on an empty secret, which is where that is
// caught.
//
// Must be called with staticIdentity held, at least for reading.
func (device *Device) staticStatic(kex suite.KEX, remoteStatic NoisePublicKey) ([]byte, error) {
	if kex == nil {
		return nil, errNoSuite
	}
	if device.staticIdentity.privateKey.IsZero() || remoteStatic.IsZero() {
		return nil, nil
	}
	return device.staticIdentity.privateKey.sharedSecret(kex, remoteStatic)
}

// SetSuite pins the suite a peer initiates with, which is how an orchestrator
// sequences a migration: it moves peers onto the new suite one at a time, while
// the device continues to accept both.
//
// Moving a peer also recomputes its static-static shared secret, because that
// secret is computed with the peer's key exchange. It comes out unchanged
// whenever the new suite names the same key exchange, which is every case this
// build can currently reach, but relying on that would leave the value silently
// stale the moment a second curve is registered.
//
// A suite whose key exchange is not this device's identity's is refused here
// rather than failing later in a handshake. See errStaticIdentityKEX.
func (peer *Peer) SetSuite(s *suite.Suite) error {
	if s == nil {
		return fmt.Errorf("peer %v: %w", peer, errNoSuite)
	}
	layout, err := wire.LayoutFor(s)
	if err != nil {
		return fmt.Errorf("peer %v: %w", peer, err)
	}

	device := peer.device

	/* Locks are taken static identity, then handshake, then suite. That is the
	 * order CreateMessageInitiation takes them in, holding the handshake while
	 * it reads the peer's suite, so taking the suite first here would invert
	 * it. */
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	if err := device.staticIdentityUsableWith(s.KEX); err != nil {
		return fmt.Errorf("peer %v cannot use suite %q: %w", peer, s.Name(), err)
	}

	peer.handshake.mutex.Lock()
	defer peer.handshake.mutex.Unlock()

	/* Computed before anything is stored, so a peer is never left holding a
	 * new suite with the previous suite's shared secret. */
	ss, err := device.staticStatic(s.KEX, peer.handshake.remoteStatic)
	if err != nil {
		return fmt.Errorf("peer %v cannot use suite %q: %w", peer, s.Name(), err)
	}

	peer.suiteMu.Lock()
	peer.suite = s
	peer.layout = layout
	peer.suiteMu.Unlock()

	peer.handshake.precomputedStaticStatic = ss
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
