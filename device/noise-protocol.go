/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/suite"
	"hash"
	"sync"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"

	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/wire"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_SECP256R1_AesGcm_SHA256"
	WGIdentifier      = "WolfGuard v1 info@wolfssl.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 246                                               // size of handshake initiation message
	MessageResponseSize        = 157                                               // size of response message
	MessageTransportHeaderSize = 16                                                // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + MinTransportOverhead // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                              // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                             // size of largest handshake related message
)

/* The transport phase takes its cipher from the session's suite, so the tag
 * and nonce lengths are the AEAD's rather than AES-GCM's. Buffer bounds and the
 * pre-authentication length gate still have to be constants, because they size
 * allocations and run before the packet's keypair is known, so they are bounds
 * on what any suite may use and BeginSymmetricSession refuses a suite outside
 * them.
 *
 * Every AEAD in the registries has a 16 byte tag today, so the two overhead
 * bounds are equal. They are separate names because they are separate
 * quantities: the minimum sizes the smallest legal transport message, the
 * maximum reduces how much content fits in a datagram. A new AEAD with a
 * different tag changes one of them and the compiler finds the places that
 * care. */
const (
	// TransportNonceCounterOffset is where the 64-bit packet counter sits in
	// the transport nonce. The rest of the nonce is zero.
	//
	// One rule covers both nonce lengths in use: at 12 bytes the counter fills
	// the nonce from offset 4, which is stock WireGuard's layout, and at 16 it
	// leaves four trailing zero bytes, which is what deployed wolfGuard sends.
	TransportNonceCounterOffset = 4

	// MinTransportNonceSize is the shortest nonce the counter fits in.
	MinTransportNonceSize = TransportNonceCounterOffset + 8
	// MaxTransportNonceSize bounds the per-worker nonce buffer.
	MaxTransportNonceSize = 16

	// MinTransportOverhead is the smallest authentication tag a suite's AEAD
	// may carry, and so fixes the smallest legal transport message.
	MinTransportOverhead = 16
	// MaxTransportOverhead is the largest, and so fixes how much content a
	// datagram can carry.
	MaxTransportOverhead = 16
)

/* checkTransportAEAD refuses an AEAD the transport buffers cannot describe.
 *
 * It runs once per session rather than per packet. Without it a suite outside
 * these bounds would either overrun a buffer sized from the constants or, in
 * the case of a nonce shorter than the counter, panic in a data-path worker. */
func checkTransportAEAD(name []byte, a cipher.AEAD) error {
	if n := a.Overhead(); n < MinTransportOverhead || n > MaxTransportOverhead {
		return fmt.Errorf("suite %q has a %d byte aead tag, this build is built for %d to %d: %w",
			name, n, MinTransportOverhead, MaxTransportOverhead, errKeySize)
	}
	if n := a.NonceSize(); n < MinTransportNonceSize || n > MaxTransportNonceSize {
		return fmt.Errorf("suite %q has a %d byte aead nonce, this build is built for %d to %d: %w",
			name, n, MinTransportNonceSize, MaxTransportNonceSize, errKeySize)
	}
	return nil
}

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

// MessageInitiation and MessageResponse are the two handshake messages. Every
// field is a slice whose length comes from the suite's layout, because the
// lengths are suite properties: a suite naming SHA-384 has 48-byte MACs, and one
// naming P-384 a 97-byte ephemeral. A fixed-size array cannot hold either, which
// is why encoding/binary cannot marshal these messages any more.
//
// They are aliases for the wire package's types rather than separate structs
// with a conversion. The conversion existed only while these fields were fixed
// arrays; keeping two identical shapes would mean copying every field into the
// codec and back out for no gain.
// MessageCookieReply is framed from a suite too, since its nonce and tag are
// its AEAD's. It is the one handshake-related message whose length does not
// identify the suite that framed it, and the one that does not need to: it
// names the index its recipient chose, so the recipient reaches the suite
// through the peer rather than through the packet.
type (
	MessageInitiation  = wire.Initiation
	MessageResponse    = wire.Response
	MessageCookieReply = wire.CookieReply
)

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      []byte            // transcript hash, the suite's hash length
	chainKey                  []byte            // chain key, the suite's hash length
	presharedKey              NoisePresharedKey // psk
	localEphemeral            NoisePrivateKey   // ephemeral secret key
	localIndex                uint32            // used to clear hash-table
	remoteIndex               uint32            // index for sending
	remoteStatic              NoisePublicKey    // long term key
	remoteEphemeral           NoisePublicKey    // ephemeral public key
	precomputedStaticStatic   []byte            // precomputed shared secret
	suite                     *suite.Suite      // the suite this handshake runs under
	layout                    wire.Layout       // suite's message layout, cached with it
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

func mixKey(newHMAC hmacFunc, dst, c, data []byte) error {
	return KDF1(newHMAC, dst, c, data)
}

/* mixHash hashes h||data with the suite's hash rather than a hardcoded one, so
 * a suite naming SHA-384 mixes with SHA-384. */
func mixHash(newHash func() hash.Hash, dst, h, data []byte) error {
	hh := newHash()
	if _, err := hh.Write(h); err != nil {
		return fmt.Errorf("mixHash: %w", err)
	}
	if _, err := hh.Write(data); err != nil {
		return fmt.Errorf("mixHash: %w", err)
	}
	out := hh.Sum(nil)
	if len(out) < len(dst) {
		return fmt.Errorf("mixHash produced %d bytes, need %d: %w", len(out), len(dst), errKeySize)
	}
	copy(dst, out)
	return nil
}

func (h *Handshake) Clear() {
	h.localEphemeral.clear()
	h.remoteEphemeral.clear()
	setZero(h.chainKey)
	setZero(h.hash)
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) error {
	newHash := h.newHash()
	if newHash == nil {
		return errNoSuite
	}
	return mixHash(newHash, h.hash[:], h.hash[:], data)
}

func (h *Handshake) mixKey(data []byte) error {
	newHMAC := h.newHMAC()
	if newHMAC == nil {
		return errNoSuite
	}
	return mixKey(newHMAC, h.chainKey[:], h.chainKey[:], data)
}

/* init runs the FIPS module's power-on self tests, before any key material
 * exists.
 *
 * It computes nothing else. The initial chaining key and transcript hash used
 * to be package globals hashed here with SHA-256; they are now a property of
 * each suite, derived once when the suite is accepted, and no suite exists at
 * package init. suites_test.go recomputes the legacy pair from the compiled-in
 * constants and checks the suite against it, which is what keeps this build
 * able to talk to deployed peers.
 */
func init() {
	wolfSSL.Wc_SetDefaultSeed_Cb()
	wolfSSL.Wc_RunAllCast_fips()
}

// CreateMessageInitiation builds an initiation under the peer's suite.
//
// Every length here is the suite's: the transcript and chaining key are its
// hash length, the AEAD key its key length, the MAC fields its layout's. The
// encrypted fields are whatever the AEAD returns rather than being copied into
// a field of a size decided at compile time.
//
// The errors from mixing and key derivation are checked rather than discarded.
// They were unreachable while every length was a constant; now a length
// mismatch between a suite and its layout surfaces here, and a derivation that
// silently failed would leave a zero key.
func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	peerSuite, layout := peer.suiteFor()
	if err := handshake.setSuite(peerSuite); err != nil {
		return nil, err
	}
	if err := handshake.beginTranscript(); err != nil {
		return nil, err
	}

	// create ephemeral key
	kex := peerSuite.KEX
	var err error
	handshake.localEphemeral, err = newPrivateKey(kex)
	if err != nil {
		return nil, err
	}

	if err := handshake.mixHash(handshake.remoteStatic.Bytes()); err != nil {
		return nil, err
	}

	ephemeral, err := handshake.localEphemeral.publicKey(kex)
	if err != nil {
		return nil, err
	}
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: bytes.Clone(ephemeral.Bytes()),
		MAC1:      make([]byte, layout.MACSize),
		MAC2:      make([]byte, layout.MACSize),
	}

	if err := handshake.mixKey(msg.Ephemeral); err != nil {
		return nil, err
	}
	if err := handshake.mixHash(msg.Ephemeral); err != nil {
		return nil, err
	}

	// encrypt static key
	ss, err := handshake.localEphemeral.sharedSecret(kex, handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	key := make([]byte, peerSuite.AEADKeySize)
	defer setZero(key)
	if err := KDF2(
		peerSuite.NewHMAC,
		handshake.chainKey,
		key,
		handshake.chainKey,
		ss,
	); err != nil {
		return nil, err
	}

	msg.Static, err = aeadSeal(peerSuite, key, device.staticIdentity.publicKey.Bytes(), handshake.hash)
	if err != nil {
		return nil, err
	}
	if err := handshake.mixHash(msg.Static); err != nil {
		return nil, err
	}

	// encrypt timestamp
	if isZero(handshake.precomputedStaticStatic) {
		return nil, errInvalidPublicKey
	}
	if err := KDF2(
		peerSuite.NewHMAC,
		handshake.chainKey,
		key,
		handshake.chainKey,
		handshake.precomputedStaticStatic,
	); err != nil {
		return nil, err
	}
	timestamp := tai64n.Now()
	msg.Timestamp, err = aeadSeal(peerSuite, key, timestamp[:], handshake.hash)
	if err != nil {
		return nil, err
	}

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	if err := handshake.mixHash(msg.Timestamp); err != nil {
		return nil, err
	}
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

// ConsumeMessageInitiation validates an initiation received under suite s and
// returns the peer it came from.
//
// The suite is a parameter rather than the device's own because a responder
// mid-migration accepts more than one, and which suite this packet used was
// already settled when the receive path chose a layout to parse it with. Using
// the device's local suite here would decode every peer's handshake with it,
// which is correct only while exactly one suite is accepted.
//
// The handshake is left running under s, not under whatever suite the peer is
// pinned to for initiating. A peer part-way through a migration may still
// initiate with the old suite, and the response has to answer in the suite the
// initiation was sent in.
func (device *Device) ConsumeMessageInitiation(s *suite.Suite, msg *MessageInitiation) *Peer {
	if s == nil || msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	/* The transcript starts at the suite's precomputed initial state and is the
	 * suite's hash length throughout. Both are scratch: they are zeroed on
	 * every exit, so what the handshake keeps has to be a copy. */
	hash := bytes.Clone(s.State.Hash)
	chainKey := bytes.Clone(s.State.ChainKey)
	key := make([]byte, s.AEADKeySize)
	defer func() {
		setZero(hash)
		setZero(chainKey)
		setZero(key)
	}()

	if err := mixHash(s.NewHash, hash, hash, device.staticIdentity.publicKey.Bytes()); err != nil {
		return nil
	}
	if err := mixHash(s.NewHash, hash, hash, msg.Ephemeral); err != nil {
		return nil
	}
	if err := mixKey(s.NewHMAC, chainKey, chainKey, msg.Ephemeral); err != nil {
		return nil
	}

	// decrypt static key
	var peerPK NoisePublicKey
	var msgEphemeralKey NoisePublicKey
	if err := msgEphemeralKey.SetBytes(msg.Ephemeral); err != nil {
		return nil
	}
	ss, err := device.staticIdentity.privateKey.sharedSecret(s.KEX, msgEphemeralKey)
	if err != nil {
		return nil
	}
	if err := KDF2(s.NewHMAC, chainKey, key, chainKey, ss); err != nil {
		return nil
	}
	/* The decrypted static key's length comes from the plaintext the sender
	 * encrypted, so it is whatever the AEAD returns rather than a constant. */
	peerPKBuf, err := aeadOpen(s, key, msg.Static, hash)
	if err != nil {
		return nil
	}
	if err := peerPK.SetBytes(peerPKBuf); err != nil {
		return nil
	}
	if err := mixHash(s.NewHash, hash, hash, msg.Static); err != nil {
		return nil
	}

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic) {
		handshake.mutex.RUnlock()
		return nil
	}
	if err := KDF2(
		s.NewHMAC,
		chainKey,
		key,
		chainKey,
		handshake.precomputedStaticStatic,
	); err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	plainTimestamp, err := aeadOpen(s, key, msg.Timestamp, hash)
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	if len(plainTimestamp) != len(timestamp) {
		handshake.mutex.RUnlock()
		return nil
	}
	copy(timestamp[:], plainTimestamp)
	if err := mixHash(s.NewHash, hash, hash, msg.Timestamp); err != nil {
		handshake.mutex.RUnlock()
		return nil
	}

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if err := handshake.setSuite(s); err != nil {
		return nil
	}
	/* Copies, not the scratch slices: those are zeroed on the way out. */
	handshake.hash = bytes.Clone(hash)
	handshake.chainKey = bytes.Clone(chainKey)
	handshake.remoteIndex = msg.Sender
	if err := handshake.remoteEphemeral.SetBytes(msg.Ephemeral); err != nil {
		return nil
	}
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	/* The suite comes from the handshake, not from the peer. The handshake is
	 * running under whatever suite the initiation arrived in, which during a
	 * migration need not be the one this peer is pinned to for initiating, and
	 * answering in a different suite than the question was asked in would
	 * derive a transcript the initiator cannot reproduce. */
	peerSuite := handshake.suite
	if peerSuite == nil {
		return nil, errNoSuite
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex
	msg.MAC1 = make([]byte, handshake.layout.MACSize)
	msg.MAC2 = make([]byte, handshake.layout.MACSize)

	// create ephemeral key

	kex := peerSuite.KEX
	handshake.localEphemeral, err = newPrivateKey(kex)
	if err != nil {
		return nil, err
	}
	respEphemeral, err := handshake.localEphemeral.publicKey(kex)
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = bytes.Clone(respEphemeral.Bytes())
	if err := handshake.mixHash(msg.Ephemeral); err != nil {
		return nil, err
	}
	if err := handshake.mixKey(msg.Ephemeral); err != nil {
		return nil, err
	}

	ss, err := handshake.localEphemeral.sharedSecret(kex, handshake.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	if err := handshake.mixKey(ss); err != nil {
		return nil, err
	}
	ss, err = handshake.localEphemeral.sharedSecret(kex, handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	if err := handshake.mixKey(ss); err != nil {
		return nil, err
	}

	// add preshared key

	/* tau is mixed into the transcript, so it is the suite's hash length, which
	 * is the length the chaining key already carries. */
	tau := make([]byte, len(handshake.chainKey))
	key := make([]byte, peerSuite.AEADKeySize)
	defer func() {
		setZero(tau)
		setZero(key)
	}()

	if err := KDF3(
		peerSuite.NewHMAC,
		handshake.chainKey,
		tau,
		key,
		handshake.chainKey,
		handshake.presharedKey[:],
	); err != nil {
		return nil, err
	}

	if err := handshake.mixHash(tau); err != nil {
		return nil, err
	}

	msg.Empty, err = aeadSeal(peerSuite, key, nil, handshake.hash)
	if err != nil {
		return nil, err
	}

	if err := handshake.mixHash(msg.Empty); err != nil {
		return nil, err
	}

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

// ConsumeMessageResponse validates a response received under suite s.
//
// s must be the suite the matching handshake is running under. The responder
// answers in the suite the initiation was sent in, so a response that decoded
// under some other accepted suite's layout is not an answer to this handshake
// and is dropped rather than mixed into its transcript.
func (device *Device) ConsumeMessageResponse(s *suite.Suite, msg *MessageResponse) *Peer {
	if s == nil || msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var hash, chainKey []byte
	defer func() {
		setZero(hash)
		setZero(chainKey)
	}()

	ok := func() bool {
		/* The identity is taken before the handshake, which is the order every
		 * other path in this package uses and the order this one inverted.
		 * SetPrivateKey holds the identity for writing and then takes each
		 * peer's handshake for writing, through ExpireCurrentKeypairs; holding
		 * a handshake here while waiting for the identity closed the cycle, so
		 * a rekey arriving beside an inbound response hung the device. Nothing
		 * is saved by taking it later: the two checks below are a state
		 * comparison and a pointer comparison. */
		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}
		if handshake.suite != s {
			return false
		}

		// finish 3-way DH

		hash = make([]byte, len(handshake.hash))
		chainKey = make([]byte, len(handshake.chainKey))

		if err := mixHash(s.NewHash, hash, handshake.hash, msg.Ephemeral); err != nil {
			return false
		}
		if err := mixKey(s.NewHMAC, chainKey, handshake.chainKey, msg.Ephemeral); err != nil {
			return false
		}

		var msgEphemeralKey NoisePublicKey
		if err := msgEphemeralKey.SetBytes(msg.Ephemeral); err != nil {
			return false
		}

		ss, err := handshake.localEphemeral.sharedSecret(s.KEX, msgEphemeralKey)
		if err != nil {
			return false
		}
		err = mixKey(s.NewHMAC, chainKey, chainKey, ss)
		setZero(ss)
		if err != nil {
			return false
		}

		ss, err = device.staticIdentity.privateKey.sharedSecret(s.KEX, msgEphemeralKey)
		if err != nil {
			return false
		}
		err = mixKey(s.NewHMAC, chainKey, chainKey, ss)
		setZero(ss)
		if err != nil {
			return false
		}

		// add preshared key (psk)

		tau := make([]byte, len(chainKey))
		key := make([]byte, s.AEADKeySize)
		defer func() {
			setZero(tau)
			setZero(key)
		}()

		if err := KDF3(
			s.NewHMAC,
			chainKey,
			tau,
			key,
			chainKey,
			handshake.presharedKey[:],
		); err != nil {
			return false
		}
		if err := mixHash(s.NewHash, hash, hash, tau); err != nil {
			return false
		}

		// authenticate transcript

		/* Resealing and comparing is how this build authenticates the empty
		 * field. The tag length is the AEAD's, so the comparison is against
		 * whatever the suite produced rather than a fixed-size buffer. */
		sealedEmpty, err := aeadSeal(s, key, nil, hash)
		if err != nil {
			return false
		}
		if !bytes.Equal(sealedEmpty, msg.Empty) {
			return false
		}
		return mixHash(s.NewHash, hash, hash, msg.Empty) == nil
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	/* Copies: the scratch is zeroed on the way out. */
	handshake.hash = bytes.Clone(hash)
	handshake.chainKey = bytes.Clone(chainKey)
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	/* The session keys come out of this handshake's transcript, so they are
	 * derived with this handshake's suite rather than the peer's configured
	 * one, which during a migration can be a different suite. */
	peerSuite := handshake.suite
	if peerSuite == nil {
		return errNoSuite
	}

	// derive keys

	keypair := new(Keypair)

	var isInitiator bool
	sendKey := make([]byte, peerSuite.AEADKeySize)
	recvKey := make([]byte, peerSuite.AEADKeySize)
	defer func() {
		setZero(sendKey)
		setZero(recvKey)
	}()

	if handshake.state == handshakeResponseConsumed {
		if err := KDF2(
			peerSuite.NewHMAC,
			sendKey,
			recvKey,
			handshake.chainKey,
			nil,
		); err != nil {
			return err
		}
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		if err := KDF2(
			peerSuite.NewHMAC,
			recvKey,
			sendKey,
			handshake.chainKey,
			nil,
		); err != nil {
			return err
		}
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey)
	setZero(handshake.hash) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	handshake.localEphemeral.clear()
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	/* Built here, once, from the suite the handshake ran under, so the data
	 * phase uses the cipher its name declares. The AEADs own copies of the key
	 * material, which is why the two buffers can be zeroed on the way out. */
	var err error
	if keypair.send, err = peerSuite.NewAEAD(sendKey); err != nil {
		return fmt.Errorf("constructing the transport send cipher: %w", err)
	}
	if keypair.receive, err = peerSuite.NewAEAD(recvKey); err != nil {
		return fmt.Errorf("constructing the transport receive cipher: %w", err)
	}
	if err := checkTransportAEAD(peerSuite.Name(), keypair.send); err != nil {
		return err
	}

	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next.Load()
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.next.Store(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.next.Store(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.next.Load() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.next.Load()
	keypairs.next.Store(nil)
	return true
}
