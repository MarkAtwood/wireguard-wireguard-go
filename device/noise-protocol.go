/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"errors"
	"fmt"
	"golang.zx2c4.com/wireguard/suite"
	"hash"
	"sync"
	"time"

	wolfSSL "github.com/wolfssl/go-wolfssl"

	"golang.zx2c4.com/wireguard/tai64n"
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
	MessageInitiationSize      = 246                                                 // size of handshake initiation message
	MessageResponseSize        = 157                                                 // size of response message
	MessageCookieReplySize     = 72                                                  // size of cookie reply message
	MessageTransportHeaderSize = 16                                                  // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + wolfSSL.AES_BLOCK_SIZE // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                                // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                               // size of largest handshake related message
)

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

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral [NoisePublicKeySize]byte
	Static    [NoisePublicKeySize + wolfSSL.AES_BLOCK_SIZE]byte
	Timestamp [tai64n.TimestampSize + wolfSSL.AES_BLOCK_SIZE]byte
	MAC1      [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	MAC2      [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral [NoisePublicKeySize]byte
	Empty     [wolfSSL.AES_BLOCK_SIZE]byte
	MAC1      [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	MAC2      [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [wolfSSL.AES_IV_SIZE]byte
	Cookie   [wolfSSL.WC_SHA256_DIGEST_SIZE + wolfSSL.AES_BLOCK_SIZE]byte
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [wolfSSL.WC_SHA256_DIGEST_SIZE]byte // hash value
	chainKey                  [wolfSSL.WC_SHA256_DIGEST_SIZE]byte // chain key
	presharedKey              NoisePresharedKey                   // psk
	localEphemeral            NoisePrivateKey                     // ephemeral secret key
	localIndex                uint32                              // used to clear hash-table
	remoteIndex               uint32                              // index for sending
	remoteStatic              NoisePublicKey                      // long term key
	remoteEphemeral           NoisePublicKey                      // ephemeral public key
	precomputedStaticStatic   []byte                              // precomputed shared secret
	suite                     *suite.Suite                        // the suite this handshake runs under
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	InitialHash     [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	ZeroNonce       [wolfSSL.AES_IV_SIZE]byte
)

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
	setZero(h.chainKey[:])
	setZero(h.hash[:])
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

/* Do basic precomputations
 */
func init() {
	wolfSSL.Wc_SetDefaultSeed_Cb()
	wolfSSL.Wc_RunAllCast_fips()

	var sha wolfSSL.Wc_Sha256
	wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_Sha256Update(&sha, []byte(NoiseConstruction), len([]byte(NoiseConstruction)))
	wolfSSL.Wc_Sha256Final(&sha, InitialChainKey[:])
	wolfSSL.Wc_Sha256Free(&sha)

	/* The legacy globals are computed here with wolfCrypt directly: no suite
	 * exists at package init. A device takes its initial state from its
	 * suite instead, and suites_test.go asserts the two agree. */
	var h2 wolfSSL.Wc_Sha256
	wolfSSL.Wc_InitSha256_ex(&h2, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_Sha256Update(&h2, InitialChainKey[:], len(InitialChainKey))
	wolfSSL.Wc_Sha256Update(&h2, []byte(WGIdentifier), len(WGIdentifier))
	wolfSSL.Wc_Sha256Final(&h2, InitialHash[:])
	wolfSSL.Wc_Sha256Free(&h2)
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	peerSuite, _ := peer.suiteFor()
	handshake.setSuite(peerSuite)
	kex := peer.kex()
	handshake.localEphemeral, err = newPrivateKey(kex)
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic.Bytes())

	ephemeral, err := handshake.localEphemeral.publicKey(kex)
	if err != nil {
		return nil, err
	}
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: ephemeral.wireArray(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key
	ss, err := handshake.localEphemeral.sharedSecret(kex, handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	KDF2(
		peerSuite.NewHMAC,
		handshake.chainKey[:],
		key[:],
		handshake.chainKey[:],
		ss[:],
	)

	if sealed, err := aeadSeal(peerSuite, key[:], device.staticIdentity.publicKey.Bytes(), handshake.hash[:]); err != nil {
		return nil, err
	} else {
		copy(msg.Static[:], sealed)
	}
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(
		peerSuite.NewHMAC,
		handshake.chainKey[:],
		key[:],
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	timestamp := tai64n.Now()
	if sealed, err := aeadSeal(peerSuite, key[:], timestamp[:], handshake.hash[:]); err != nil {
		return nil, err
	} else {
		copy(msg.Timestamp[:], sealed)
	}

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	deviceSuite, _ := device.localSuite()
	if deviceSuite == nil {
		return nil
	}
	var (
		hash     [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
		chainKey [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(deviceSuite.NewHash, hash[:], InitialHash[:], device.staticIdentity.publicKey.Bytes())
	mixHash(deviceSuite.NewHash, hash[:], hash[:], msg.Ephemeral[:])
	mixKey(deviceSuite.NewHMAC, chainKey[:], InitialChainKey[:], msg.Ephemeral[:])

	// decrypt static key
	var peerPK NoisePublicKey
	var key [wolfSSL.AES_256_KEY_SIZE]byte
	msgEphemeralKey, err := publicKeyFromWire(msg.Ephemeral)
	if err != nil {
		return nil
	}
	ss, err := device.staticIdentity.privateKey.sharedSecret(device.kex(), msgEphemeralKey)
	if err != nil {
		return nil
	}
	KDF2(deviceSuite.NewHMAC, chainKey[:], key[:], chainKey[:], ss[:])
	/* The decrypted static key's length comes from the plaintext the sender
	 * encrypted, so it is whatever the AEAD returns rather than a constant. */
	peerPKBuf, err := aeadOpen(deviceSuite, key[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	if err := peerPK.SetBytes(peerPKBuf); err != nil {
		return nil
	}
	mixHash(deviceSuite.NewHash, hash[:], hash[:], msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
		deviceSuite.NewHMAC,
		chainKey[:],
		key[:],
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	plainTimestamp, openErr := aeadOpen(deviceSuite, key[:], msg.Timestamp[:], hash[:])
	if openErr == nil {
		copy(timestamp[:], plainTimestamp)
	}
	ret := 0
	if openErr != nil {
		ret = -1
	}
	if ret < 0 {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(deviceSuite.NewHash, hash[:], hash[:], msg.Timestamp[:])

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

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	if err := handshake.remoteEphemeral.SetBytes(msg.Ephemeral[:]); err != nil {
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

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

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

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	peerSuite, _ := peer.suiteFor()
	handshake.setSuite(peerSuite)
	kex := peer.kex()
	handshake.localEphemeral, err = newPrivateKey(kex)
	if err != nil {
		return nil, err
	}
	respEphemeral, err := handshake.localEphemeral.publicKey(kex)
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = respEphemeral.wireArray()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	ss, err := handshake.localEphemeral.sharedSecret(kex, handshake.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])
	ss, err = handshake.localEphemeral.sharedSecret(kex, handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])

	// add preshared key

	var tau [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	var key [wolfSSL.AES_256_KEY_SIZE]byte

	KDF3(
		peerSuite.NewHMAC,
		handshake.chainKey[:],
		tau[:],
		key[:],
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	if sealed, err := aeadSeal(peerSuite, key[:], nil, handshake.hash[:]); err != nil {
		return nil, err
	} else {
		copy(msg.Empty[:], sealed)
	}

	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	deviceSuite, _ := device.localSuite()
	if deviceSuite == nil {
		return nil
	}
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
		chainKey [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
	)

	ok := func() bool {
		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

		mixHash(deviceSuite.NewHash, hash[:], handshake.hash[:], msg.Ephemeral[:])
		mixKey(deviceSuite.NewHMAC, chainKey[:], handshake.chainKey[:], msg.Ephemeral[:])

		msgEphemeralKey, err := publicKeyFromWire(msg.Ephemeral)
		if err != nil {
			return false
		}

		ss, err := handshake.localEphemeral.sharedSecret(lookup.peer.kex(), msgEphemeralKey)
		if err != nil {
			return false
		}
		mixKey(deviceSuite.NewHMAC, chainKey[:], chainKey[:], ss[:])
		setZero(ss[:])

		ss, err = device.staticIdentity.privateKey.sharedSecret(lookup.peer.kex(), msgEphemeralKey)
		if err != nil {
			return false
		}
		mixKey(deviceSuite.NewHMAC, chainKey[:], chainKey[:], ss[:])
		setZero(ss[:])

		// add preshared key (psk)

		var tau [wolfSSL.WC_SHA256_DIGEST_SIZE]byte
		var key [wolfSSL.AES_256_KEY_SIZE]byte
		KDF3(
			deviceSuite.NewHMAC,
			chainKey[:],
			tau[:],
			key[:],
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(deviceSuite.NewHash, hash[:], hash[:], tau[:])

		// authenticate transcript

		var authTag [wolfSSL.AES_BLOCK_SIZE]byte
		sealedEmpty, err := aeadSeal(deviceSuite, key[:], nil, hash[:])
		if err != nil {
			return false
		}
		copy(authTag[:], sealedEmpty)

		if !bytes.Equal(authTag[:], msg.Empty[:]) {
			return false
		}
		mixHash(deviceSuite.NewHash, hash[:], hash[:], msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	peerSuite, _ := peer.suiteFor()
	if peerSuite == nil {
		return errNoSuite
	}
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [wolfSSL.AES_256_KEY_SIZE]byte
	var recvKey [wolfSSL.AES_256_KEY_SIZE]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
			peerSuite.NewHMAC,
			sendKey[:],
			recvKey[:],
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
			peerSuite.NewHMAC,
			recvKey[:],
			sendKey[:],
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	handshake.localEphemeral.clear()
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send = sendKey
	keypair.receive = recvKey

	setZero(sendKey[:])
	setZero(recvKey[:])

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
