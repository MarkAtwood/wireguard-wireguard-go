/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/wire"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

/* The mac1 and mac2 keys, the MAC algorithm and the length of the mac1 and mac2
 * fields all come from the suite in force for the packet being handled. None of
 * it can be hardcoded: the fields are hash-sized, so a suite naming SHA-384 has
 * 48-byte fields, and every offset here is measured from the end of the packet.
 *
 * Hardcoding SHA-256 was not merely inflexible. The generator and the checker
 * were wrong in the same way, so they agreed with each other, and a SHA-384
 * handshake would have appeared to succeed while mac1 was written across the
 * mac1/mac2 field boundary. That symmetry is what made the bug invisible.
 */

// cookieSecretSize is the length of the responder's rotating cookie secret. It
// keys a MAC, so it is a parameter of its own and follows neither the cookie's
// length nor any suite.
const cookieSecretSize = 32

// errCookieUninitialized is reported when cookie state is used before Init has
// given it a static public key.
var errCookieUninitialized = errors.New("cookie state has no public key")

// cookieKeys are the quantities the cookie mechanism derives from one static
// public key under one suite.
//
// They are immutable once derived, so a caller that takes a reference under the
// lock may use it after releasing the lock.
type cookieKeys struct {
	// mac1 keys the MAC over a handshake message up to its mac1 field. HMAC
	// accepts a key of any length, so this is the whole digest.
	mac1 []byte
	// encryption keys the AEAD that wraps a cookie in a reply.
	encryption []byte
	// macSize is the length of the mac1 and mac2 fields. It is the suite's
	// hash size, which is the quantity wire.Layout.MACSize is derived from, so
	// offsets computed from it land on the fields the wire codec encoded.
	macSize int
}

// cookieKeyCache holds the keys derived from one static public key, per suite.
//
// A device may speak several suites, each naming its own hash, so a single
// fixed-size key will not do. Keys are cached under the suite's handshake name,
// which is what distinguishes one set of primitives from another.
//
// The cache does no locking of its own. It lives inside a CookieChecker or a
// CookieGenerator and is guarded by that value's lock, the same lock that
// guards the cookie state beside it. Sharing the lock is what makes a reset
// serialize against a derivation: keys derived from a public key that Init has
// since replaced must never reach a caller.
type cookieKeyCache struct {
	pk      NoisePublicKey
	bySuite map[string]*cookieKeys
}

// reset points the cache at a new static public key and drops everything
// derived from the previous one.
func (c *cookieKeyCache) reset(pk NoisePublicKey) {
	c.pk = pk
	c.bySuite = make(map[string]*cookieKeys)
}

// lookup returns the keys already derived for s, or nil.
func (c *cookieKeyCache) lookup(s *suite.Suite) *cookieKeys {
	return c.bySuite[string(s.Name())]
}

// derive computes and caches the keys for s.
func (c *cookieKeyCache) derive(s *suite.Suite) (*cookieKeys, error) {
	if c.bySuite == nil {
		return nil, errCookieUninitialized
	}
	if s.AEADKeySize <= 0 {
		return nil, fmt.Errorf("the suite's aead key length is %d: %w", s.AEADKeySize, errKeySize)
	}

	macSize := s.NewHash().Size()
	if macSize <= 0 {
		return nil, fmt.Errorf("the suite's hash is %d bytes: %w", macSize, errKeySize)
	}

	mac1Key, err := cookieLabelHash(s, WGLabelMAC1, c.pk)
	if err != nil {
		return nil, err
	}

	cookieKey, err := cookieLabelHash(s, WGLabelCookie, c.pk)
	if err != nil {
		return nil, err
	}
	// The cookie encryption key is the digest cut to the AEAD's key length,
	// because it is handed to the AEAD as that key. For a 32-byte digest and
	// AES-256 that is the whole digest; for SHA-384 it is the first 32 of 48.
	// A digest shorter than the key is rejected rather than stretched, since
	// stretching would invent key material the name does not describe.
	if len(cookieKey) < s.AEADKeySize {
		return nil, fmt.Errorf("the suite's hash gives %d bytes, its aead key is %d: %w",
			len(cookieKey), s.AEADKeySize, errKeySize)
	}

	k := &cookieKeys{
		mac1:       mac1Key,
		encryption: cookieKey[:s.AEADKeySize],
		macSize:    macSize,
	}
	c.bySuite[string(s.Name())] = k
	return k, nil
}

// cookieLabelHash is H_s(label || pk), the shape both cookie keys take.
//
// It hashes with the suite's own hash rather than calling wolfCrypt, so a build
// without SHA-256 compiled in still derives the keys its suites name.
func cookieLabelHash(s *suite.Suite, label string, pk NoisePublicKey) ([]byte, error) {
	h := s.NewHash()
	if _, err := h.Write([]byte(label)); err != nil {
		return nil, fmt.Errorf("hashing the %q label: %w", label, err)
	}
	if _, err := h.Write(pk.Bytes()); err != nil {
		return nil, fmt.Errorf("hashing the static key under %q: %w", label, err)
	}
	return h.Sum(nil), nil
}

// suiteMAC computes the suite's keyed MAC over in.
func suiteMAC(s *suite.Suite, key, in []byte) ([]byte, error) {
	h, err := s.NewHMAC(key)
	if err != nil {
		return nil, fmt.Errorf("keying the cookie mac: %w", err)
	}
	if _, err := h.Write(in); err != nil {
		return nil, fmt.Errorf("updating the cookie mac: %w", err)
	}
	return h.Sum(nil), nil
}

// fieldMAC computes the MAC that fills a mac1 or mac2 field of size bytes.
//
// The length has to match the field rather than merely cover it. Every offset
// in this file comes from the suite's hash size, while NewHash and NewHMAC are
// independent fields of a Suite, so a registration whose MAC disagrees with its
// hash would have the MAC compared against, or written over, the wrong bytes.
func fieldMAC(s *suite.Suite, key, in []byte, size int) ([]byte, error) {
	mac, err := suiteMAC(s, key, in)
	if err != nil {
		return nil, err
	}
	if len(mac) != size {
		return nil, fmt.Errorf("the suite's mac is %d bytes, its mac fields are %d: %w",
			len(mac), size, errKeySize)
	}
	return mac, nil
}

// errShortForMACs reports a message that cannot hold the suite's two MAC
// fields. Offsets are measured back from the end of the packet, so this must be
// rejected before any of them are computed.
func errShortForMACs(msg []byte, macSize int) error {
	return fmt.Errorf("message is %d bytes, too short for two %d-byte mac fields: %w",
		len(msg), macSize, errKeySize)
}

type CookieChecker struct {
	sync.RWMutex
	keyCache cookieKeyCache
	mac2     struct {
		secret    [cookieSecretSize]byte
		secretSet time.Time
	}
}

type CookieGenerator struct {
	sync.RWMutex
	keyCache cookieKeyCache
	mac2     struct {
		cookie      [wire.CookieSize]byte
		cookieSet   time.Time
		hasLastMAC1 bool
		// lastMAC1 is hash-sized, so it is a slice rather than an array.
		lastMAC1 []byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	st.keyCache.reset(pk)
	st.mac2.secretSet = time.Time{}
}

// keys returns the keys for s, deriving them the first time s is seen.
//
// Lookup is the common path and takes only the read lock; the write lock is
// taken to derive, and the lookup is repeated under it because another
// goroutine may have derived the same suite's keys in between.
func (st *CookieChecker) keys(s *suite.Suite) (*cookieKeys, error) {
	if s == nil || s.NewHash == nil || s.NewHMAC == nil {
		return nil, errNoSuite
	}

	st.RLock()
	k := st.keyCache.lookup(s)
	st.RUnlock()
	if k != nil {
		return k, nil
	}

	st.Lock()
	defer st.Unlock()

	if k := st.keyCache.lookup(s); k != nil {
		return k, nil
	}
	return st.keyCache.derive(s)
}

// cookie computes the cookie bound to src under the current secret.
//
// The caller holds st's lock. The secret rotates, and a cookie computed partly
// before and partly after a rotation would verify against neither.
func (st *CookieChecker) cookie(s *suite.Suite, src []byte) ([]byte, error) {
	mac, err := suiteMAC(s, st.mac2.secret[:], src)
	if err != nil {
		return nil, err
	}
	if len(mac) < wire.CookieSize {
		return nil, fmt.Errorf("the suite's mac is %d bytes, the cookie is %d: %w",
			len(mac), wire.CookieSize, errKeySize)
	}
	return mac[:wire.CookieSize], nil
}

// CheckMAC1 holds no lock of its own. The mac1 key used to be mutable state of
// st, written by Init; it is now an immutable entry of the key cache, which
// keys took under the lock, and nothing else here reads st.
func (st *CookieChecker) CheckMAC1(s *suite.Suite, msg []byte) bool {
	keys, err := st.keys(s)
	if err != nil {
		return false
	}

	smac2 := len(msg) - keys.macSize
	smac1 := smac2 - keys.macSize
	if smac1 < 0 {
		return false
	}

	mac1, err := fieldMAC(s, keys.mac1, msg[:smac1], keys.macSize)
	if err != nil {
		return false
	}

	return wolfSSL.ConstantCompare(mac1, msg[smac1:smac2], keys.macSize) == 1
}

func (st *CookieChecker) CheckMAC2(s *suite.Suite, msg, src []byte) bool {
	keys, err := st.keys(s)
	if err != nil {
		return false
	}

	smac2 := len(msg) - keys.macSize
	if smac2 < keys.macSize {
		return false
	}

	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	cookie, err := st.cookie(s, src)
	if err != nil {
		return false
	}

	// calculate mac of packet (including mac1)

	mac2, err := fieldMAC(s, cookie, msg[:smac2], keys.macSize)
	if err != nil {
		return false
	}

	return wolfSSL.ConstantCompare(mac2, msg[smac2:], keys.macSize) == 1
}

func (st *CookieChecker) CreateReply(
	s *suite.Suite,
	msg []byte,
	recv uint32,
	src []byte,
) (*MessageCookieReply, error) {
	keys, err := st.keys(s)
	if err != nil {
		return nil, err
	}

	smac2 := len(msg) - keys.macSize
	smac1 := smac2 - keys.macSize
	if smac1 < 0 {
		return nil, errShortForMACs(msg, keys.macSize)
	}

	st.RLock()

	// refresh cookie secret

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
		var rng wolfSSL.WC_RNG
		wolfSSL.Wc_InitRng(&rng)
		ret := wolfSSL.Wc_RNG_GenerateBlock(&rng, st.mac2.secret[:], len(st.mac2.secret[:]))
		wolfSSL.Wc_FreeRng(&rng)
		if ret < 0 {
			st.Unlock()
			return nil, errors.New("RNG failed")
		}
		st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	defer st.RUnlock()

	// derive cookie

	cookie, err := st.cookie(s, src)
	if err != nil {
		return nil, err
	}

	// encrypt cookie

	/* Sealed with the suite's AEAD rather than a hardcoded AES-GCM, for the
	 * reason the handshake and the transport phase are: a suite that names a
	 * cipher has to be the cipher that runs. The nonce is the AEAD's own
	 * length, which is what makes a reply's size follow the suite. */
	aead, err := s.NewAEAD(keys.encryption)
	if err != nil {
		return nil, fmt.Errorf("constructing the cookie cipher: %w", err)
	}

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType
	reply.Receiver = recv
	reply.Nonce = make([]byte, aead.NonceSize())

	/* A fresh random nonce per reply. The key is derived from the responder's
	 * static public key, so it is the same for every reply this device ever
	 * sends, and the nonce is the only thing keeping those invocations apart. */
	var rng wolfSSL.WC_RNG
	wolfSSL.Wc_InitRng(&rng)
	ret := wolfSSL.Wc_RNG_GenerateBlock(&rng, reply.Nonce, len(reply.Nonce))
	wolfSSL.Wc_FreeRng(&rng)
	if ret < 0 {
		return nil, errors.New("RNG failed")
	}

	/* The additional data is the mac1 the responder saw, which binds the reply
	 * to the message that provoked it. */
	reply.Cookie = aead.Seal(nil, reply.Nonce, cookie, msg[smac1:smac2])

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	st.keyCache.reset(pk)
	st.mac2.cookieSet = time.Time{}
}

// keys returns the keys for s, deriving them the first time s is seen. It locks
// as CookieChecker.keys does.
func (st *CookieGenerator) keys(s *suite.Suite) (*cookieKeys, error) {
	if s == nil || s.NewHash == nil || s.NewHMAC == nil {
		return nil, errNoSuite
	}

	st.RLock()
	k := st.keyCache.lookup(s)
	st.RUnlock()
	if k != nil {
		return k, nil
	}

	st.Lock()
	defer st.Unlock()

	if k := st.keyCache.lookup(s); k != nil {
		return k, nil
	}
	return st.keyCache.derive(s)
}

func (st *CookieGenerator) ConsumeReply(s *suite.Suite, msg *MessageCookieReply) bool {
	keys, err := st.keys(s)
	if err != nil {
		return false
	}

	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	aead, err := s.NewAEAD(keys.encryption)
	if err != nil {
		return false
	}
	if len(msg.Nonce) != aead.NonceSize() {
		return false
	}

	/* An authentication failure and a reply framed under the wrong suite are
	 * both just a dropped reply: the initiator retries without a cookie and the
	 * responder issues another. */
	cookie, err := aead.Open(nil, msg.Nonce, msg.Cookie, st.mac2.lastMAC1)
	if err != nil {
		return false
	}
	if len(cookie) != wire.CookieSize {
		return false
	}

	st.mac2.cookieSet = time.Now()
	copy(st.mac2.cookie[:], cookie)
	return true
}

// AddMacs fills the mac1 and mac2 fields at the end of an encoded handshake
// message, under the suite that message was framed with.
//
// mac2 is left zero unless this generator holds a current cookie, which is the
// ordinary case: a responder only issues one under load.
//
// On error msg may already have been partly written, so a caller must discard
// the message rather than send it. mac2 covers mac1, so mac1 has to be in the
// buffer before mac2 can be computed over it, and making the write atomic would
// mean staging a copy of the field or restoring it on failure.
//
// What makes that unnecessary is the callers, not the arithmetic. Both send.go
// sites pass a buffer allocated for this one message rather than a pooled one,
// and both discard it if this returns an error, so a partial write is never
// observed. The residual is that lastMAC1 may hold the mac1 of a message that
// was never sent, which costs one cookie reply that fails to decrypt and a
// handshake retry.
//
// It is specifically NOT safe to argue that a failing mac2 would have failed as
// mac1 first. The two differ in exactly the thing that can fail: mac1 is keyed
// with the full digest, so hash-sized, while mac2 is keyed with the cookie,
// which is always wire.CookieSize, and keying is the only real failure source in
// fieldMAC, since hash.Hash.Write does not error and both calls check against
// the same length. For the legacy suite both keys are 32 bytes and the two
// calls are equivalent; under SHA-384 they are 48 and 32, so a backend
// enforcing a minimum HMAC key length would accept the first and refuse the
// second.
func (st *CookieGenerator) AddMacs(s *suite.Suite, msg []byte) error {
	keys, err := st.keys(s)
	if err != nil {
		return err
	}

	smac2 := len(msg) - keys.macSize
	smac1 := smac2 - keys.macSize
	if smac1 < 0 {
		return errShortForMACs(msg, keys.macSize)
	}

	st.Lock()
	defer st.Unlock()

	// set mac1

	mac1, err := fieldMAC(s, keys.mac1, msg[:smac1], keys.macSize)
	if err != nil {
		return err
	}
	copy(msg[smac1:smac2], mac1)

	// The cookie reply authenticates the mac1 the responder saw, so the
	// initiator keeps it to decrypt that reply. It is hash-sized, and the
	// append reuses the buffer across messages.
	st.mac2.lastMAC1 = append(st.mac2.lastMAC1[:0], mac1...)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return nil
	}

	// mac2 covers mac1, which is already in place above.
	mac2, err := fieldMAC(s, st.mac2.cookie[:], msg[:smac2], keys.macSize)
	if err != nil {
		return err
	}
	copy(msg[smac2:], mac2)

	return nil
}
