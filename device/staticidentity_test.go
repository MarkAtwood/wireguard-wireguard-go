/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"errors"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/suitestd"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// registerOtherCurvesForTest makes X25519 and P-384 resolvable so a test can
// name a key exchange that is not this device's identity.
//
// Each curve is registered on its own rather than through suitestd.Register,
// which would also replace P-256 and move every other test in this binary off
// wolfCrypt. See registerChaCha20ForTest, which has the same constraint.
func registerOtherCurvesForTest(tb testing.TB) {
	tb.Helper()
	suite.RegisterKEX(suitestd.NameX25519, suitestd.X25519KEX())
	suite.RegisterKEX(suitestd.NameP384, suitestd.P384KEX())
}

// Suites naming a key exchange other than this build's P-256. X25519's private
// key is 32 bytes, the same as P-256's, so it gets as far as deriving a public
// key and is caught by that key differing. P-384's is 48, so it is refused
// before that.
const (
	x25519SuiteName = ":X25519:HKDF-SHA-256:AEAD_AES_256_GCM"
	p384SuiteName   = ":P-384:HKDF-SHA-384:AEAD_AES_256_GCM"
)

// TestSuiteWithAnotherKeyExchangeIsRefused pins the boundary of key-exchange
// agility.
//
// A device has one static key pair and all three Diffie-Hellman operations in
// the handshake involve it, so a peer whose suite names a different curve
// cannot be spoken to until the device is re-keyed, which is an out-of-band
// operation. The hash and the AEAD move per peer freely; the key exchange does
// not. That is refused at configuration time rather than discovered as an
// unexplained handshake failure.
func TestSuiteWithAnotherKeyExchangeIsRefused(t *testing.T) {
	registerOtherCurvesForTest(t)

	device := randDevice(t)
	defer device.Close()

	for _, c := range []struct {
		name  string
		suite string
	}{
		{"private key length matches, public key does not", x25519SuiteName},
		{"private key length does not match", p384SuiteName},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Accepting it is refused, since it could never complete and would
			// take a message-length routing slot.
			if _, err := device.AcceptSuite([]byte(c.suite), []byte(LegacyIdentifier)); !errors.Is(err, errStaticIdentityKEX) {
				t.Errorf("AcceptSuite error = %v, want %v", err, errStaticIdentityKEX)
			}

			// And so is pinning a peer to it. The suite is resolved directly,
			// bypassing AcceptSuite, so this tests SetSuite's own gate rather
			// than relying on the suite being unavailable.
			s, err := device.suites.registry.Accept([]byte(c.suite), []byte(LegacyIdentifier))
			if err != nil {
				t.Fatalf("resolving %q: %v", c.suite, err)
			}
			peer, err := device.NewPeer(newTestPublicKey(t))
			if err != nil {
				t.Fatal(err)
			}
			if err := peer.SetSuite(s); !errors.Is(err, errStaticIdentityKEX) {
				t.Errorf("SetSuite error = %v, want %v", err, errStaticIdentityKEX)
			}

			// A refused SetSuite must leave the peer as it was, on the device
			// suite, rather than half-moved.
			got, _ := peer.suiteFor()
			deviceSuite, _ := device.localSuite()
			if got != deviceSuite {
				t.Errorf("the peer moved to %q despite the refusal", got.Name())
			}
		})
	}
}

// TestMovingAPeerKeepsItsSharedSecret is the other half: a suite that keeps the
// key exchange and changes only the hash is still allowed, and the peer's
// long-term shared secret survives the move.
//
// The secret is recomputed on every SetSuite because it is computed with the
// peer's key exchange. When the curve is unchanged the value is unchanged too,
// which is what this checks: recomputing must not clear it or compute it under
// something else.
func TestMovingAPeerKeepsItsSharedSecret(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	sha384, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("AcceptSuite: %v", err)
	}

	peer, err := device.NewPeer(newTestPublicKey(t))
	if err != nil {
		t.Fatal(err)
	}

	peer.handshake.mutex.RLock()
	before := bytes.Clone(peer.handshake.precomputedStaticStatic)
	peer.handshake.mutex.RUnlock()

	if len(before) == 0 {
		t.Fatal("the new peer has no shared secret, so this test proves nothing")
	}
	if isZero(before) {
		t.Fatal("the new peer's shared secret is all zeros")
	}

	if err := peer.SetSuite(sha384); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}

	peer.handshake.mutex.RLock()
	after := bytes.Clone(peer.handshake.precomputedStaticStatic)
	peer.handshake.mutex.RUnlock()

	if !bytes.Equal(before, after) {
		t.Errorf("the shared secret changed across a move that kept the key exchange:\n%x\n%x", before, after)
	}
}

// TestPeerBeforeAPrivateKeyHasNoSharedSecret covers the configuration order a
// device is allowed to be driven in.
//
// Peers may be added before the private key is set. The shared secret is empty
// until then, and the handshake refuses to run on an empty one, which is why
// leaving it empty is not reported as an error.
func TestPeerBeforeAPrivateKeyHasNoSharedSecret(t *testing.T) {
	// A real device, brought up the way NewDevice brings one up, but never
	// given a private key.
	tun := tuntest.NewChannelTUN()
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelSilent, ""))
	defer device.Close()

	peer, err := device.NewPeer(newTestPublicKey(t))
	if err != nil {
		t.Fatalf("a peer could not be added before the private key: %v", err)
	}

	peer.handshake.mutex.RLock()
	secret := peer.handshake.precomputedStaticStatic
	peer.handshake.mutex.RUnlock()

	if len(secret) != 0 {
		t.Errorf("the peer has a %d byte shared secret with no device private key", len(secret))
	}

	// The handshake refuses rather than deriving keys from nothing.
	if _, err := device.CreateMessageInitiation(peer); !errors.Is(err, errInvalidPublicKey) {
		t.Errorf("CreateMessageInitiation error = %v, want %v", err, errInvalidPublicKey)
	}
}

// newTestPublicKey is a fresh public key of this build's key exchange, for use
// as a peer's static key.
func newTestPublicKey(tb testing.TB) NoisePublicKey {
	tb.Helper()
	sk, err := newPrivateKey(testKEX())
	if err != nil {
		tb.Fatal(err)
	}
	return sk.publicKeyOrFatal(tb)
}
