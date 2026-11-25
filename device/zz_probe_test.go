/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// This file is the two-live-suite migration demo. It wants renaming to
// migration_demo_test.go; it kept a scratch name because the sandbox would not
// permit the rename.

package device

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/wire"
)

// stockSuiteName is a second suite with different algorithms, and therefore
// different message lengths, from the deployed one.
const stockSuiteName = ":X25519:HKDF-BLAKE2S-256:AEAD_CHACHA20_POLY1305"

// TestMigrationResponderServesTwoLiveSuites is the migration demo at the
// framing level: one device accepting two suites at once, routing an inbound
// handshake to the right layout by its length, with each suite keeping its own
// chaining key.
//
// This is the state a fleet is in mid-migration, when some peers have moved to
// the new suite and some have not.
func TestMigrationResponderServesTwoLiveSuites(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	legacy, legacyLayout := device.localSuite()
	stock, err := device.AcceptSuite([]byte(stockSuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("accepting the second suite: %v", err)
	}
	stockLayout, err := wire.LayoutFor(stock)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}

	t.Logf("legacy %q: initiation %d bytes", legacy.Name(), legacyLayout.InitiationSize())
	t.Logf("stock  %q: initiation %d bytes", stock.Name(), stockLayout.InitiationSize())

	// 1. The two suites are genuinely distinct, in keys and in framing.
	if bytes.Equal(legacy.State.ChainKey, stock.State.ChainKey) {
		t.Error("the two live suites share a chaining key")
	}
	if legacyLayout.InitiationSize() == stockLayout.InitiationSize() {
		t.Fatal("the two suites do not differ in length, so this demo proves nothing")
	}

	// 2. Both are accepted, and each length routes to its own layout. This is
	//    what the receive path does before it knows which peer is sending.
	for _, c := range []struct {
		name   string
		size   int
		expect wire.Layout
	}{
		{"legacy", legacyLayout.InitiationSize(), legacyLayout},
		{"stock", stockLayout.InitiationSize(), stockLayout},
	} {
		t.Run("routes "+c.name, func(t *testing.T) {
			if !device.acceptsInitiationSize(c.size) {
				t.Fatalf("device rejects a %d byte initiation", c.size)
			}
			got, ok := device.layoutForInitiationSize(c.size)
			if !ok {
				t.Fatalf("no layout for a %d byte initiation", c.size)
			}
			if got != c.expect {
				t.Errorf("routed to %+v, want %+v", got, c.expect)
			}
		})
	}

	// 3. A message framed under one suite must not decode under the other,
	//    which is what keeps the two populations from being confused.
	legacyPacket := make([]byte, legacyLayout.InitiationSize())
	if _, err := stockLayout.ParseInitiation(legacyPacket); !errors.Is(err, wire.ErrSize) {
		t.Errorf("a legacy-sized packet parsed under the stock layout: %v", err)
	}

	// 4. Peers are moved one at a time. An unpinned peer stays on the device
	//    suite, which is how a migration is sequenced rather than flag-dayed.
	moved := &Peer{device: &device}
	if err := moved.SetSuite(stock); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}
	notMoved := &Peer{device: &device}

	if s, _ := moved.suiteFor(); s != stock {
		t.Error("the moved peer is not on the stock suite")
	}
	if s, _ := notMoved.suiteFor(); s != legacy {
		t.Error("the unmoved peer did not stay on the device suite")
	}

	// 5. The receive buffer has to fit the larger of the two.
	if got, want := device.maxHandshakeSize(), legacyLayout.InitiationSize(); got != want {
		t.Errorf("maxHandshakeSize = %d, want %d", got, want)
	}
}

// TestKEXIsDispatchedButHashAndAEADAreNot records exactly how far per-suite
// crypto dispatch has got, so the gap is a failing-when-fixed assertion rather
// than a note someone has to remember.
//
// Dispatched: the key exchange. A peer pinned to a suite naming X25519 gets
// 32 byte keys from the suite's key exchange, matching its layout, while the
// device's own suite gets wolfCrypt P-256 and 65 bytes.
//
// NOT dispatched: the hash and the AEAD. noise-protocol.go still calls
// wolfCrypt SHA-256 and AES-GCM directly for mixHash, mixKey and the encrypted
// fields. So a peer on a suite naming BLAKE2s and ChaCha20-Poly1305 would
// exchange X25519 keys and then hash with SHA-256 and encrypt with AES-GCM.
// Both ends run this code so they agree with each other, but the handshake
// name would not describe what was used, and the name is what the two peers
// agreed on. That makes this a correctness gap, not merely an unfinished one.
func TestKEXIsDispatchedButHashAndAEADAreNot(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}
	stock, err := device.AcceptSuite([]byte(stockSuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("AcceptSuite: %v", err)
	}

	peer := &Peer{device: &device}
	if err := peer.SetSuite(stock); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}
	_, layout := peer.suiteFor()

	// The key exchange follows the peer's suite.
	sk, err := newPrivateKey(peer.kex())
	if err != nil {
		t.Fatalf("newPrivateKey through the peer's suite: %v", err)
	}
	pk, err := sk.publicKey(peer.kex())
	if err != nil {
		t.Fatalf("publicKey through the peer's suite: %v", err)
	}
	if pk.Len() != layout.PublicKeySize {
		t.Errorf("the peer's key exchange produced %d bytes, its layout wants %d",
			pk.Len(), layout.PublicKeySize)
	}

	// The device's own suite still gets P-256, so the two really differ.
	deviceSK, err := newPrivateKey(device.kex())
	if err != nil {
		t.Fatalf("newPrivateKey through the device's suite: %v", err)
	}
	devicePK, err := deviceSK.publicKey(device.kex())
	if err != nil {
		t.Fatalf("publicKey through the device's suite: %v", err)
	}
	if devicePK.Len() == pk.Len() {
		t.Errorf("both suites produced %d byte keys; dispatch is not taking effect", pk.Len())
	}
	t.Logf("peer suite key %d bytes, device suite key %d bytes", pk.Len(), devicePK.Len())

	// The hash and AEAD are NOT dispatched. The suite says one thing and the
	// handshake code does another. When that is fixed, this assertion fails and
	// whoever sees it should delete it and extend the migration demo to a real
	// two-suite handshake.
	if got := stock.NewHash().Size(); got != 32 {
		t.Fatalf("the stock suite's hash is %d bytes; revisit this test", got)
	}
	hardcoded := countHandshakeHardcodedCrypto(t)
	if hardcoded == 0 {
		t.Error("noise-protocol.go no longer calls wolfCrypt directly, so hash and AEAD " +
			"dispatch appears to have landed: replace this test with an end-to-end " +
			"two-suite handshake")
	}
	t.Logf("noise-protocol.go still has %d direct wolfCrypt hash/AEAD calls", hardcoded)
}

// countHandshakeHardcodedCrypto counts the direct wolfCrypt hash and AEAD calls
// left in the handshake, which is the remaining dispatch work.
func countHandshakeHardcodedCrypto(t *testing.T) int {
	t.Helper()
	src, err := os.ReadFile("noise-protocol.go")
	if err != nil {
		t.Fatalf("reading noise-protocol.go: %v", err)
	}
	n := 0
	for _, pat := range []string{"Wc_Sha256", "Wc_AesGcm"} {
		n += bytes.Count(src, []byte(pat))
	}
	return n
}
