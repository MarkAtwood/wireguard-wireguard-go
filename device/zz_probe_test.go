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

// TestMigrationBlockedOnCryptoDispatch pins the remaining blocker, so it is a
// statement in code rather than a note in a tracker.
//
// Framing is suite-driven, but the handshake's crypto is not: noise-helpers.go
// calls wolfCrypt with ECC_SECP256R1 hardcoded, so it produces a 65 byte public
// key whatever suite a peer is pinned to. Under a suite whose key exchange is
// X25519 the layout wants 32, and encoding fails.
//
// That it fails at all is the good news: wire's field-length check refuses to
// emit a malformed packet rather than putting a 65 byte key in a 32 byte field.
//
// When the suites package gains wolfCrypt-backed implementations and the
// handshake calls them through the suite, this test should be replaced by a
// real two-suite handshake. Its failure is the signal that the blocker is gone.
func TestMigrationBlockedOnCryptoDispatch(t *testing.T) {
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

	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	pk := sk.publicKey()

	if pk.Len() == layout.PublicKeySize {
		t.Fatalf("the crypto produced a %d byte key matching the stock layout; "+
			"per-suite crypto dispatch appears to have landed, so replace this "+
			"test with a real two-suite handshake", pk.Len())
	}
	t.Logf("crypto produced %d bytes, the stock layout wants %d", pk.Len(), layout.PublicKeySize)

	var msg MessageInitiation
	msg.Type = MessageInitiationType
	msg.Ephemeral = pk.wireArray()
	if _, err := layout.AppendInitiation(nil, msg.toWire()); !errors.Is(err, wire.ErrFieldLength) {
		t.Errorf("encoding error = %v, want %v; a mismatched key must not be encodable",
			err, wire.ErrFieldLength)
	}
}
