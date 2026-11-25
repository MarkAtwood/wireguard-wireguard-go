/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wire"
)

// TestLegacySuiteMatchesThePackageGlobals is the compatibility check for the
// whole plumbing change.
//
// The handshake derives its keys from the package-level InitialChainKey and
// InitialHash, computed in init() from the compiled-in constants. The suite
// computes the same pair from the same handshake name and identifier. If the
// two ever disagree, a device built on the suite cannot talk to a device built
// on the globals, which includes every peer in the field.
func TestLegacySuiteMatchesThePackageGlobals(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	s, _ := device.localSuite()
	if s == nil {
		t.Fatal("no local suite after initSuites")
	}

	if !bytes.Equal(s.State.ChainKey, InitialChainKey[:]) {
		t.Errorf("suite chain key %x does not match InitialChainKey %x", s.State.ChainKey, InitialChainKey[:])
	}
	if !bytes.Equal(s.State.Hash, InitialHash[:]) {
		t.Errorf("suite hash %x does not match InitialHash %x", s.State.Hash, InitialHash[:])
	}
	if got := string(s.Name()); got != LegacyHandshakeName {
		t.Errorf("suite name = %q, want %q", got, LegacyHandshakeName)
	}
	if got := string(s.Name()); got != NoiseConstruction {
		t.Errorf("suite name = %q but the package constant is %q", got, NoiseConstruction)
	}
}

// TestLegacyLayoutMatchesThePackageConstants checks the other half: the sizes
// the suite's layout produces must be the sizes the message structs are.
func TestLegacyLayoutMatchesThePackageConstants(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	_, layout := device.localSuite()
	if got := layout.InitiationSize(); got != MessageInitiationSize {
		t.Errorf("layout initiation size = %d, MessageInitiationSize = %d", got, MessageInitiationSize)
	}
	if got := layout.ResponseSize(); got != MessageResponseSize {
		t.Errorf("layout response size = %d, MessageResponseSize = %d", got, MessageResponseSize)
	}
	if got := layout.PublicKeySize; got != NoisePublicKeySize {
		t.Errorf("layout public key size = %d, NoisePublicKeySize = %d", got, NoisePublicKeySize)
	}
}

// TestAcceptedSizesGateOnLength covers the pre-authentication length check that
// replaces the single-constant equality test.
func TestAcceptedSizesGateOnLength(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	if !device.acceptsInitiationSize(MessageInitiationSize) {
		t.Errorf("device rejects its own initiation size %d", MessageInitiationSize)
	}
	if !device.acceptsResponseSize(MessageResponseSize) {
		t.Errorf("device rejects its own response size %d", MessageResponseSize)
	}
	for _, n := range []int{0, 1, MessageInitiationSize - 1, MessageInitiationSize + 1} {
		if device.acceptsInitiationSize(n) {
			t.Errorf("device accepts an initiation of %d bytes", n)
		}
	}
	if got, want := device.maxHandshakeSize(), MessageInitiationSize; got != want {
		t.Errorf("maxHandshakeSize = %d, want %d", got, want)
	}
}

// TestPeerFollowsTheDeviceSuiteByDefault pins the default, since every peer
// relies on it until an orchestrator pins a suite.
func TestPeerFollowsTheDeviceSuiteByDefault(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	peer := &Peer{device: &device}
	s, layout := peer.suiteFor()
	deviceSuite, deviceLayout := device.localSuite()

	if s != deviceSuite {
		t.Error("a peer with no suite does not follow the device's")
	}
	if layout != deviceLayout {
		t.Errorf("peer layout %+v, device layout %+v", layout, deviceLayout)
	}
}

// TestSetSuitePinsAPeer is the migration mechanism: a peer can be moved to a
// different suite while the device keeps its own.
func TestSetSuitePinsAPeer(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	sha384, err := device.suites.registry.Accept(
		[]byte(":P-256:HKDF-SHA-384:AEAD_AES_256_GCM"),
		[]byte(LegacyIdentifier),
	)
	if err != nil {
		t.Fatalf("accepting a second suite: %v", err)
	}

	peer := &Peer{device: &device}
	if err := peer.SetSuite(sha384); err != nil {
		t.Fatalf("SetSuite: %v", err)
	}

	s, layout := peer.suiteFor()
	if s != sha384 {
		t.Error("SetSuite did not pin the peer's suite")
	}
	deviceSuite, deviceLayout := device.localSuite()
	if s == deviceSuite {
		t.Error("the pinned peer still reports the device suite")
	}
	if layout == deviceLayout {
		t.Error("the pinned peer still reports the device layout")
	}

	// The two suites must disagree on message size, which is the whole reason
	// the layout has to travel with the peer.
	expected, err := wire.LayoutFor(sha384)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}
	if layout != expected {
		t.Errorf("peer layout %+v, want %+v", layout, expected)
	}
	if layout.InitiationSize() == deviceLayout.InitiationSize() {
		t.Errorf("both suites give initiation size %d", layout.InitiationSize())
	}
}

func TestSetSuiteRejectsNil(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	peer := &Peer{device: &device}
	if err := peer.SetSuite(nil); err == nil {
		t.Error("SetSuite accepted a nil suite")
	}
}

// TestLayoutEncodingMatchesEncodingBinary is the check that the send path did
// not change the bytes on the wire.
//
// send.go now encodes through the suite's layout instead of encoding/binary.
// This asserts the two agree for the legacy suite, over the message structs
// this package actually uses, which also exercises toWire. Without it, the
// conversion between the message struct and the layout's view would be
// untested, and a field swapped there would be invisible.
func TestLayoutEncodingMatchesEncodingBinary(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}
	_, layout := device.localSuite()

	fill := func(b []byte, start byte) {
		for i := range b {
			b[i] = start + byte(i)
		}
	}

	t.Run("initiation", func(t *testing.T) {
		var msg MessageInitiation
		msg.Type = MessageInitiationType
		msg.Sender = 0x0badc0de
		fill(msg.Ephemeral[:], 0x40)
		fill(msg.Static[:], 0x80)
		fill(msg.Timestamp[:], 0xC0)
		fill(msg.MAC1[:], 0x10)
		fill(msg.MAC2[:], 0x20)

		var legacy bytes.Buffer
		if err := binary.Write(&legacy, binary.LittleEndian, msg); err != nil {
			t.Fatalf("binary.Write: %v", err)
		}
		got, err := layout.AppendInitiation(nil, msg.toWire())
		if err != nil {
			t.Fatalf("AppendInitiation: %v", err)
		}
		if !bytes.Equal(got, legacy.Bytes()) {
			t.Errorf("layout encoding differs from encoding/binary\n got %x\nwant %x", got, legacy.Bytes())
		}

		// And the decode path must recover the same struct.
		decoded, err := layout.ParseInitiation(got)
		if err != nil {
			t.Fatalf("ParseInitiation: %v", err)
		}
		var back MessageInitiation
		back.fromWire(decoded)
		if back != msg {
			t.Error("fromWire did not recover the original message")
		}
	})

	t.Run("response", func(t *testing.T) {
		var msg MessageResponse
		msg.Type = MessageResponseType
		msg.Sender = 0x11112222
		msg.Receiver = 0x33334444
		fill(msg.Ephemeral[:], 0x40)
		fill(msg.Empty[:], 0x70)
		fill(msg.MAC1[:], 0x10)
		fill(msg.MAC2[:], 0x20)

		var legacy bytes.Buffer
		if err := binary.Write(&legacy, binary.LittleEndian, msg); err != nil {
			t.Fatalf("binary.Write: %v", err)
		}
		got, err := layout.AppendResponse(nil, msg.toWire())
		if err != nil {
			t.Fatalf("AppendResponse: %v", err)
		}
		if !bytes.Equal(got, legacy.Bytes()) {
			t.Errorf("layout encoding differs from encoding/binary\n got %x\nwant %x", got, legacy.Bytes())
		}

		decoded, err := layout.ParseResponse(got)
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		var back MessageResponse
		back.fromWire(decoded)
		if back != msg {
			t.Error("fromWire did not recover the original message")
		}
	})
}

// TestAcceptSuiteRejectsLengthCollision covers the guard.
//
// The case is not hypothetical and it is the awkward one: migrating from the
// legacy handshake name to the self-describing dynamic name, keeping the same
// algorithms, produces two suites with different chaining keys and IDENTICAL
// message lengths. Length cannot tell them apart, so accepting both would leave
// the second unreachable. Registration refuses it instead.
func TestAcceptSuiteRejectsLengthCollision(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	// Same primitives as the legacy suite, written as a dynamic name.
	same := ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"
	_, err := device.AcceptSuite([]byte(same), []byte(LegacyIdentifier))
	if !errors.Is(err, errSuiteLengthCollision) {
		t.Fatalf("AcceptSuite error = %v, want %v", err, errSuiteLengthCollision)
	}
	if !strings.Contains(err.Error(), LegacyHandshakeName) || !strings.Contains(err.Error(), same) {
		t.Errorf("error does not name both suites: %v", err)
	}

	// The colliding suite must not have displaced the legacy one.
	layout, ok := device.layoutForInitiationSize(MessageInitiationSize)
	if !ok {
		t.Fatal("the legacy suite is no longer reachable by length")
	}
	if layout.InitiationSize() != MessageInitiationSize {
		t.Errorf("layout initiation size = %d, want %d", layout.InitiationSize(), MessageInitiationSize)
	}
}

// TestAcceptSuiteAllowsDifferentLengths is the migration that does work by
// length: different algorithms, so different message sizes.
func TestAcceptSuiteAllowsDifferentLengths(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	sha384 := ":P-256:HKDF-SHA-384:AEAD_AES_256_GCM"
	s, err := device.AcceptSuite([]byte(sha384), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("AcceptSuite: %v", err)
	}

	sha384Layout, err := wire.LayoutFor(s)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}
	if sha384Layout.InitiationSize() == MessageInitiationSize {
		t.Fatal("the test's two suites do not differ in length, so it proves nothing")
	}

	// Both lengths are now accepted, and each resolves to its own layout.
	for _, c := range []struct {
		size int
		want wire.Layout
	}{
		{MessageInitiationSize, device.suites.localLayout},
		{sha384Layout.InitiationSize(), sha384Layout},
	} {
		if !device.acceptsInitiationSize(c.size) {
			t.Errorf("device rejects an initiation of %d bytes", c.size)
		}
		got, ok := device.layoutForInitiationSize(c.size)
		if !ok {
			t.Fatalf("no layout for a %d byte initiation", c.size)
		}
		if got != c.want {
			t.Errorf("layout for %d bytes = %+v, want %+v", c.size, got, c.want)
		}
	}

	if got, want := device.maxHandshakeSize(), sha384Layout.InitiationSize(); got != want {
		t.Errorf("maxHandshakeSize = %d, want %d (the larger suite)", got, want)
	}
}

// TestReacceptingTheSameSuiteIsNotACollision checks a configuration reload does
// not trip the guard against the suite's own previous entry.
func TestReacceptingTheSameSuiteIsNotACollision(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	sha384 := []byte(":P-256:HKDF-SHA-384:AEAD_AES_256_GCM")
	if _, err := device.AcceptSuite(sha384, []byte(LegacyIdentifier)); err != nil {
		t.Fatalf("first AcceptSuite: %v", err)
	}
	if _, err := device.AcceptSuite(sha384, []byte(LegacyIdentifier)); err != nil {
		t.Errorf("re-accepting the same suite failed: %v", err)
	}
}
