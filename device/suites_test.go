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

	wolfSSL "github.com/wolfssl/go-wolfssl"
	"golang.zx2c4.com/wireguard/wire"
)

// deployedInitialState recomputes the initial chaining key and transcript hash
// of the deployed build, directly with wolfCrypt and the compiled-in constants,
// exactly as the shipped code did before the suite computed them.
//
// This is the independent oracle for the whole suite mechanism. It must not be
// expressed in terms of a suite, a registry or the initialstate package, since
// those are what it checks. It lives in the test rather than in the package
// because production has no use for a hardcoded SHA-256 initial state any more:
// every handshake takes its own from its suite.
func deployedInitialState() (chainKey, hash []byte) {
	chainKey = make([]byte, wolfSSL.WC_SHA256_DIGEST_SIZE)
	hash = make([]byte, wolfSSL.WC_SHA256_DIGEST_SIZE)

	var sha wolfSSL.Wc_Sha256
	wolfSSL.Wc_InitSha256_ex(&sha, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_Sha256Update(&sha, []byte(NoiseConstruction), len(NoiseConstruction))
	wolfSSL.Wc_Sha256Final(&sha, chainKey)
	wolfSSL.Wc_Sha256Free(&sha)

	var h2 wolfSSL.Wc_Sha256
	wolfSSL.Wc_InitSha256_ex(&h2, nil, wolfSSL.INVALID_DEVID)
	wolfSSL.Wc_Sha256Update(&h2, chainKey, len(chainKey))
	wolfSSL.Wc_Sha256Update(&h2, []byte(WGIdentifier), len(WGIdentifier))
	wolfSSL.Wc_Sha256Final(&h2, hash)
	wolfSSL.Wc_Sha256Free(&h2)

	return chainKey, hash
}

// TestLegacySuiteMatchesTheDeployedConstants is the compatibility check for the
// whole plumbing change.
//
// The deployed build hashed its initial chaining key and transcript hash from
// the compiled-in constants with SHA-256. The suite computes the same pair from
// the same handshake name and identifier. If the two ever disagree, a device
// built on the suite cannot talk to any peer in the field.
func TestLegacySuiteMatchesTheDeployedConstants(t *testing.T) {
	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		t.Fatalf("initSuites: %v", err)
	}

	s, _ := device.localSuite()
	if s == nil {
		t.Fatal("no local suite after initSuites")
	}

	wantChainKey, wantHash := deployedInitialState()
	if !bytes.Equal(s.State.ChainKey, wantChainKey) {
		t.Errorf("suite chain key %x, deployed build computes %x", s.State.ChainKey, wantChainKey)
	}
	if !bytes.Equal(s.State.Hash, wantHash) {
		t.Errorf("suite hash %x, deployed build computes %x", s.State.Hash, wantHash)
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

// deployedInitiation and deployedResponse are the handshake messages exactly as
// the deployed build declares them: fixed-size arrays, marshalled by
// encoding/binary.
//
// They are frozen here, as literal lengths, so this test has an oracle that is
// not the code under test. The package's own message types are now the wire
// package's, whose fields are slices sized from the suite, so encoding/binary
// cannot marshal them and the package can no longer produce these bytes any
// other way than through the codec being checked.
//
// The lengths are 65 for a P-256 public key in X9.63 uncompressed form, 16 for
// the AES-GCM tag, 12 for the tai64n timestamp and 32 for a SHA-256 MAC. They
// are written out rather than taken from constants because they are frozen by
// deployment: a peer in the field speaks these offsets whatever a constant
// elsewhere is later changed to.
type (
	deployedInitiation struct {
		Type      uint32
		Sender    uint32
		Ephemeral [65]byte
		Static    [65 + 16]byte
		Timestamp [12 + 16]byte
		MAC1      [32]byte
		MAC2      [32]byte
	}

	deployedResponse struct {
		Type      uint32
		Sender    uint32
		Receiver  uint32
		Ephemeral [65]byte
		Empty     [16]byte
		MAC1      [32]byte
		MAC2      [32]byte
	}
)

// TestLayoutEncodingMatchesTheDeployedFormat is the check that making the
// message fields suite-sized did not move the bytes on the wire.
//
// The send path encodes through the suite's layout. This builds the same
// message both ways, through the layout and through encoding/binary over the
// frozen deployed structs, and requires the two to be byte for byte identical
// for the legacy suite. It is asserted here, inside the package that sends the
// packets, rather than only in the wire package's own golden test, because this
// is the path a deployed peer's bytes actually travel.
func TestLayoutEncodingMatchesTheDeployedFormat(t *testing.T) {
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
		var frozen deployedInitiation
		frozen.Type = MessageInitiationType
		frozen.Sender = 0x0badc0de
		fill(frozen.Ephemeral[:], 0x40)
		fill(frozen.Static[:], 0x80)
		fill(frozen.Timestamp[:], 0xC0)
		fill(frozen.MAC1[:], 0x10)
		fill(frozen.MAC2[:], 0x20)

		var want bytes.Buffer
		if err := binary.Write(&want, binary.LittleEndian, frozen); err != nil {
			t.Fatalf("binary.Write: %v", err)
		}

		msg := MessageInitiation{
			Type:      frozen.Type,
			Sender:    frozen.Sender,
			Ephemeral: frozen.Ephemeral[:],
			Static:    frozen.Static[:],
			Timestamp: frozen.Timestamp[:],
			MAC1:      frozen.MAC1[:],
			MAC2:      frozen.MAC2[:],
		}
		got, err := layout.AppendInitiation(nil, &msg)
		if err != nil {
			t.Fatalf("AppendInitiation: %v", err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("layout encoding differs from the deployed format\n got %x\nwant %x", got, want.Bytes())
		}

		// And the decode path must recover every field.
		back, err := layout.ParseInitiation(got)
		if err != nil {
			t.Fatalf("ParseInitiation: %v", err)
		}
		if back.Type != msg.Type || back.Sender != msg.Sender {
			t.Errorf("decoded header %d/%#x, want %d/%#x", back.Type, back.Sender, msg.Type, msg.Sender)
		}
		for _, f := range []struct {
			name      string
			got, want []byte
		}{
			{"ephemeral", back.Ephemeral, msg.Ephemeral},
			{"static", back.Static, msg.Static},
			{"timestamp", back.Timestamp, msg.Timestamp},
			{"mac1", back.MAC1, msg.MAC1},
			{"mac2", back.MAC2, msg.MAC2},
		} {
			if !bytes.Equal(f.got, f.want) {
				t.Errorf("decoded %s = %x, want %x", f.name, f.got, f.want)
			}
		}
	})

	t.Run("response", func(t *testing.T) {
		var frozen deployedResponse
		frozen.Type = MessageResponseType
		frozen.Sender = 0x11112222
		frozen.Receiver = 0x33334444
		fill(frozen.Ephemeral[:], 0x40)
		fill(frozen.Empty[:], 0x70)
		fill(frozen.MAC1[:], 0x10)
		fill(frozen.MAC2[:], 0x20)

		var want bytes.Buffer
		if err := binary.Write(&want, binary.LittleEndian, frozen); err != nil {
			t.Fatalf("binary.Write: %v", err)
		}

		msg := MessageResponse{
			Type:      frozen.Type,
			Sender:    frozen.Sender,
			Receiver:  frozen.Receiver,
			Ephemeral: frozen.Ephemeral[:],
			Empty:     frozen.Empty[:],
			MAC1:      frozen.MAC1[:],
			MAC2:      frozen.MAC2[:],
		}
		got, err := layout.AppendResponse(nil, &msg)
		if err != nil {
			t.Fatalf("AppendResponse: %v", err)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Errorf("layout encoding differs from the deployed format\n got %x\nwant %x", got, want.Bytes())
		}

		back, err := layout.ParseResponse(got)
		if err != nil {
			t.Fatalf("ParseResponse: %v", err)
		}
		if back.Type != msg.Type || back.Sender != msg.Sender || back.Receiver != msg.Receiver {
			t.Error("decoded response header does not match")
		}
		for _, f := range []struct {
			name      string
			got, want []byte
		}{
			{"ephemeral", back.Ephemeral, msg.Ephemeral},
			{"empty", back.Empty, msg.Empty},
			{"mac1", back.MAC1, msg.MAC1},
			{"mac2", back.MAC2, msg.MAC2},
		} {
			if !bytes.Equal(f.got, f.want) {
				t.Errorf("decoded %s = %x, want %x", f.name, f.got, f.want)
			}
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
	routed, layout, ok := device.suiteForInitiationSize(MessageInitiationSize)
	if !ok {
		t.Fatal("the legacy suite is no longer reachable by length")
	}
	if got := string(routed.Name()); got != LegacyHandshakeName {
		t.Errorf("the legacy initiation size routes to %q, want %q", got, LegacyHandshakeName)
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
		_, got, ok := device.suiteForInitiationSize(c.size)
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
