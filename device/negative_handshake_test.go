/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/wire"
)

/* The two properties asserted here are the ones that survived the rescoping of
 * WOLFGUARD-AGILITY-6ytx.7. Nothing is negotiated in this design, so there is
 * no downgrade and no tampered-vector surface to test: the handshake name is
 * carried and hashed, and altering it in flight changes the chaining key. What
 * is left is what an unauthenticated sender can make a responder do.
 *
 * First, a garbage initiation must cost no more than one scalar multiplication
 * however many suites are live. That is the claim the design makes against
 * douzzer's "N suites costs N scalar multiplications", and the claim the
 * rejected probe-based draft would have failed: it filtered candidates by
 * message length and broke ties by verifying mac1 under each candidate's
 * layout, so its cost grew with the accept set.
 *
 * Second, mac1 must not become an oracle for which suites a responder accepts
 * beyond what its responses already reveal. */

// countingKEX counts the scalar multiplications a key exchange performs.
//
// SharedSecret is the only handshake operation whose cost is a scalar
// multiplication, and sharedSecret in noise-helpers.go reaches it through this
// interface, so wrapping a suite's KEX counts every one a handshake does. The
// interface exists so that a wolfCrypt implementation can replace the stdlib
// one, which makes this a use of an extension point the design already has
// rather than a seam cut for a test.
type countingKEX struct {
	suite.KEX
	calls *atomic.Int64
}

func (k countingKEX) SharedSecret(priv, peerPub []byte) ([]byte, error) {
	k.calls.Add(1)
	return k.KEX.SharedSecret(priv, peerPub)
}

// countSharedSecrets routes every accepted suite's key exchange through calls,
// leaving the implementation underneath it alone.
//
// One counter shared by every accepted suite is the whole point. It measures
// what a single packet costs the device rather than what it costs one suite, so
// a receive path that tried each candidate in turn would show up as a count
// that grows with the size of the accept set.
//
// Suites already wrapped are skipped, so this can be called again after another
// suite is accepted without double counting the ones already covered.
func countSharedSecrets(tb testing.TB, device *Device, calls *atomic.Int64) {
	tb.Helper()

	device.suites.Lock()
	defer device.suites.Unlock()

	for _, c := range device.suites.accepted {
		if _, already := c.suite.KEX.(countingKEX); already {
			continue
		}
		c.suite.KEX = countingKEX{KEX: c.suite.KEX, calls: calls}
	}
}

// randBytes returns n bytes that will not decrypt as anything.
func randBytes(tb testing.TB, n int) []byte {
	tb.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		tb.Fatalf("reading %d random bytes: %v", n, err)
	}
	return b
}

// forgedInitiation is an initiation framed exactly as a real one, carrying a
// valid mac1 and garbage everywhere a key or a timestamp belongs.
//
// This is the worst case an unauthenticated sender can reach, and it is cheap
// to produce. mac1 is keyed on the responder's static public key, which is not
// secret from anyone intending to talk to it, so forging one needs nothing but
// a value the responder publishes.
//
// The ephemeral field holds a real point on the suite's curve rather than
// random bytes. That matters for what is being measured: a random 65 bytes
// fails to import before any scalar multiplication happens, so a test built on
// random bytes would time the cheap rejection and report it as the cost of an
// attack. A sender trying to make a responder work would send a real point.
func forgedInitiation(tb testing.TB, responderPub NoisePublicKey, s *suite.Suite, layout wire.Layout) []byte {
	tb.Helper()

	_, ephemeral, err := s.KEX.GenerateKey()
	if err != nil {
		tb.Fatalf("generating an ephemeral key: %v", err)
	}

	packet, err := layout.AppendInitiation(nil, &wire.Initiation{
		Type:      MessageInitiationType,
		Sender:    1,
		Ephemeral: ephemeral,
		Static:    randBytes(tb, layout.PublicKeySize+layout.AEADOverhead),
		Timestamp: randBytes(tb, tai64n.TimestampSize+layout.AEADOverhead),
		MAC1:      make([]byte, layout.MACSize),
		MAC2:      make([]byte, layout.MACSize),
	})
	if err != nil {
		tb.Fatalf("encoding a forged initiation: %v", err)
	}
	if len(packet) != layout.InitiationSize() {
		tb.Fatalf("forged initiation is %d bytes, the layout says %d", len(packet), layout.InitiationSize())
	}

	/* Written onto the encoded packet, which is where a real sender writes it,
	 * so mac1 lands on the field the codec reserved for it under this suite's
	 * lengths rather than at a fixed offset. */
	var gen CookieGenerator
	gen.Init(responderPub)
	if err := gen.AddMacs(s, packet); err != nil {
		tb.Fatalf("adding macs to a forged initiation: %v", err)
	}
	return packet
}

// devicePublicKey reads a device's own static public key, which is the value an
// attacker needs to forge mac1 and the only one it needs.
func devicePublicKey(device *Device) NoisePublicKey {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	return device.staticIdentity.publicKey
}

// TestGarbageInitiationCostsOneScalarMultiplication walks the gates of the
// receive path in the order receive.go applies them, counting the scalar
// multiplications each one costs, with one and then two suites live.
//
// The count must be one in both cases. Two live suites are the most this build
// can serve: a suite's message length is what routes it, P-256 fixes the public
// key at 65 bytes and every candidate AEAD fixes the tag at 16, so the hash is
// the only varying term and only two hash lengths are registered. The accept
// set refuses a second suite of the same length for that reason.
func TestGarbageInitiationCostsOneScalarMultiplication(t *testing.T) {
	for _, live := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d live suites", live), func(t *testing.T) {
			device := randDevice(t)
			defer device.Close()

			if live == 2 {
				if _, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier)); err != nil {
					t.Fatalf("accepting a second suite: %v", err)
				}
			}
			if accepted, _ := device.suiteConfig(); len(accepted) != live {
				t.Fatalf("the device accepts %d suites, this case is about %d", len(accepted), live)
			}

			var calls atomic.Int64
			countSharedSecrets(t, device, &calls)

			s, layout := device.localSuite()
			packet := forgedInitiation(t, devicePublicKey(device), s, layout)

			// Gate one: a length is turned into exactly one suite.
			calls.Store(0)
			recvSuite, recvLayout, ok := device.suiteForInitiationSize(len(packet))
			if !ok {
				t.Fatalf("no accepted suite frames a %d byte initiation", len(packet))
			}
			if recvSuite != s {
				t.Fatalf("routed to %q, want %q", recvSuite.Name(), s.Name())
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("routing an initiation to a suite cost %d scalar multiplications, want 0", n)
			}

			// Gate two: mac1, which is a MAC and must cost no asymmetric work.
			if !device.cookieChecker.CheckMAC1(recvSuite, packet) {
				t.Fatal("the forged mac1 was rejected, so this is not measuring the worst case")
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("verifying mac1 cost %d scalar multiplications, want 0", n)
			}

			/* A packet that fails this gate must cost nothing either, which is
			 * what makes mac1 worth checking first. */
			forged := append([]byte(nil), packet...)
			forged[recvLayout.InitiationMAC1Offset()] ^= 1
			if device.cookieChecker.CheckMAC1(recvSuite, forged) {
				t.Error("mac1 verified with a flipped bit in it")
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("rejecting mac1 cost %d scalar multiplications, want 0", n)
			}

			// Gate three: consuming it, which is where the one scalar
			// multiplication is spent and where the garbage is caught.
			msg, err := recvLayout.ParseInitiation(packet)
			if err != nil {
				t.Fatalf("parsing a forged initiation: %v", err)
			}
			if peer := device.ConsumeMessageInitiation(recvSuite, msg); peer != nil {
				t.Fatal("a forged initiation was consumed as a valid one")
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("a garbage initiation cost %d scalar multiplications with %d suites live, want 1",
					n, live)
			}

			/* A packet that routed to no suite must cost nothing even if it
			 * reaches the consumer anyway. This is what makes the routing
			 * gate's second result safe to get wrong: the guarantee is in
			 * ConsumeMessageInitiation, which refuses a nil suite before it
			 * reads the message, not in the order the caller checks things. */
			calls.Store(0)
			if peer := device.ConsumeMessageInitiation(nil, msg); peer != nil {
				t.Error("an initiation was consumed under no suite at all")
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("consuming under no suite cost %d scalar multiplications, want 0", n)
			}
		})
	}
}

// TestUnauthenticatedGatesPrecedeAnyScalarMultiplication pins the order the
// gates run in, which is the one thing the test above cannot see.
//
// That test calls the gates in the order receive.go calls them, so it measures
// each gate's cost but takes the ordering on trust: it would pass unchanged if
// the real path consumed first and checked mac1 afterwards, which is the
// regression that matters, since it would hand any sender a scalar
// multiplication for the price of a datagram.
//
// Reading the source to assert an ordering is the same technique
// TestHandshakeFileCallsNoCryptoDirectly already uses in this package, done
// over the syntax tree rather than over substrings so that it is the call
// sites being compared and not their spelling.
func TestUnauthenticatedGatesPrecedeAnyScalarMultiplication(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "receive.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing receive.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "RoutineHandshake" {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("receive.go has no RoutineHandshake, so this test is pinning nothing")
	}

	gates := []string{"suiteForInitiationSize", "CheckMAC1", "ConsumeMessageInitiation"}
	at := make(map[string]token.Pos, len(gates))
	for _, name := range gates {
		pos := firstCallPos(fn, name)
		if pos == token.NoPos {
			t.Fatalf("RoutineHandshake makes no call to %s", name)
		}
		at[name] = pos
	}

	for i := 1; i < len(gates); i++ {
		before, after := gates[i-1], gates[i]
		if at[before] >= at[after] {
			t.Errorf("%s is called at %s, after %s at %s: an unauthenticated sender reaches %s first",
				before, fset.Position(at[before]), after, fset.Position(at[after]), after)
		}
	}

	/* Order alone would be decorative if the result were discarded, so the
	 * mac1 gate has to branch out of the iteration when it fails.
	 *
	 * The routing gate gets no such assertion, because it does not need one.
	 * It reports failure through a second result, and a path that ignored it
	 * would carry a nil suite into ConsumeMessageInitiation, which refuses a
	 * nil suite before it touches the packet. That is a guarantee in the
	 * consumer rather than in this ordering, so it is asserted where it lives,
	 * in TestGarbageInitiationCostsOneScalarMultiplication. */
	if !gateBranchesOnFailure(fn, "CheckMAC1") {
		t.Error("no if statement in RoutineHandshake tests CheckMAC1 and branches out when it fails")
	}
}

// firstCallPos is the position of the first call to a method named name under
// node, or token.NoPos.
func firstCallPos(node ast.Node, name string) token.Pos {
	pos := token.NoPos
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return true
		}
		if pos == token.NoPos || call.Pos() < pos {
			pos = call.Pos()
		}
		return true
	})
	return pos
}

// gateBranchesOnFailure reports whether some if statement under fn decides on
// the result of a call to name and leaves the iteration in its body.
//
// Leaving means goto, break, continue or return. Which one is receive.go's
// business; that the packet is abandoned is this test's.
func gateBranchesOnFailure(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || found {
			return !found
		}
		if firstCallPos(ifs.Cond, name) == token.NoPos {
			return true
		}
		ast.Inspect(ifs.Body, func(b ast.Node) bool {
			switch b.(type) {
			case *ast.BranchStmt, *ast.ReturnStmt:
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

// TestMAC1IsNoOracleForTheAcceptSet asserts that an initiation framed under a
// suite a device resolves but does not serve is refused for free, and that the
// refusal is about the accept set rather than about the packet.
//
// The distinction the test rests on is one the design draws deliberately: the
// registry is a factory and the accept set is policy, so a device can resolve a
// suite it will not serve. That is what makes an unserved but perfectly well
// formed initiation constructible here at all.
func TestMAC1IsNoOracleForTheAcceptSet(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	var calls atomic.Int64
	countSharedSecrets(t, device, &calls)

	/* Resolved through the registry, which does not accept it: the suite
	 * exists, derives its own initial state and frames its own messages, and
	 * this device serves no handshake of its length. */
	device.suites.Lock()
	unserved, err := device.suites.registry.Accept([]byte(sha384SuiteName), []byte(LegacyIdentifier))
	device.suites.Unlock()
	if err != nil {
		t.Fatalf("resolving a suite without accepting it: %v", err)
	}
	unservedLayout, err := wire.LayoutFor(unserved)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}

	packet := forgedInitiation(t, devicePublicKey(device), unserved, unservedLayout)

	// The pre-queue length gate, which is where RoutineReceiveIncoming drops a
	// handshake before it costs a queue slot.
	if device.acceptsInitiationSize(len(packet)) {
		t.Errorf("the device admits a %d byte initiation it serves no suite for", len(packet))
	}
	if _, _, ok := device.suiteForInitiationSize(len(packet)); ok {
		t.Error("a suite was routed for a length no accepted suite produces")
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("an initiation for an unserved suite cost %d scalar multiplications, want 0", n)
	}

	/* Under load the responder answers an initiation carrying no cookie with a
	 * cookie reply. That reply is a response, so it tells a sender only what a
	 * response tells it, and reaching it requires a valid mac1 and therefore
	 * the responder's static public key. What must not happen is that it costs
	 * asymmetric work, because then a cookie, whose purpose is to make a
	 * sender prove its address before the responder spends anything, would
	 * cost the thing it exists to defer. */
	device.rate.underLoadUntil.Store(time.Now().Add(time.Minute).UnixNano())
	if !device.IsUnderLoad() {
		t.Fatal("the device does not report being under load, so the cookie path is not being tested")
	}
	served, _ := device.localSuite()
	servedPacket := forgedInitiation(t, devicePublicKey(device), served, mustLayout(t, served))
	calls.Store(0)
	if device.cookieChecker.CheckMAC2(served, servedPacket, []byte{1}) {
		t.Error("mac2 verified on a packet carrying no cookie")
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("the cookie path cost %d scalar multiplications, want 0", n)
	}

	/* The control. The same bytes, once the suite is accepted, must route,
	 * verify and reach the one scalar multiplication. Without this the zero
	 * above would be consistent with the packet being malformed, and the test
	 * would be asserting nothing about the accept set. */
	if _, err := device.AcceptSuite([]byte(sha384SuiteName), []byte(LegacyIdentifier)); err != nil {
		t.Fatalf("accepting the suite that was only resolved: %v", err)
	}
	countSharedSecrets(t, device, &calls)
	calls.Store(0)

	recvSuite, recvLayout, ok := device.suiteForInitiationSize(len(packet))
	if !ok {
		t.Fatal("the same length does not route even once its suite is accepted")
	}
	if !device.cookieChecker.CheckMAC1(recvSuite, packet) {
		t.Fatal("mac1 on the same bytes is rejected once the suite is accepted")
	}
	msg, err := recvLayout.ParseInitiation(packet)
	if err != nil {
		t.Fatalf("parsing the same bytes under the now accepted suite: %v", err)
	}
	if peer := device.ConsumeMessageInitiation(recvSuite, msg); peer != nil {
		t.Fatal("a forged initiation was consumed as a valid one")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the same bytes cost %d scalar multiplications once served, want 1", n)
	}
}

// mustLayout derives a suite's layout or fails the test.
func mustLayout(tb testing.TB, s *suite.Suite) wire.Layout {
	tb.Helper()
	layout, err := wire.LayoutFor(s)
	if err != nil {
		tb.Fatalf("LayoutFor %q: %v", s.Name(), err)
	}
	return layout
}
