/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"strconv"
	"testing"

	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/wire"
)

func TestCookieMAC1(t *testing.T) {
	// setup generator / checker

	var (
		generator CookieGenerator
		checker   CookieChecker
	)

	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.publicKeyOrFatal(t)

	generator.Init(pk)
	checker.Init(pk)

	/* The suite supplies the MAC and its length. These vectors are the
	 * deployed suite's, so this is also the check that making the cookie MACs
	 * suite-driven did not change a single byte for it. */
	s := testLegacySuite(t)

	// check mac1

	src := []byte{192, 168, 13, 37, 10, 10, 10}

	checkMAC1 := func(msg []byte) {
		if err := generator.AddMacs(s, msg); err != nil {
			t.Fatal("AddMacs:", err)
		}
		if !checker.CheckMAC1(s, msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if checker.CheckMAC2(s, msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}
	}

	checkMAC1([]byte{
		0x99, 0xbb, 0xa5, 0xfc, 0x99, 0xaa, 0x83, 0xbd,
		0x7b, 0x00, 0xc5, 0x9a, 0x4c, 0xb9, 0xcf, 0x62,
		0x40, 0x23, 0xf3, 0x8e, 0xd8, 0xd0, 0x62, 0x64,
		0x5d, 0xb2, 0x80, 0x13, 0xda, 0xce, 0xc6, 0x91,
		0x61, 0xd6, 0x30, 0xf1, 0x32, 0xb3, 0xa2, 0xf4,
		0x7b, 0x43, 0xb5, 0xa7, 0xe2, 0xb1, 0xf5, 0x6c,
		0x74, 0x6b, 0xb0, 0xcd, 0x1f, 0x94, 0x86, 0x7b,
		0xc8, 0xfb, 0x92, 0xed, 0x54, 0x9b, 0x44, 0xf5,
		0xc8, 0x7d, 0xb7, 0x8e, 0xff, 0x49, 0xc4, 0xe8,
		0x39, 0x7c, 0x19, 0xe0, 0x60, 0x19, 0x51, 0xf8,
		0xe4, 0x8e, 0x02, 0xf1, 0x7f, 0x1d, 0xcc, 0x8e,
		0xb0, 0x07, 0xff, 0xf8, 0xaf, 0x7f, 0x66, 0x82,
		0x83, 0xcc, 0x7c, 0xfa, 0x80, 0xdb, 0x81, 0x53,
		0xad, 0xf7, 0xd8, 0x0c, 0x10, 0xe0, 0x20, 0xfd,
		0xe8, 0x0b, 0x3f, 0x90, 0x15, 0xcd, 0x93, 0xad,
		0x0b, 0xd5, 0x0c, 0xcc, 0x88, 0x56, 0xe4, 0x3f,
	})

	checkMAC1([]byte{
		0x33, 0xe7, 0x2a, 0x84, 0x9f, 0xff, 0x57, 0x6c,
		0x2d, 0xc3, 0x2d, 0xe1, 0xf5, 0x5c, 0x97, 0x56,
		0xb8, 0x93, 0xc2, 0x7d, 0xd4, 0x41, 0xdd, 0x7a,
		0x4a, 0x59, 0x3b, 0x50, 0xdd, 0x7a, 0x7a, 0x8c,
		0x9b, 0x96, 0xaf, 0x55, 0x3c, 0xeb, 0x6d, 0x0b,
		0x13, 0x0b, 0x97, 0x98, 0xb3, 0x40, 0xc3, 0xcc,
		0xb8, 0x57, 0x33, 0x45, 0x6e, 0x8b, 0x09, 0x2b,
		0x81, 0x2e, 0xd2, 0xb9, 0x66, 0x0b, 0x93, 0x05,
	})

	// exchange cookie reply

	func() {
		msg := []byte{
			0x6d, 0xd7, 0xc3, 0x2e, 0xb0, 0x76, 0xd8, 0xdf,
			0x30, 0x65, 0x7d, 0x62, 0x3e, 0xf8, 0x9a, 0xe8,
			0xe7, 0x3c, 0x64, 0xa3, 0x78, 0x48, 0xda, 0xf5,
			0x25, 0x61, 0x28, 0x53, 0x79, 0x32, 0x86, 0x9f,
			0xa0, 0x27, 0x95, 0x69, 0xb6, 0xba, 0xd0, 0xa2,
			0xf8, 0x68, 0xea, 0xa8, 0x62, 0xf2, 0xfd, 0x1b,
			0xe0, 0xb4, 0x80, 0xe5, 0x6b, 0x3a, 0x16, 0x9e,
			0x35, 0xf6, 0xa8, 0xf2, 0x4f, 0x9a, 0x7b, 0xe9,
			0x77, 0x0b, 0xc2, 0xb4, 0xed, 0xba, 0xf9, 0x22,
			0xc3, 0x03, 0x97, 0x42, 0x9f, 0x79, 0x74, 0x27,
			0xfe, 0xf9, 0x06, 0x6e, 0x97, 0x3a, 0xa6, 0x8f,
			0xc9, 0x57, 0x0a, 0x54, 0x4c, 0x64, 0x4a, 0xe2,
			0x4f, 0xa1, 0xce, 0x95, 0x9b, 0x23, 0xa9, 0x2b,
			0x85, 0x93, 0x42, 0xb0, 0xa5, 0x53, 0xed, 0xeb,
			0x63, 0x2a, 0xf1, 0x6d, 0x46, 0xcb, 0x2f, 0x61,
			0x8c, 0xe1, 0xe8, 0xfa, 0x67, 0x20, 0x80, 0x6d,
		}
		if err := generator.AddMacs(s, msg); err != nil {
			t.Fatal("AddMacs:", err)
		}
		reply, err := checker.CreateReply(s, msg, 1377, src)
		if err != nil {
			t.Fatal("Failed to create cookie reply:", err)
		}
		if !generator.ConsumeReply(s, reply) {
			t.Fatal("Failed to consume cookie reply")
		}
	}()

	// check mac2

	checkMAC2 := func(msg []byte) {
		if err := generator.AddMacs(s, msg); err != nil {
			t.Fatal("AddMacs:", err)
		}

		if !checker.CheckMAC1(s, msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if !checker.CheckMAC2(s, msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}

		msg[5] ^= 0x20

		if checker.CheckMAC1(s, msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if checker.CheckMAC2(s, msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}

		msg[5] ^= 0x20

		srcBad1 := []byte{192, 168, 13, 37, 40, 1}
		if checker.CheckMAC2(s, msg, srcBad1) {
			t.Fatal("MAC2 generation/verification failed")
		}

		srcBad2 := []byte{192, 168, 13, 38, 40, 1}
		if checker.CheckMAC2(s, msg, srcBad2) {
			t.Fatal("MAC2 generation/verification failed")
		}
	}

	checkMAC2([]byte{
		0x03, 0x31, 0xb9, 0x9e, 0xb0, 0x2a, 0x54, 0xa3,
		0xc1, 0x3f, 0xb4, 0x96, 0x16, 0xb9, 0x25, 0x15,
		0x3d, 0x3a, 0x82, 0xf9, 0x58, 0x36, 0x86, 0x3f,
		0x13, 0x2f, 0xfe, 0xb2, 0x53, 0x20, 0x8c, 0x3f,
		0xba, 0xeb, 0xfb, 0x4b, 0x1b, 0x22, 0x02, 0x69,
		0x2c, 0x90, 0xbc, 0xdc, 0xcf, 0xcf, 0x85, 0xeb,
		0x62, 0x66, 0x6f, 0xe8, 0xe1, 0xa6, 0xa8, 0x4c,
		0xa0, 0x04, 0x23, 0x15, 0x42, 0xac, 0xfa, 0x38,
	})

	checkMAC2([]byte{
		0x0e, 0x2f, 0x0e, 0xa9, 0x29, 0x03, 0xe1, 0xf3,
		0x24, 0x01, 0x75, 0xad, 0x16, 0xa5, 0x66, 0x85,
		0xca, 0x66, 0xe0, 0xbd, 0xc6, 0x34, 0xd8, 0x84,
		0x09, 0x9a, 0x58, 0x14, 0xfb, 0x05, 0xda, 0xf5,
		0x90, 0xf5, 0x0c, 0x4e, 0x22, 0x10, 0xc9, 0x85,
		0x0f, 0xe3, 0x77, 0x35, 0xe9, 0x6b, 0xc2, 0x55,
		0x32, 0x46, 0xae, 0x25, 0xe0, 0xe3, 0x37, 0x7a,
		0x4b, 0x71, 0xcc, 0xfc, 0x91, 0xdf, 0xd6, 0xca,
		0xfe, 0xee, 0xce, 0x3f, 0x77, 0xa2, 0xfd, 0x59,
		0x8e, 0x73, 0x0a, 0x8d, 0x5c, 0x24, 0x14, 0xca,
		0x38, 0x91, 0xb8, 0x2c, 0x8c, 0xa2, 0x65, 0x7b,
		0xbc, 0x49, 0xbc, 0xb5, 0x58, 0xfc, 0xe3, 0xd7,
		0x02, 0xcf, 0xf7, 0x4c, 0x60, 0x91, 0xed, 0x55,
		0xe9, 0xf9, 0xfe, 0xd1, 0x44, 0x2c, 0x75, 0xf2,
		0xb3, 0x5d, 0x7b, 0x27, 0x56, 0xc0, 0x48, 0x4f,
		0xb0, 0xba, 0xe4, 0x7d, 0xd0, 0xaa, 0xcd, 0x3d,
		0xe3, 0x50, 0xd2, 0xcf, 0xb9, 0xfa, 0x4b, 0x2d,
		0xc6, 0xdf, 0x3b, 0x32, 0x98, 0x45, 0xe6, 0x8f,
		0x1c, 0x5c, 0xa2, 0x20, 0x7d, 0x1c, 0x28, 0xc2,
		0xd4, 0xa1, 0xe0, 0x21, 0x52, 0x8f, 0x1c, 0xd0,
		0x62, 0x97, 0x48, 0xbb, 0xf4, 0xa9, 0xcb, 0x35,
		0xf2, 0x07, 0xd3, 0x50, 0xd8, 0xa9, 0xc5, 0x9a,
		0x0f, 0xbd, 0x37, 0xaf, 0xe1, 0x45, 0x19, 0xee,
		0x41, 0xf3, 0xf7, 0xe5, 0xe0, 0x30, 0x3f, 0xbe,
		0x3d, 0x39, 0x64, 0x00, 0x7a, 0x1a, 0x51, 0x5e,
		0xe1, 0x70, 0x0b, 0xb9, 0x77, 0x5a, 0xf0, 0xc4,
		0x8a, 0xa1, 0x3a, 0x77, 0x1a, 0xe0, 0xc2, 0x06,
		0x91, 0xd5, 0xe9, 0x1c, 0xd3, 0xfe, 0xab, 0x93,
		0x1a, 0x0a, 0x4c, 0xbb, 0xf0, 0xff, 0xdc, 0xaa,
		0x61, 0x73, 0xcb, 0x03, 0x4b, 0x71, 0x68, 0x64,
		0x3d, 0x82, 0x31, 0x41, 0xd7, 0x8b, 0x22, 0x7b,
		0x7d, 0xa1, 0xd5, 0x85, 0x6d, 0xf0, 0x1b, 0xaa,
	})
}

// TestCookieRejectsMessagesTooShortForItsMACs covers the only behaviour the
// suite-sized cookie MACs added that the deployed code did not have.
//
// Every offset in cookie.go is measured backwards from the end of the packet,
// so a message that cannot hold the suite's two MAC fields would slice out of
// range. The deployed code had no such check and panicked.
//
// No production caller can reach the guard. receive.go settles the suite from
// the packet's length before any MAC is touched, so a packet arriving at
// CheckMAC1 is exactly an InitiationSize or ResponseSize, both of which are
// 8 or 12 header bytes plus a key and ciphertext beyond their two MAC fields;
// AddMacs is only ever handed a buffer the layout has just sized. The guard is
// kept because these are exported methods whose length precondition cannot be
// stated in their signatures, and what it prevents is a panic in a receive
// goroutine rather than a dropped packet. Asserting it here is what stops it
// being untested code: a future caller added without the length dispatch is
// rejected, not fatal.
func TestCookieRejectsMessagesTooShortForItsMACs(t *testing.T) {
	s := testLegacySuite(t)
	macSize := s.NewHash().Size()

	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.publicKeyOrFatal(t)

	var (
		generator CookieGenerator
		checker   CookieChecker
	)
	generator.Init(pk)
	checker.Init(pk)

	src := []byte{192, 168, 13, 37}

	for _, n := range []int{0, 1, macSize, 2*macSize - 1} {
		t.Run(strconv.Itoa(n)+" bytes", func(t *testing.T) {
			msg := make([]byte, n)
			if err := generator.AddMacs(s, msg); err == nil {
				t.Error("AddMacs accepted a message too short for two mac fields")
			}
			if checker.CheckMAC1(s, msg) {
				t.Error("CheckMAC1 accepted a message too short for two mac fields")
			}
			if checker.CheckMAC2(s, msg, src) {
				t.Error("CheckMAC2 accepted a message too short for two mac fields")
			}
			if _, err := checker.CreateReply(s, msg, 1, src); err == nil {
				t.Error("CreateReply accepted a message too short for two mac fields")
			}
		})
	}

	// The boundary is admissible rather than rejected: two MAC fields and
	// nothing else is the shortest message the offsets can describe, and the
	// shortest vector above is exactly that length.
	exact := make([]byte, 2*macSize)
	if err := generator.AddMacs(s, exact); err != nil {
		t.Errorf("AddMacs refused a message of exactly two mac fields: %v", err)
	}
	if !checker.CheckMAC1(s, exact) {
		t.Error("CheckMAC1 rejected a message of exactly two mac fields")
	}
}

// testSuite resolves a suite by handshake name the way a device does, so it
// carries its name, its precomputed initial state and its layout.
func testSuite(tb testing.TB, name string) (*suite.Suite, wire.Layout) {
	tb.Helper()

	var device Device
	device.log = NewLogger(LogLevelSilent, "")
	if err := device.initSuites(); err != nil {
		tb.Fatalf("initSuites: %v", err)
	}
	s, err := device.AcceptSuite([]byte(name), []byte(LegacyIdentifier))
	if err != nil {
		tb.Fatalf("accepting %q: %v", name, err)
	}
	layout, err := wire.LayoutFor(s)
	if err != nil {
		tb.Fatalf("LayoutFor %q: %v", name, err)
	}
	return s, layout
}

// TestCookieReplyIsFramedAndSealedBySuite runs a cookie reply end to end under
// two suites whose AEADs differ.
//
// Before this the reply was a fixed 72 bytes sealed with AES-GCM called
// directly, so a suite naming ChaCha20-Poly1305 had its cookie encrypted with
// a cipher its name did not mention, which is the defect the transport phase
// had before the suite drove it. The deployed suite must still produce exactly
// 72 bytes, or a reply stops being recognised in the field.
//
// The oracle for the cookie surviving the AEAD is not the reply itself. The
// generator opens the reply and MACs with what it recovered; the checker
// recomputes the cookie from its own rotating secret and verifies that MAC. The
// checker never sees the generator's copy, so mac2 verifying is two
// independent derivations of the cookie meeting.
func TestCookieReplyIsFramedAndSealedBySuite(t *testing.T) {
	registerChaCha20ForTest(t)

	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.publicKeyOrFatal(t)
	src := []byte{192, 168, 13, 37}

	for _, c := range []struct {
		label     string
		name      string
		wantReply int
		wantNonce int
	}{
		{"deployed", LegacyHandshakeName, 72, 16},
		{"chacha20", chachaSuiteName, 68, 12},
	} {
		t.Run(c.label, func(t *testing.T) {
			s, layout := testSuite(t, c.name)

			var (
				generator CookieGenerator
				checker   CookieChecker
			)
			generator.Init(pk)
			checker.Init(pk)

			/* An initiation-shaped message, MAC'd so the generator holds the
			 * mac1 the reply is bound to. */
			msg := make([]byte, layout.InitiationSize())
			if err := generator.AddMacs(s, msg); err != nil {
				t.Fatalf("AddMacs: %v", err)
			}
			if checker.CheckMAC2(s, msg, src) {
				t.Fatal("mac2 verified before any cookie had been issued")
			}

			const sender = uint32(0x01020304)
			reply, err := checker.CreateReply(s, msg, sender, src)
			if err != nil {
				t.Fatalf("CreateReply: %v", err)
			}
			if got := len(reply.Nonce); got != c.wantNonce {
				t.Errorf("the reply's nonce is %d bytes, the suite's aead takes %d", got, c.wantNonce)
			}

			packet, err := layout.AppendCookieReply(nil, reply)
			if err != nil {
				t.Fatalf("AppendCookieReply: %v", err)
			}
			if len(packet) != c.wantReply {
				t.Errorf("the encoded reply is %d bytes, want %d", len(packet), c.wantReply)
			}

			/* Decoded the way the receive path decodes it: the index out of the
			 * bytes alone, then the body under the peer's layout. */
			if got, ok := wire.CookieReplyReceiver(packet); !ok || got != sender {
				t.Errorf("CookieReplyReceiver = %d, %v; want %d, true", got, ok, sender)
			}
			decoded, err := layout.ParseCookieReply(packet)
			if err != nil {
				t.Fatalf("ParseCookieReply: %v", err)
			}

			if !generator.ConsumeReply(s, decoded) {
				t.Fatal("the initiator could not open the cookie reply")
			}

			if err := generator.AddMacs(s, msg); err != nil {
				t.Fatalf("AddMacs after the cookie: %v", err)
			}
			if !checker.CheckMAC2(s, msg, src) {
				t.Error("mac2 does not verify under the cookie the reply carried")
			}
		})
	}

	/* The two AES suites frame identical 72 byte replies, so nothing about the
	 * packet separates them. What separates them is the encryption key, which
	 * is derived with the suite's own hash. This is the case that makes routing
	 * a reply by its length impossible and routing it by index necessary. */
	t.Run("identically framed replies do not open under each other", func(t *testing.T) {
		a, aLayout := testSuite(t, LegacyHandshakeName)
		b, bLayout := testSuite(t, sha384SuiteName)
		if aLayout.CookieReplySize() != bLayout.CookieReplySize() {
			t.Fatalf("the suites frame %d and %d byte replies, so this is not the case being tested",
				aLayout.CookieReplySize(), bLayout.CookieReplySize())
		}

		var (
			generator CookieGenerator
			checker   CookieChecker
		)
		generator.Init(pk)
		checker.Init(pk)

		msg := make([]byte, aLayout.InitiationSize())
		if err := generator.AddMacs(a, msg); err != nil {
			t.Fatalf("AddMacs: %v", err)
		}
		reply, err := checker.CreateReply(a, msg, 7, src)
		if err != nil {
			t.Fatalf("CreateReply: %v", err)
		}

		if generator.ConsumeReply(b, reply) {
			t.Error("a reply sealed under one suite opened under another of identical framing")
		}
		if !generator.ConsumeReply(a, reply) {
			t.Error("the same reply did not open under its own suite either, so the check above proves nothing")
		}
	})
}
