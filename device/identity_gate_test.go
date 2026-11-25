/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/suite"
	"golang.zx2c4.com/wireguard/suitestd"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wire"
)

// foreignCurveSuiteName names a suite on a curve the deployed identity cannot
// use.
//
// P-384 public keys are 97 bytes against P-256's 65, so such a suite also
// frames messages of its own lengths. That is what makes a stale accept-set
// entry cost something rather than merely being inert: it holds a
// message-length routing slot and swallows every handshake of that length.
const foreignCurveSuiteName = ":P-384:HKDF-SHA-384:AEAD_AES_256_GCM"

// registerP384ForTest makes P-384 resolvable, which is how a test reaches a
// curve the wolfCrypt backend does not register.
//
// Like registerChaCha20ForTest it registers one primitive rather than calling
// suitestd.Register(), which would also replace P-256, HKDF-SHA-256 and
// AEAD_AES_256_GCM and so move every other test in this binary off wolfCrypt
// while still claiming to exercise the FIPS backend. P-384 is a name nothing
// else here uses, so adding it displaces nothing.
func registerP384ForTest(tb testing.TB) {
	tb.Helper()
	suite.RegisterKEX(suitestd.NameP384, suitestd.P384KEX())
}

// keylessDevice is a device that has not been given a private key.
//
// This is the state a device is in partway through a UAPI set operation, and
// the state the identity gate cannot judge a suite in.
func keylessDevice(tb testing.TB) *Device {
	tb.Helper()
	tun := tuntest.NewChannelTUN()
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelSilent, ""))
	tb.Cleanup(device.Close)
	return device
}

// TestSetPrivateKeyDropsSuitesTheIdentityCannotServe covers the gap in the
// identity gate.
//
// staticIdentityUsableWith admits any suite while the device has no private
// key, which it has to: peers and suites may be configured before the key, and
// there is nothing to judge them against yet. The gate therefore has to run
// again when the key arrives. It used to check only the suite the device
// initiates with, so a suite on a foreign curve stayed in the accept set
// against an identity it could never serve.
//
// That is worse than a suite that merely never completes a handshake. Inbound
// handshakes are routed by message length, so the entry swallows every packet
// of its length and, through the collision guard, blocks a usable suite of the
// same length from being accepted at all.
func TestSetPrivateKeyDropsSuitesTheIdentityCannotServe(t *testing.T) {
	registerP384ForTest(t)

	device := keylessDevice(t)

	foreign, err := device.AcceptSuite([]byte(foreignCurveSuiteName), []byte(LegacyIdentifier))
	if err != nil {
		t.Fatalf("accepting a suite before the private key: %v", err)
	}
	foreignLayout, err := wire.LayoutFor(foreign)
	if err != nil {
		t.Fatalf("LayoutFor: %v", err)
	}
	if !device.acceptsInitiationSize(foreignLayout.InitiationSize()) {
		t.Fatal("the suite was not accepted at all, so this test proves nothing")
	}
	if foreignLayout.InitiationSize() == deployedInitiationSize() {
		t.Fatalf("the foreign suite frames %d byte initiations like the deployed one, so it holds no slot of its own",
			foreignLayout.InitiationSize())
	}

	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	if err := device.SetPrivateKey(sk); err != nil {
		t.Fatalf("SetPrivateKey: %v", err)
	}

	accepted, local := device.suiteConfig()
	for _, name := range accepted {
		if name == foreignCurveSuiteName {
			t.Errorf("%q is still accepted against an identity that cannot serve it", name)
		}
	}
	if device.acceptsInitiationSize(foreignLayout.InitiationSize()) {
		t.Errorf("a %d byte initiation still routes, so the dropped suite kept its slot",
			foreignLayout.InitiationSize())
	}

	/* Dropping the unusable suite must not cost the usable one. The key change
	 * succeeds, so the device has to come out of it serving what it can. */
	if local != LegacyHandshakeName {
		t.Errorf("local suite = %q, want %q", local, LegacyHandshakeName)
	}
	if !device.acceptsInitiationSize(deployedInitiationSize()) {
		t.Error("the deployed suite stopped being served")
	}
}

// TestUAPIAcceptSuiteBeforePrivateKey is the reachable form of the gap.
//
// The UAPI applies device lines in the order they arrive, so accept_suite
// before private_key in one set operation is ordinary input rather than a
// contrived sequence, and it is the order wg-quick writes.
//
// The set operation has to succeed. Refusing the whole configuration because
// one accept-set entry turned out not to fit would leave an operator unable to
// install a key at all, so the unusable suite is dropped and the key is set.
func TestUAPIAcceptSuiteBeforePrivateKey(t *testing.T) {
	registerP384ForTest(t)

	device := keylessDevice(t)

	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}

	if err := device.IpcSet(uapiCfg(
		"accept_suite", foreignCurveSuiteName,
		"private_key", hex.EncodeToString(sk.Bytes()),
	)); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	accepted, local := device.suiteConfig()
	for _, name := range accepted {
		if name == foreignCurveSuiteName {
			t.Errorf("%q survived the private_key line that cannot serve it", name)
		}
	}
	if local != LegacyHandshakeName {
		t.Errorf("local suite = %q, want %q", local, LegacyHandshakeName)
	}
	if !device.acceptsInitiationSize(deployedInitiationSize()) {
		t.Error("the device does not serve the deployed suite after the set operation")
	}
}
