/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// deployedInitiationSize is the length of the deployed suite's initiation,
// taken from the struct this package freezes as the deployed wire format rather
// than from the layout the device computes, so that a device claiming not to
// serve the deployed suite any more is being measured against the format a peer
// in the field actually sends.
func deployedInitiationSize() int { return binary.Size(deployedInitiation{}) }

// deployedResponseSize is the same for the deployed suite's response.
func deployedResponseSize() int { return binary.Size(deployedResponse{}) }

// legacyDynamicName names the deployed suite's primitives in registry
// vocabulary. It therefore produces messages of exactly the deployed suite's
// lengths while being a different handshake name, which is the collision the
// accept set has to refuse.
const legacyDynamicName = ":P-256:HKDF-SHA-256:AEAD_AES_256_GCM"

// uapiDeviceLines returns the device-level lines of a UAPI get response, which
// are the ones before the first peer begins.
func uapiDeviceLines(tb testing.TB, conf string) []string {
	tb.Helper()
	lines := strings.Split(strings.TrimRight(conf, "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			return lines[:i]
		}
	}
	return lines
}

// uapiValues collects the values a key carries, in the order they appear.
func uapiValues(lines []string, key string) []string {
	var out []string
	for _, line := range lines {
		if name, value, ok := strings.Cut(line, "="); ok && name == key {
			out = append(out, value)
		}
	}
	return out
}

// uapiSuiteLines reduces a UAPI get response to the suite configuration it
// reports, as a set operation.
//
// The whole response is not a set operation and never was: it also carries
// read-only statistics such as tx_bytes and last_handshake_time_sec, which the
// set path refuses as unknown keys, and a listen_port that a second device
// cannot bind. What has to re-apply is the configuration, so that is what is
// extracted: the device's accept set and local suite, and each peer's identity
// and pinned suite. public_key is kept because it is what opens a peer section,
// so a pinned suite without it would be read as a device line.
func uapiSuiteLines(conf string) string {
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimRight(conf, "\n"), "\n") {
		switch key, _, _ := strings.Cut(line, "="); key {
		case "accept_suite", "local_suite", "public_key", "suite":
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// peerLine formats the UAPI lines that configure one peer.
func peerLine(tb testing.TB, pk NoisePublicKey, extra ...string) string {
	tb.Helper()
	return "public_key=" + hex.EncodeToString(pk.Bytes()) + "\n" +
		strings.Join(append(extra, ""), "\n")
}

// TestUAPIConfiguresAMigration is the orchestrator's half of the migration,
// driven entirely over the configuration surface: one device accepts a second
// suite while continuing to initiate with the deployed one, and a single peer
// is moved onto the new suite.
//
// Nothing here calls AcceptSuite or SetSuite. The suites, the peers and the
// pin all arrive as UAPI text, which is what an orchestrator can actually
// send, and the assertion is a completed handshake under the new suite's
// cryptography. That is an oracle outside the configuration code: the two ends
// agree on a transcript, or they do not.
func TestUAPIConfiguresAMigration(t *testing.T) {
	initiator := randDevice(t)
	defer initiator.Close()
	responder := randDevice(t)
	defer responder.Close()

	initiatorPub := initiator.staticIdentity.privateKey.publicKeyOrFatal(t)
	responderPub := responder.staticIdentity.privateKey.publicKeyOrFatal(t)

	/* The responder serves both suites and keeps initiating with the deployed
	 * one, which is the state every device in the fleet is in during the
	 * migration window. */
	if err := responder.IpcSet("accept_suite=" + sha384SuiteName + "\n" +
		peerLine(t, initiatorPub)); err != nil {
		t.Fatalf("configuring the responder: %v", err)
	}

	/* The initiator accepts the new suite and this one peer is moved onto it.
	 * Accepting is not optional on the initiating side either: the response
	 * comes back framed under the new suite and is routed by its length. */
	if err := initiator.IpcSet("accept_suite=" + sha384SuiteName + "\n" +
		peerLine(t, responderPub, "suite="+sha384SuiteName)); err != nil {
		t.Fatalf("configuring the initiator: %v", err)
	}

	peerOfResponder := initiator.LookupPeer(responderPub)
	peerOfInitiator := responder.LookupPeer(initiatorPub)
	if peerOfResponder == nil || peerOfInitiator == nil {
		t.Fatal("the configuration did not create both peers")
	}
	peerOfResponder.Start()
	peerOfInitiator.Start()
	defer peerOfResponder.Stop()
	defer peerOfInitiator.Stop()

	used := exchange(t, initiator, responder, peerOfResponder, peerOfInitiator)

	if got := used.NewHash().Size(); got != 48 {
		t.Errorf("the handshake ran under a %d byte hash, want 48", got)
	}
	if got, want := string(used.Name()), sha384SuiteName; got != want {
		t.Errorf("the handshake ran under %q, want %q", got, want)
	}

	/* The responder was never moved, so a second peer of its own still
	 * initiates with the deployed suite. Both populations are live at once,
	 * which is the property the migration window depends on. */
	unmoved, err := responder.NewPeer(newTestPublicKey(t))
	if err != nil {
		t.Fatalf("NewPeer: %v", err)
	}
	s, _ := unmoved.suiteFor()
	if got, want := string(s.Name()), LegacyHandshakeName; got != want {
		t.Errorf("an unmoved peer initiates with %q, want %q", got, want)
	}
}

// TestUAPIReportsTheSuiteConfiguration checks that what a device reports is
// what an orchestrator can send back, which is the property the whole surface
// rests on: a device's state has to be readable, or a migration cannot be
// resumed or audited.
func TestUAPIReportsTheSuiteConfiguration(t *testing.T) {
	device := randDevice(t)
	defer device.Close()

	pinned := newTestPublicKey(t)
	if err := device.IpcSet("accept_suite=" + sha384SuiteName + "\n" +
		"local_suite=" + sha384SuiteName + "\n" +
		peerLine(t, pinned, "suite="+LegacyHandshakeName)); err != nil {
		t.Fatalf("configuring the device: %v", err)
	}

	conf, err := device.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	t.Logf("reported configuration:\n%s", conf)

	/* The expected contents are written out here rather than read back from
	 * the device, so this is an oracle and not a restatement. */
	deviceLines := uapiDeviceLines(t, conf)
	/* Sorted, so the dynamic name comes first: ":" is below "N" in ASCII. */
	if got, want := uapiValues(deviceLines, "accept_suite"),
		[]string{sha384SuiteName, LegacyHandshakeName}; !equalStrings(got, want) {
		t.Errorf("accept set reported as %q, want %q", got, want)
	}
	if got, want := uapiValues(deviceLines, "local_suite"), []string{sha384SuiteName}; !equalStrings(got, want) {
		t.Errorf("local suite reported as %q, want %q", got, want)
	}
	if got, want := uapiValues(strings.Split(conf, "\n"), "suite"), []string{LegacyHandshakeName}; !equalStrings(got, want) {
		t.Errorf("the peer's pinned suite reported as %q, want %q", got, want)
	}

	/* The reported local suite has to come after the line that accepts it,
	 * because local_suite is refused for a suite that is not yet accepted.
	 * Order is part of the representation, not a cosmetic detail. */
	if strings.Index(conf, "local_suite=") < strings.Index(conf, "accept_suite="+sha384SuiteName) {
		t.Error("local_suite is reported before the accept_suite line it depends on")
	}

	/* And the suite configuration re-applies to a fresh device, which is what
	 * an orchestrator does when it restores or clones one. A reported suite
	 * that could not be sent back would make the surface readable but not
	 * resumable. */
	restored := randDevice(t)
	defer restored.Close()
	if err := restored.IpcSet(uapiSuiteLines(conf)); err != nil {
		t.Fatalf("re-applying the reported suite configuration: %v", err)
	}
	again, err := restored.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet after re-applying: %v", err)
	}
	if got, want := uapiSuiteLines(again), uapiSuiteLines(conf); got != want {
		t.Errorf("re-applying the suite configuration changed it:\n%s\nbecame\n%s", want, got)
	}
}

// TestUAPIRefusesUnservableConfiguration covers the refusals, which are the
// load-bearing part of this surface.
//
// Every case here is a configuration a device could hold while being unable to
// act on it. Accepted silently, each one produces a device that initiates
// handshakes it can never complete, with nothing in its configuration to say
// why, and the failure appears as an unreachable peer rather than as a
// rejected configuration line.
func TestUAPIRefusesUnservableConfiguration(t *testing.T) {
	pinnedPeer := newTestPublicKey(t)

	for _, c := range []struct {
		name string
		// setup is applied first and must succeed.
		setup string
		// conf is the configuration under test and must be refused.
		conf string
		want error
	}{
		{
			name: "initiating with a suite that is not accepted",
			conf: "local_suite=" + sha384SuiteName + "\n",
			want: errSuiteNotAccepted,
		},
		{
			name: "pinning a peer to a suite that is not accepted",
			conf: peerLine(t, pinnedPeer, "suite="+sha384SuiteName),
			want: errSuiteNotAccepted,
		},
		{
			name: "dropping the suite this device initiates with",
			conf: "unaccept_suite=" + LegacyHandshakeName + "\n",
			want: errSuiteInForce,
		},
		{
			name:  "dropping a suite a peer is pinned to",
			setup: "accept_suite=" + sha384SuiteName + "\n" + peerLine(t, pinnedPeer, "suite="+sha384SuiteName),
			conf:  "unaccept_suite=" + sha384SuiteName + "\n",
			want:  errSuiteInForce,
		},
		{
			name: "dropping a suite that was never accepted",
			conf: "unaccept_suite=" + sha384SuiteName + "\n",
			want: errSuiteNotAccepted,
		},
		/* A second suite of the deployed suite's lengths used to be refused
		 * here, because a length router could not tell the two apart. It is
		 * accepted now: an initiation carries its suite's name, so identical
		 * framing is no longer ambiguous. The case is kept in
		 * TestAcceptSuiteAdmitsSamePrimitivesUnderADynamicName, where it
		 * asserts that both suites are servable at once. */
	} {
		t.Run(c.name, func(t *testing.T) {
			device := randDevice(t)
			defer device.Close()

			if c.setup != "" {
				if err := device.IpcSet(c.setup); err != nil {
					t.Fatalf("setup: %v", err)
				}
			}

			err := device.IpcSet(c.conf)
			if !errors.Is(err, c.want) {
				t.Fatalf("IpcSet error = %v, want %v", err, c.want)
			}

			/* A refused line must also leave the device able to serve what it
			 * already had, rather than half-applied. */
			if !device.acceptsInitiationSize(deployedInitiationSize()) {
				t.Error("the device no longer serves the suite it was already configured for")
			}
		})
	}
}

// TestUAPIRetiresTheDeployedSuite is the last step of a migration, which is the
// step that determines whether the surface is a migration surface at all: once
// every peer has moved, the device stops serving the old suite.
//
// The oracle is that the device goes on completing handshakes under the new
// suite while refusing the old suite's message length outright, which is what
// the receive path decides on before it knows who is speaking.
func TestUAPIRetiresTheDeployedSuite(t *testing.T) {
	initiator := randDevice(t)
	defer initiator.Close()
	responder := randDevice(t)
	defer responder.Close()

	initiatorPub := initiator.staticIdentity.privateKey.publicKeyOrFatal(t)
	responderPub := responder.staticIdentity.privateKey.publicKeyOrFatal(t)

	/* Accept, then move the device's own default, then retire. That order is
	 * forced: the deployed suite cannot be dropped while it is still the one
	 * this device initiates with. */
	retire := "accept_suite=" + sha384SuiteName + "\n" +
		"local_suite=" + sha384SuiteName + "\n" +
		"unaccept_suite=" + LegacyHandshakeName + "\n"

	for _, d := range []*Device{initiator, responder} {
		if err := d.IpcSet(retire); err != nil {
			t.Fatalf("retiring the deployed suite: %v", err)
		}
		if d.acceptsInitiationSize(deployedInitiationSize()) {
			t.Errorf("the device still serves a %d byte initiation after retiring the deployed suite",
				deployedInitiationSize())
		}
		/* Both directions. A retired suite that kept its response-length slot
		 * would leave the device admitting packets it can no longer route, and
		 * would hold maxHandshakeSize at the retired suite's length for the
		 * life of the device, oversizing every handshake receive buffer. */
		if d.acceptsResponseSize(deployedResponseSize()) {
			t.Errorf("the device still serves a %d byte response after retiring the deployed suite",
				deployedResponseSize())
		}
		if got := d.maxHandshakeSize(); got == deployedInitiationSize() {
			t.Errorf("maxHandshakeSize is still the retired suite's %d bytes", got)
		}
	}

	if err := responder.IpcSet(peerLine(t, initiatorPub)); err != nil {
		t.Fatalf("configuring the responder's peer: %v", err)
	}
	if err := initiator.IpcSet(peerLine(t, responderPub)); err != nil {
		t.Fatalf("configuring the initiator's peer: %v", err)
	}

	peerOfResponder := initiator.LookupPeer(responderPub)
	peerOfInitiator := responder.LookupPeer(initiatorPub)
	if peerOfResponder == nil || peerOfInitiator == nil {
		t.Fatal("the configuration did not create both peers")
	}
	peerOfResponder.Start()
	peerOfInitiator.Start()
	defer peerOfResponder.Stop()
	defer peerOfInitiator.Stop()

	/* Neither peer is pinned. They run under the new suite because it is the
	 * device's own now, which is what retiring the old one means. */
	used := exchange(t, initiator, responder, peerOfResponder, peerOfInitiator)
	if got, want := string(used.Name()), sha384SuiteName; got != want {
		t.Errorf("the handshake ran under %q, want %q", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
