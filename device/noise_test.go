/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"testing"

	wolfSSL "github.com/wolfssl/go-wolfssl"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := newPrivateKey(testKEX())
	assertNil(t, err)

	sk2, err := newPrivateKey(testKEX())
	assertNil(t, err)

	pk1 := sk1.publicKeyOrFatal(t)
	pk2 := sk2.publicKeyOrFatal(t)

	ss1, err1 := sk1.sharedSecret(testKEX(), pk2)
	ss2, err2 := sk2.sharedSecret(testKEX(), pk1)

	if err1 != nil || err2 != nil {
		t.Fatalf("Failed to compute shared secret: %v, %v", err1, err2)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatalf("the two directions disagree: %x and %x", ss1, ss2)
	}
	if len(ss1) == 0 {
		t.Fatal("the shared secret is empty")
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey(testKEX())
	if err != nil {
		t.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun.TUN(), conn.NewDefaultBind(), logger)
	device.SetPrivateKey(sk)
	return device
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func assertIntEqual(t *testing.T, a, b int) {
	if a != b {
		t.Fatal(a, "!=", b)
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKeyOrFatal(t))
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.next.Load()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var out []byte
		var nonce [12]byte

		aes := wolfSSL.Wc_AesAllocAligned()
		wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
		wolfSSL.Wc_AesGcmSetKey(aes, key1.send[:], len(key1.send[:]))
		out, _ = wolfSSL.Wc_AesGcm_Appended_Tag_Encrypt(aes, out, testMsg, nonce[:], nil)
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)

		aes = wolfSSL.Wc_AesAllocAligned()
		wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
		wolfSSL.Wc_AesGcmSetKey(aes, key2.receive[:], len(key2.receive[:]))
		ret := wolfSSL.Wc_AesGcm_Appended_Tag_Decrypt(aes, out, out, nonce[:], nil)
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)

		assertIntEqual(t, ret, 0)
		assertEqual(t, out[:len(out)-wolfSSL.AES_BLOCK_SIZE], testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var out []byte
		var nonce [12]byte

		aes := wolfSSL.Wc_AesAllocAligned()
		wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
		wolfSSL.Wc_AesGcmSetKey(aes, key2.send[:], len(key2.send[:]))
		out, _ = wolfSSL.Wc_AesGcm_Appended_Tag_Encrypt(aes, out, testMsg, nonce[:], nil)
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)

		aes = wolfSSL.Wc_AesAllocAligned()
		wolfSSL.Wc_AesInit(aes, nil, wolfSSL.INVALID_DEVID)
		wolfSSL.Wc_AesGcmSetKey(aes, key1.receive[:], len(key1.receive[:]))
		ret := wolfSSL.Wc_AesGcm_Appended_Tag_Decrypt(aes, out, out, nonce[:], nil)
		wolfSSL.Wc_AesFree(aes)
		wolfSSL.Wc_AesFreeAllocAligned(aes)

		assertIntEqual(t, ret, 0)
		assertEqual(t, out[:len(out)-wolfSSL.AES_BLOCK_SIZE], testMsg)
	}()
}
