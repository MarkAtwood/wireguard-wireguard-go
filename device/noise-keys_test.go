/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"
)

// TestKeyLengthsAfterGeneration pins the lengths that key material carries once
// keys hold their own length rather than inheriting it from an array type.
//
// It exists because the generation path hands wolfCrypt a buffer and trusts the
// returned length: offering a buffer larger than the key, which is what storing
// keys at the maximum size requires, means a length that is not updated leaves
// the key holding trailing zeros as though they were part of it.
func TestKeyLengthsAfterGeneration(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	if got := sk.Len(); got != NoisePrivateKeySize {
		t.Errorf("private key length = %d, want %d", got, NoisePrivateKeySize)
	}
	if sk.IsZero() {
		t.Error("newPrivateKey returned a zero key")
	}

	pk := sk.publicKey()
	if got := pk.Len(); got != NoisePublicKeySize {
		t.Errorf("public key length = %d, want %d; the export length was not honoured", got, NoisePublicKeySize)
	}
	if pk.IsZero() {
		t.Error("publicKey returned a zero key")
	}
	if got := len(pk.Bytes()); got != pk.Len() {
		t.Errorf("Bytes() is %d bytes but Len() is %d", got, pk.Len())
	}

	// A P-256 public key in X9.63 uncompressed form begins with 0x04. Checking
	// it catches a key that was stored at the wrong offset or length.
	if b := pk.Bytes(); b[0] != 0x04 {
		t.Errorf("public key starts with %#02x, want 0x04 for an uncompressed point", b[0])
	}
}

// TestKeyRoundTripIsStable checks that deriving a public key twice from the same
// private key gives the same bytes, which fails if a length is being read from
// uninitialised storage.
func TestKeyRoundTripIsStable(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	first, second := sk.publicKey(), sk.publicKey()
	if !first.Equals(second) {
		t.Errorf("publicKey is not deterministic: %x then %x", first.Bytes(), second.Bytes())
	}
}

// TestSetBytesZeroesPadding is required for correctness, not tidiness: a public
// key is a map key, so two keys holding the same material must compare equal
// even if one of them previously held something longer.
func TestSetBytesZeroesPadding(t *testing.T) {
	long := bytes.Repeat([]byte{0xAA}, NoiseMaxPublicKeySize)
	short := bytes.Repeat([]byte{0xBB}, 32)

	var reused NoisePublicKey
	if err := reused.SetBytes(long); err != nil {
		t.Fatalf("SetBytes(long): %v", err)
	}
	if err := reused.SetBytes(short); err != nil {
		t.Fatalf("SetBytes(short): %v", err)
	}

	var fresh NoisePublicKey
	if err := fresh.SetBytes(short); err != nil {
		t.Fatalf("SetBytes(fresh): %v", err)
	}

	if reused != fresh {
		t.Error("a reused key does not compare equal to a fresh one holding the same material; stale padding survived")
	}
	if !reused.Equals(fresh) {
		t.Error("Equals disagrees for the same material")
	}
}

func TestSetBytesRejectsUnusableLengths(t *testing.T) {
	var pk NoisePublicKey
	if err := pk.SetBytes(nil); err == nil {
		t.Error("SetBytes accepted an empty key")
	}
	if err := pk.SetBytes(make([]byte, NoiseMaxPublicKeySize+1)); err == nil {
		t.Error("SetBytes accepted a key larger than the maximum")
	}

	var sk NoisePrivateKey
	if err := sk.SetBytes(make([]byte, NoiseMaxPrivateKeySize+1)); err == nil {
		t.Error("SetBytes accepted a private key larger than the maximum")
	}
}

// TestKeysOfDifferentLengthAreNotEqual guards the comparison: material that
// happens to be a prefix of another key must not compare equal to it.
func TestKeysOfDifferentLengthAreNotEqual(t *testing.T) {
	var short, long NoisePublicKey
	if err := short.SetBytes(bytes.Repeat([]byte{0x01}, 32)); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	if err := long.SetBytes(bytes.Repeat([]byte{0x01}, 65)); err != nil {
		t.Fatalf("SetBytes: %v", err)
	}
	if short.Equals(long) {
		t.Error("keys of different lengths compared equal")
	}
	if short == long {
		t.Error("keys of different lengths are == equal, so they would collide as map keys")
	}
}
