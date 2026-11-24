/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"errors"
	"fmt"

	wolfSSL "github.com/wolfssl/go-wolfssl"
)

const (
	// NoiseMaxPublicKeySize and NoiseMaxPrivateKeySize bound the key material
	// of any suite this build can resolve. P-384 is the largest registered key
	// exchange: 97 bytes uncompressed, with a 48 byte scalar.
	//
	// Keys are stored in arrays of this size and carry their real length, so a
	// key remains comparable and can be a map key, while the crypto only ever
	// sees the bytes that are actually part of the key. Storing the maximum
	// costs memory per peer and nothing on the wire.
	NoiseMaxPublicKeySize  = 97
	NoiseMaxPrivateKeySize = 48

	// NoisePublicKeySize and NoisePrivateKeySize are the sizes this build's
	// suite uses, P-256. They remain the sizes new keys are created at until
	// per-peer suite selection exists; at that point the length comes from the
	// peer's suite instead.
	NoisePublicKeySize  = 65
	NoisePrivateKeySize = 32

	NoisePresharedKeySize = 32
)

// errKeySize is reported when key material does not match the length its suite
// prescribes.
var errKeySize = errors.New("key length does not match the suite")

// errNoSuite is reported when a peer is given no suite to use.
var errNoSuite = errors.New("no cipher suite")

type (
	// NoisePublicKey is a public key of any suite's key exchange.
	//
	// It is a comparable value, so it still works as a map key and still passes
	// by value, which is how the rest of the package uses it. Bytes is the only
	// way to reach the key material, so no caller can accidentally hand the
	// zero padding to a hash or a key exchange.
	NoisePublicKey struct {
		b [NoiseMaxPublicKeySize]byte
		n int
	}

	// NoisePrivateKey is a private key of any suite's key exchange.
	NoisePrivateKey struct {
		b [NoiseMaxPrivateKeySize]byte
		n int
	}

	// NoisePresharedKey is the optional pre-shared symmetric key. Its length is
	// fixed by the protocol rather than by the suite, so it stays an array.
	NoisePresharedKey [NoisePresharedKeySize]byte

	NoiseNonce uint64 // padded to 12-bytes
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

// Bytes returns the key material, without the storage padding.
//
// The slice aliases the key's own storage, so it must not be modified. Every
// hash, MAC and key exchange input goes through here.
func (key NoisePublicKey) Bytes() []byte { return key.b[:key.n] }

// Len is the key's length in bytes.
func (key NoisePublicKey) Len() int { return key.n }

// SetBytes installs key material of any length a suite may use.
//
// The storage beyond the key is zeroed, which is required rather than tidy: a
// NoisePublicKey is used as a map key, so two keys holding the same material
// must compare equal, and stale bytes past the length would break that.
func (key *NoisePublicKey) SetBytes(b []byte) error {
	if len(b) == 0 || len(b) > NoiseMaxPublicKeySize {
		return fmt.Errorf("public key is %d bytes, the maximum is %d: %w",
			len(b), NoiseMaxPublicKeySize, errKeySize)
	}
	key.b = [NoiseMaxPublicKeySize]byte{}
	copy(key.b[:], b)
	key.n = len(b)
	return nil
}

func (key *NoisePublicKey) FromHex(src string) error {
	// Until a peer carries its suite, a configured public key is this build's
	// size. The length check moves to the suite when that lands.
	buf := make([]byte, NoisePublicKeySize)
	if err := loadExactHex(buf, src); err != nil {
		return err
	}
	return key.SetBytes(buf)
}

func (key NoisePublicKey) IsZero() bool {
	if key.n == 0 {
		return true
	}
	var zero NoisePublicKey
	if err := zero.SetBytes(make([]byte, key.n)); err != nil {
		return false
	}
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	if key.n != tar.n {
		return false
	}
	return wolfSSL.ConstantCompare(key.Bytes(), tar.Bytes(), key.n) == 1
}

// Bytes returns the key material, without the storage padding.
func (key NoisePrivateKey) Bytes() []byte { return key.b[:key.n] }

// Len is the key's length in bytes.
func (key NoisePrivateKey) Len() int { return key.n }

// SetBytes installs key material of any length a suite may use.
func (key *NoisePrivateKey) SetBytes(b []byte) error {
	if len(b) == 0 || len(b) > NoiseMaxPrivateKeySize {
		return fmt.Errorf("private key is %d bytes, the maximum is %d: %w",
			len(b), NoiseMaxPrivateKeySize, errKeySize)
	}
	key.b = [NoiseMaxPrivateKeySize]byte{}
	copy(key.b[:], b)
	key.n = len(b)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	if key.n == 0 {
		return true
	}
	var zero NoisePrivateKey
	if err := zero.SetBytes(make([]byte, key.n)); err != nil {
		return false
	}
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	if key.n != tar.n {
		return false
	}
	return wolfSSL.ConstantCompare(key.Bytes(), tar.Bytes(), key.n) == 1
}

func (key *NoisePrivateKey) FromHex(src string) (err error) {
	buf := make([]byte, NoisePrivateKeySize)
	if err := loadExactHex(buf, src); err != nil {
		return err
	}
	return key.SetBytes(buf)
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = key.FromHex(src)
	if key.IsZero() {
		return
	}
	return
}

// publicKeyFromWire reads a fixed-size wire field into a length-carrying key.
//
// Transitional, paired with wireArray: it exists only while the message structs
// still hold fixed-size fields.
func publicKeyFromWire(a [NoisePublicKeySize]byte) (pk NoisePublicKey, err error) {
	err = pk.SetBytes(a[:])
	return
}

// wireArray copies the key into the fixed-size field the legacy
// encoding/binary message structs carry.
//
// Transitional. The wire package encodes a message from the suite's layout
// instead, at which point these fixed fields and this method go away. A key
// longer than the field is truncated by copy, which cannot happen while every
// key is this build's single size, and which is why the fields must not outlive
// the switch to the wire package.
func (key NoisePublicKey) wireArray() [NoisePublicKeySize]byte {
	var a [NoisePublicKeySize]byte
	copy(a[:], key.Bytes())
	return a
}

// clear zeroes the key material in place.
func (key *NoisePublicKey) clear() {
	setZero(key.b[:])
	key.n = 0
}

// clear zeroes the key material in place.
func (key *NoisePrivateKey) clear() {
	setZero(key.b[:])
	key.n = 0
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}
