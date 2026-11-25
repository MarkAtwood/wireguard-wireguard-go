// Command gengolden marshals the deployed handshake layout, frozen by
// declaration in this file, with encoding/binary, and compares the result
// against the golden file the wire package's tests use as their oracle.
//
// The layout lives here rather than being captured from the device package so
// that the oracle cannot be derived from the code it judges. device's message
// types are aliases for the wire package's, whose fields are slices sized from
// the cipher suite: encoding/binary cannot marshal those, and if it could, a
// capture from device would be the wire codec checking itself. Declaring the
// fixed-size arrays here instead pins the layout to what deployed peers speak,
// so it holds still when a size constant elsewhere moves.
//
// It lives in its own main package on purpose. The wire package's tests must
// not import device, because device will import wire, and a test binary
// containing that pair would be an import cycle. A separate command can import
// device freely, since nothing imports the command.
//
// By default it VERIFIES and fails on any difference. Pass -write to rewrite
// the golden file.
//
// Rewriting moves the oracle, so it is a deliberate act and not a remedy for a
// failing test. If the bytes changed without the wire format deliberately
// changing, the thing to find out is why the codec's output moved, not to
// record the new output. The message sizes are additionally asserted in the
// tests against the values the protocol actually uses, so drift has to defeat
// both.
//
// Regenerate with:
//
//	go generate ./wire/...
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/device"
)

// The lengths below are the deployed build's, written as literals because they
// are frozen by what is on the wire. Importing the constants they came from
// would let a change there move the oracle silently, which is the one thing
// this command exists to catch. They were, in device/noise-protocol.go:
//
//	publicKeyLen  = NoisePublicKeySize            = 65
//	tagLen        = wolfSSL.AES_BLOCK_SIZE        = 16 (AEAD tag)
//	timestampLen  = tai64n.TimestampSize          = 12
//	macLen        = wolfSSL.WC_SHA256_DIGEST_SIZE = 32
const (
	publicKeyLen = 65
	tagLen       = 16
	timestampLen = 12
	macLen       = 32
)

// messageInitiation and messageResponse are the deployed layouts, field for
// field and in order. Only sizes and order reach the wire, so these are the
// whole of what is being frozen.
type messageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral [publicKeyLen]byte
	Static    [publicKeyLen + tagLen]byte
	Timestamp [timestampLen + tagLen]byte
	MAC1      [macLen]byte
	MAC2      [macLen]byte
}

type messageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral [publicKeyLen]byte
	Empty     [tagLen]byte
	MAC1      [macLen]byte
	MAC2      [macLen]byte
}

// goldenPath is relative to the wire package directory, which is where
// go:generate runs this command.
const goldenPath = "testdata/golden_wire.json"

// golden is the on-disk shape. Sizes are recorded beside the bytes so a
// reviewer reading a diff sees a layout change without counting hex digits.
type golden struct {
	Note       string  `json:"note"`
	Initiation message `json:"initiation"`
	Response   message `json:"response"`
}

type message struct {
	Size int    `json:"size"`
	Hex  string `json:"hex"`
}

// fill writes an ascending pattern so every field's offset and length is
// visible in the recorded bytes.
func fill(b []byte, start byte) {
	for i := range b {
		b[i] = start + byte(i)
	}
}

func capture() (golden, error) {
	var init messageInitiation
	init.Type = device.MessageInitiationType
	init.Sender = 0x11223344
	fill(init.Ephemeral[:], 0x40)
	fill(init.Static[:], 0x80)
	fill(init.Timestamp[:], 0xC0)
	fill(init.MAC1[:], 0x10)
	fill(init.MAC2[:], 0x20)

	var resp messageResponse
	resp.Type = device.MessageResponseType
	resp.Sender = 0x55667788
	resp.Receiver = 0x99aabbcc
	fill(resp.Ephemeral[:], 0x40)
	fill(resp.Empty[:], 0x70)
	fill(resp.MAC1[:], 0x10)
	fill(resp.MAC2[:], 0x20)

	var g golden
	g.Note = "The deployed handshake layout, frozen as fixed-size arrays in " +
		"wire/internal/gengolden and marshalled there with encoding/binary. " +
		"This is the format deployed peers speak; the wire package must " +
		"reproduce it byte for byte."

	// The device constants are deliberately still the expected sizes: they are
	// staying in device, and if they ever move away from the frozen layout
	// that disagreement is exactly what should fail here.
	for _, m := range []struct {
		v    any
		out  *message
		want int
	}{
		{init, &g.Initiation, device.MessageInitiationSize},
		{resp, &g.Response, device.MessageResponseSize},
	} {
		var buf bytes.Buffer
		if err := binary.Write(&buf, binary.LittleEndian, m.v); err != nil {
			return g, fmt.Errorf("marshalling %T: %w", m.v, err)
		}
		if buf.Len() != m.want {
			return g, fmt.Errorf("marshalled %T to %d bytes, the package constant says %d",
				m.v, buf.Len(), m.want)
		}
		m.out.Size = buf.Len()
		m.out.Hex = hex.EncodeToString(buf.Bytes())
	}
	return g, nil
}

func main() {
	write := flag.Bool("write", false, "rewrite the golden file instead of verifying it")
	flag.Parse()

	got, err := capture()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gengolden: marshalling the frozen wire format: %v\n", err)
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "gengolden: encoding: %v\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')

	if *write {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "gengolden: creating %s: %v\n", filepath.Dir(goldenPath), err)
			os.Exit(1)
		}
		if err := os.WriteFile(goldenPath, encoded, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "gengolden: writing %s: %v\n", goldenPath, err)
			os.Exit(1)
		}
		fmt.Printf("gengolden: wrote %s (initiation %d, response %d bytes)\n",
			goldenPath, got.Initiation.Size, got.Response.Size)
		return
	}

	onDisk, err := os.ReadFile(goldenPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gengolden: reading %s: %v\nRun with -write to create it.\n", goldenPath, err)
		os.Exit(1)
	}
	// Compare the recorded messages, not the serialized file: the note is prose
	// about the oracle, so editing it must not read as the wire format moving.
	var recorded golden
	if err := json.Unmarshal(onDisk, &recorded); err != nil {
		fmt.Fprintf(os.Stderr, "gengolden: parsing %s: %v\n", goldenPath, err)
		os.Exit(1)
	}
	if recorded.Initiation != got.Initiation || recorded.Response != got.Response {
		fmt.Fprintf(os.Stderr,
			"gengolden: %s does not match the frozen deployed layout.\n"+
				"The wire format moved. Establish why before running -write: rewriting moves the oracle.\n",
			goldenPath)
		os.Exit(1)
	}
	fmt.Printf("gengolden: %s matches the frozen deployed layout (initiation %d, response %d bytes)\n",
		goldenPath, got.Initiation.Size, got.Response.Size)
}
