// Command gengolden captures the handshake wire format produced by the device
// package's encoding/binary marshalling, which is the format deployed peers
// speak, and compares it against the golden file the wire package's tests use
// as their oracle.
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
// changing, the thing to find out is why device's output moved, not to record
// the new output. The message sizes are additionally asserted in the tests
// against the values the protocol actually uses, so drift has to defeat both.
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
	var init device.MessageInitiation
	init.Type = device.MessageInitiationType
	init.Sender = 0x11223344
	fill(init.Ephemeral[:], 0x40)
	fill(init.Static[:], 0x80)
	fill(init.Timestamp[:], 0xC0)
	fill(init.MAC1[:], 0x10)
	fill(init.MAC2[:], 0x20)

	var resp device.MessageResponse
	resp.Type = device.MessageResponseType
	resp.Sender = 0x55667788
	resp.Receiver = 0x99aabbcc
	fill(resp.Ephemeral[:], 0x40)
	fill(resp.Empty[:], 0x70)
	fill(resp.MAC1[:], 0x10)
	fill(resp.MAC2[:], 0x20)

	var g golden
	g.Note = "Captured from device's encoding/binary marshalling by " +
		"wire/internal/gengolden. This is the format deployed peers speak; the " +
		"wire package must reproduce it byte for byte."

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
		fmt.Fprintf(os.Stderr, "gengolden: capturing the wire format: %v\n", err)
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
	if !bytes.Equal(bytes.TrimSpace(onDisk), bytes.TrimSpace(encoded)) {
		fmt.Fprintf(os.Stderr,
			"gengolden: %s does not match what device produces.\n"+
				"The wire format moved. Establish why before running -write: rewriting moves the oracle.\n",
			goldenPath)
		os.Exit(1)
	}
	fmt.Printf("gengolden: %s matches device (initiation %d, response %d bytes)\n",
		goldenPath, got.Initiation.Size, got.Response.Size)
}
