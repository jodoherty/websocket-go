package ws

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzReadFrame is a safety fuzz target for the frame decoder: arbitrary
// byte streams must never panic, index out of range, or loop forever —
// they may only produce a frame or an error. Run with:
//
//	go test ./ws -run '' -fuzz FuzzReadFrame -fuzztime 30s
func FuzzReadFrame(f *testing.F) {
	// Seeds: the RFC 6455 §5.7 examples, truncated forms, and control frames.
	seed := [][]byte{
		{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f},
		{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
		{0x81},                 // truncated header
		{0x81, 0x7e, 0x00},     // truncated 16-bit length
		{0x81, 0x7e, 0xff, 0xff, 0x48}, // length longer than payload
		{0x80, 0x00},           // continuation without start
		{0x82, 0x00},           // empty binary
		{0x89, 0x80},           // ping, no mask (client side violation)
		{0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58},
		{0x83, 0x00},           // reserved opcode
		{0x81, 0x03, 0x48, 0x65, 0x6c},
		{},
	}
	for _, s := range seed {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Exercise both sides of the masking rule on the same input. The
		// codec is a pure function of its stream: no connection state,
		// so this targets exactly the byte-level decoding logic.
		for _, isClient := range []bool{true, false} {
			fc := &frameCodec{
				br:       bufio.NewReader(bytes.NewReader(data)),
				isClient: isClient,
				maxMsg:   1 << 20,
			}
			// A single readFrame call may not panic; it returns either a
			// frame or an error.
			_, _ = fc.readFrame()
		}
	})
}
