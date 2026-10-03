package ws

import (
	"bufio"
	"bytes"
	"testing"
)

// These tests pin the per-frame allocation budget so a regression (an
// escaped buffer, a fresh copy, a new slice somewhere) fails CI instead of
// silently raising GC pressure on every message:
//
//   - writeFrame: 0 allocations in steady state. All per-frame buffers are
//     per-connection scratch (see frameCodec); the masked copy is reused.
//   - readFrame: exactly 1 allocation — the payload, which the caller owns
//     and therefore cannot be pooled.

func encodeFrameForBudget(t *testing.T, isClient bool, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fc := frameCodec{bw: bufio.NewWriter(&buf), isClient: isClient, maxMsg: 1 << 20}
	if err := fc.writeFrame(OpText, payload); err != nil {
		t.Fatalf("encodeFrameForBudget: %v", err)
	}
	return buf.Bytes()
}

func TestWriteFrameAllocationBudget(t *testing.T) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	for name, isClient := range map[string]bool{
		"masked": true,
		"plain":  false,
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			fc := frameCodec{bw: bufio.NewWriter(&buf), isClient: isClient, maxMsg: 1 << 20}
			// Warm up so the masked-write scratch is already sized; the
			// budget is the steady-state per-frame cost.
			if err := fc.writeFrame(OpText, payload); err != nil {
				t.Fatal(err)
			}
			if n := testing.AllocsPerRun(100, func() {
				if err := fc.writeFrame(OpText, payload); err != nil {
					t.Fatal(err)
				}
			}); n != 0 {
				t.Fatalf("writeFrame: %v allocs/op, want 0", n)
			}
		})
	}
}

func TestReadFrameAllocationBudget(t *testing.T) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	for name, isClient := range map[string]bool{
		"client reads plain":  true,
		"server reads masked": false,
	} {
		encoded := encodeFrameForBudget(t, !isClient, payload)
		t.Run(name, func(t *testing.T) {
			src := bytes.NewReader(encoded)
			fc := frameCodec{br: bufio.NewReader(src), isClient: isClient, maxMsg: 1 << 20}
			f, err := fc.readFrame()
			if err != nil || !bytes.Equal(f.payload, payload) {
				t.Fatalf("setup read: %v", err)
			}
			// The reader resets are allocation-free (verified by
			// MemStats), so only readFrame's own allocations are measured.
			if n := testing.AllocsPerRun(100, func() {
				src.Reset(encoded)
				fc.br.Reset(src)
				f, err := fc.readFrame()
				if err != nil || !bytes.Equal(f.payload, payload) {
					t.Fatal(err)
				}
			}); n != 1 {
				t.Fatalf("readFrame: %v allocs/op, want 1 (the payload)", n)
			}
		})
	}
}
