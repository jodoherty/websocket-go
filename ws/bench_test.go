package ws

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

// discardW is a writer that throws data away; it lets the write benchmarks
// measure framing, not the sink.
type discardW struct{}

func (discardW) Write(p []byte) (int, error) { return len(p), nil }

// encodeOneFrame encodes one frame off-timer so the read benchmarks can
// loop over a fixed input.
func encodeOneFrame(b *testing.B, isClient bool, payload []byte) []byte {
	b.Helper()
	var buf bytes.Buffer
	fc := &frameCodec{bw: bufio.NewWriterSize(&buf, 16<<10), isClient: isClient, maxMsg: 1 << 20}
	if err := fc.writeFrame(OpText, payload); err != nil {
		b.Fatalf("encodeOneFrame: %v", err)
	}
	return buf.Bytes()
}

// BenchmarkFrameCodecWrite measures encoding one 1 KiB text frame, on both
// sides of the masking rule (the client side does a random mask + XOR copy,
// the server side writes the payload directly).
func BenchmarkFrameCodecWrite(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	for name, isClient := range map[string]bool{
		"ClientMasked": true,
		"ServerPlain":  false,
	} {
		b.Run(name, func(b *testing.B) {
			fc := &frameCodec{bw: bufio.NewWriterSize(discardW{}, 16<<10), isClient: isClient, maxMsg: 1 << 20}
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := fc.writeFrame(OpText, payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFrameCodecRead measures decoding one 1 KiB text frame, again on
// both sides of the masking rule.
func BenchmarkFrameCodecRead(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	for name, isClient := range map[string]bool{
		"ClientReadsPlain":  true,  // we are the client: peer frames are unmasked
		"ServerReadsMasked": false, // we are the server: peer frames are masked
	} {
		encoded := encodeOneFrame(b, !isClient, payload) // the peer's encoding
		b.Run(name, func(b *testing.B) {
			br := bufio.NewReaderSize(bytes.NewReader(encoded), 16<<10)
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fc := &frameCodec{br: br, isClient: isClient, maxMsg: 1 << 20}
				f, err := fc.readFrame()
				if err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(f.payload, payload) {
					b.Fatal("payload mismatch")
				}
				br.Reset(bytes.NewReader(encoded))
			}
		})
	}
}

// BenchmarkConnRoundTrip measures the steady-state per-message cost across
// the stack: client WriteMessage → wire bytes → server ReadMessage over an
// in-memory pipe. The synchronous pipe makes each write block until the
// server has read it, so the loop is a true round trip without any
// bookkeeping channel; one pipe pair serves the whole benchmark.
func BenchmarkConnRoundTrip(b *testing.B) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	sr, cr := net.Pipe()
	server := newConn(sr, sr, false, 1<<20, 0, 0)
	client := newConn(cr, cr, true, 1<<20, 0, 0)
	defer client.Close(StatusNormalClosure, "")
	defer server.Close(StatusNormalClosure, "")

	go func() {
		for i := 0; i < b.N; i++ {
			op, data, err := server.ReadMessage()
			if err != nil || op != OpText || !bytes.Equal(data, payload) {
				b.Errorf("server read %d: op=%d err=%v", i, op, err)
				return
			}
		}
	}()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := client.WriteMessage(OpText, payload); err != nil {
			b.Fatalf("client write %d: %v", i, err)
		}
	}
	b.StopTimer()
	// Let the server finish its last read before the teardown close.
	// (The synchronous pipe already guarantees each write was consumed.)
}

// BenchmarkAcceptKey measures the handshake accept-key computation. It is
// SHA-1 over ~36 bytes, so it should be far cheaper than any frame work —
// a regression here would point at an accidental allocation or copy.
func BenchmarkAcceptKey(b *testing.B) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = acceptKey(key)
	}
}
