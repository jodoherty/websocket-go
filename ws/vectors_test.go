package ws

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// Test vectors taken verbatim from RFC 6455. These pin the implementation to
// the spec rather than to itself: if acceptKey or the frame codec drift from
// the RFC in a self-consistent way (client and server wrong the same way),
// these tests catch it.

// RFC 6455 §1.3: the canonical handshake example.
func TestRFC6455AcceptKey(t *testing.T) {
	got := acceptKey("dGhlIHNhbXBsZSBub25jZQ==")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Fatalf("acceptKey = %q, want %q (RFC 6455 §1.3)", got, want)
	}
}

// fakeAddr satisfies net.Addr.
type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// fakeConn is a net.Conn whose reads come from data and whose writes are
// discarded — enough to drive readFrame/writeFrameLocked without a real
// socket.
type fakeConn struct{ data []byte; off int }

func (f *fakeConn) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}
func (f *fakeConn) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeConn) Close() error                { return nil }
func (f *fakeConn) LocalAddr() net.Addr         { return fakeAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr        { return fakeAddr{} }
func (f *fakeConn) SetDeadline(time.Time) error { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// newTestConn builds a Conn whose read side is served from data. isClient
// selects which side of the masking rule applies: as the client we expect
// unmasked frames from the (server) peer; as the server we expect masked
// frames from the (client) peer.
func newTestConn(data []byte, isClient bool) *Conn {
	fc := &fakeConn{data: data}
	return newConn(fc, fc, isClient, 1<<20, 0)
}

// newTestCodec is the codec-level equivalent: decode frames from data with
// the given side of the masking rule. No connection state involved.
func newTestCodec(data []byte, isClient bool) *frameCodec {
	return &frameCodec{br: bufio.NewReader(bytes.NewReader(data)), isClient: isClient, maxMsg: 1 << 20}
}

// RFC 6455 §5.7 examples.
func TestRFC6455Frames(t *testing.T) {
	t.Parallel()

	// A single-frame unmasked text message: "Hello".
	c := newTestCodec([]byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}, true)
	f, err := c.readFrame()
	if err != nil || f.opcode != OpText || !f.fin || string(f.payload) != "Hello" {
		t.Fatalf("unmasked text: (%+v, %v), want text \"Hello\"", f, err)
	}

	// A single-frame masked text message: "Hello".
	// (We are the server here, so we expect the client's frame to be masked.)
	c = newTestCodec([]byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}, false)
	f, err = c.readFrame()
	if err != nil || f.opcode != OpText || !f.fin || string(f.payload) != "Hello" {
		t.Fatalf("masked text: (%+v, %v), want text \"Hello\"", f, err)
	}

	// A fragmented unmasked text message: "Hel" + "lo" → "Hello".
	cConn := newTestConn([]byte{
		0x01, 0x03, 0x48, 0x65, 0x6c, // "Hel", fin=0
		0x80, 0x02, 0x6c, 0x6f,       // "lo", fin=1
	}, true)
	op, data, err := cConn.ReadMessage()
	if err != nil || op != OpText || string(data) != "Hello" {
		t.Fatalf("fragmented text: (%d, %q, %v), want text \"Hello\"", op, data, err)
	}

	// Unmasked ping / masked pong (RFC 6455 §5.7): ping is answered inline
	// with a pong matching the body, and ReadMessage never sees either.
	cConn = newTestConn([]byte{
		0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f, // ping "Hello" (unmasked, from server side)
	}, true)
	// Consume the ping by feeding the next frame, an EOF: ReadMessage must
	// have consumed the ping without returning it.
	_, _, err = cConn.ReadMessage()
	if err == nil {
		t.Fatal("ReadMessage after a lone ping should hit EOF, got nil")
	}

	// 256-byte binary message, 16-bit length form.
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	var buf []byte
	buf = append(buf, 0x82, 0x7e, 0x01, 0x00)
	buf = append(buf, payload...)
	c = newTestCodec(buf, true)
	f, err = c.readFrame()
	if err != nil || f.opcode != OpBinary || !bytes.Equal(f.payload, payload) {
		t.Fatalf("256-byte binary: op=%d len=%d err=%v", f.opcode, len(f.payload), err)
	}

	// 64KiB binary message, 64-bit length form.
	big := make([]byte, 65536)
	for i := range big {
		big[i] = byte(i % 251)
	}
	buf = []byte{0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	buf = append(buf, big...)
	c = newTestCodec(buf, true)
	f, err = c.readFrame()
	if err != nil || f.opcode != OpBinary || !bytes.Equal(f.payload, big) {
		t.Fatalf("64KiB binary: op=%d len=%d err=%v", f.opcode, len(f.payload), err)
	}
}

// TestFrameCodecRoundtrip hammers the encoder/decoder against each other:
// every frame the writer produces must decode identically, on both sides of
// the masking rule.
func TestFrameCodecRoundtrip(t *testing.T) {
	t.Parallel()
	for _, isClient := range []bool{true, false} {
		for _, n := range []int{0, 1, 124, 125, 126, 127, 128, 255, 256, 65535, 65536, 65537, 1 << 20} {
			payload := make([]byte, n)
			for i := range payload {
				payload[i] = byte(i * 31 + 7)
			}
			for op := range [3]int{OpText, OpBinary, OpPing} {
				if op >= 8 && n > 125 {
					continue // control frames max at 125
				}

				var sink bytes.Buffer
				wc := frameCodec{bw: bufio.NewWriterSize(&sink, 16), isClient: isClient, maxMsg: 1 << 20}
				if err := wc.writeFrame(op, payload); err != nil {
					t.Fatalf("write (%v, %d, %d): %v", isClient, op, n, err)
				}

				rc := newTestCodec(sink.Bytes(), !isClient) // peer side: masking expectation flipped
				f, err := rc.readFrame()
				if err != nil {
					t.Fatalf("read (%v, %d, %d): %v", isClient, op, n, err)
				}
				if f.opcode != op || !f.fin || !bytes.Equal(f.payload, payload) {
					t.Fatalf("roundtrip mismatch for (isClient=%v op=%d len=%d)", isClient, op, n)
				}
			}
		}
	}
}
