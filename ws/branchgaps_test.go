package ws

// This file closes the branch-coverage gaps reported by
// cmd/branchcov: the error outcomes that the main suites exercise only
// from one direction (missing header vs. wrong header, oversized read vs.
// oversized write, first fragment vs. fragment chain, ...).

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// failWriteConn is a net.Conn whose Write always fails. It exists to reach
// the write-failure branches that a healthy transport cannot produce.
type failWriteConn struct{}

func (failWriteConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (failWriteConn) Write(_ []byte) (int, error) { return 0, errors.New("simulated write failure") }
func (failWriteConn) SetReadDeadline(time.Time) error {
	return nil
}
func (failWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (failWriteConn) SetDeadline(time.Time) error      { return nil }
func (failWriteConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (failWriteConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (failWriteConn) Close() error                     { return nil }

// errDeadlineConn is a net.Conn whose SetReadDeadline always fails, to
// reach the armIdle error branch.
type errDeadlineConn struct{}

func (errDeadlineConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (errDeadlineConn) Write(_ []byte) (int, error) {
	return 0, io.EOF
}
func (errDeadlineConn) SetReadDeadline(time.Time) error {
	return errors.New("simulated deadline failure")
}
func (errDeadlineConn) SetWriteDeadline(time.Time) error { return nil }
func (errDeadlineConn) SetDeadline(time.Time) error      { return nil }
func (errDeadlineConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (errDeadlineConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (errDeadlineConn) Close() error                     { return nil }

// TestWriteMessageValidationBranches pins the two write-side rejections:
// only OpText/OpBinary may be written, and only messages within
// MaxMessageSize.
func TestWriteMessageValidationBranches(t *testing.T) {
	// Validation fires before any I/O, so a never-writable transport is
	// fine (and proves no frame was written).
	c := newRawConn(failWriteConn{}, failWriteConn{}, true, 1<<20, 0, 0)

	writeErr := c.WriteMessage(OpPing, nil)
	if writeErr == nil || !errors.Is(writeErr, errProtocol) {
		t.Fatalf("WriteMessage(OpPing) = %v, want errProtocol", writeErr)
	}

	// A message one byte over the limit must be rejected before any
	// frame is written.
	limited := newRawConn(failWriteConn{}, failWriteConn{}, true, 16, 0, 0)
	writeErr = limited.WriteMessage(OpText, make([]byte, 17))
	if writeErr == nil || !errors.Is(writeErr, errMessageTooBig) {
		t.Fatalf("WriteMessage over MaxMessageSize = %v, want errMessageTooBig", writeErr)
	}
}

// deadlineRecordConn is a net.Conn that records every write-deadline
// change, to pin the per-frame write-bound invariant of WriteMessage.
type deadlineRecordConn struct {
	deadlines []time.Time
}

func (d *deadlineRecordConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (d *deadlineRecordConn) Write(_ []byte) (int, error) { return 0, io.EOF }
func (d *deadlineRecordConn) SetReadDeadline(_ time.Time) error {
	return nil
}
func (d *deadlineRecordConn) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}
func (d *deadlineRecordConn) SetDeadline(_ time.Time) error { return nil }
func (d *deadlineRecordConn) LocalAddr() net.Addr           { return fakeAddr{} }
func (d *deadlineRecordConn) RemoteAddr() net.Addr          { return fakeAddr{} }
func (d *deadlineRecordConn) Close() error                  { return nil }

// TestWriteMessageClearsDeadlineOnCompressFailure pins the per-frame
// write-bound invariant on every exit path: a WriteMessage whose
// compression fails must leave no armed write deadline behind on the
// transport — the bound is per-write, cleared on return, so the next
// operation starts with a clean deadline state.
func TestWriteMessageClearsDeadlineOnCompressFailure(t *testing.T) {
	rec := &deadlineRecordConn{}
	c := newRawConn(rec, rec, true, 1<<20, 0, time.Second)
	// Force the compressor to fail at creation: an out-of-range flate
	// level makes flate.NewWriter reject, so compress returns before any
	// frame is written.
	c.deflateNegotiated = true
	c.compressLevel = 99

	writeErr := c.WriteMessage(OpText, []byte("hello"))
	if writeErr == nil {
		t.Fatal("WriteMessage = nil, want the compression failure")
	}
	if len(rec.deadlines) == 0 {
		t.Fatal("no write deadline recorded; expected the armed write bound")
	}
	if last := rec.deadlines[len(rec.deadlines)-1]; !last.IsZero() {
		t.Fatalf("last write deadline after the failed WriteMessage = %v, want it cleared (zero)", last)
	}
}

// TestCloseRejectsOutOfRangeCode pins the close-code range check in
// Close: codes outside 1000-4999 are rejected before any I/O.
func TestCloseRejectsOutOfRangeCode(t *testing.T) {
	c := newRawConn(failWriteConn{}, failWriteConn{}, true, 1<<20, 0, 0)

	for _, code := range []int{999, 5000, 0} {
		closeErr := c.Close(code, "bad")
		if closeErr == nil || !errors.Is(closeErr, errBadCloseCode) {
			t.Fatalf("Close(%d) = %v, want errBadCloseCode", code, closeErr)
		}
	}
}

// TestReadFrameTruncatedHeader pins the header read failure: a stream that
// ends mid-header must produce a wrapped I/O error, not a panic.
func TestReadFrameTruncatedHeader(t *testing.T) {
	c := newTestConn([]byte{0x81}, true) // only 1 of the 2 header bytes

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "read frame header") {
		t.Fatalf("ReadMessage on truncated header = %v, want a header read error", err)
	}
}

// TestFragmentChainAcrossThreeFrames pins the multi-fragment continuation
// path: a fragment that is neither first nor final must keep the
// reassembly going (the !fin branch of handleData).
func TestFragmentChainAcrossThreeFrames(t *testing.T) {
	// "he" (start, non-fin) + "ll" (continuation, non-fin) + "o!"
	// (continuation, fin). Unmasked, as a client reads them.
	frames := []byte{
		0x01, 0x02, 'h', 'e',
		0x00, 0x02, 'l', 'l',
		0x80, 0x02, 'o', '!',
	}
	c := newTestConn(frames, true)

	opcode, data, err := c.ReadMessage()
	if err != nil || opcode != OpText || string(data) != "hello!" {
		t.Fatalf("ReadMessage = (%d, %q, %v), want (1, \"hello!\", nil)", opcode, data, err)
	}
}

// TestHandshakeWrongHeaderValue pins the wrong-value (not just missing)
// rejection: headers that are present but do not contain the required
// token must be rejected with 400.
func TestHandshakeWrongHeaderValue(t *testing.T) {
	up := NewUpgrader(WithCheckOrigin(func(*http.Request) bool { return true }))
	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, _ *Session) error {
		return nil
	}))
	s := httptest.NewServer(mux)
	defer s.Close()

	for name, header := range map[string]struct{ key, value string }{
		"Connection": {"Connection", "keep-alive"},
		"Upgrade":    {"Upgrade", "h2c"},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, s.URL+"/ws", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			req.Header.Set(header.key, header.value)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s: %q -> status %d, want 400", header.key, header.value, resp.StatusCode)
			}
		})
	}
}

// TestWriteFramePayloadFailure pins the payload write error on both sides of
// the masking rule: a payload larger than the buffered writer flushes
// straight to the transport, so a failing transport surfaces as the payload
// error, not the flush error.
func TestWriteFramePayloadFailure(t *testing.T) {
	payload := make([]byte, 20<<10) // larger than the 16 KiB buffer

	// Client side (masked payload).
	clientFC := &frameCodec{bw: bufio.NewWriterSize(failWriteConn{}, bufSize), isClient: true, maxMsg: 1 << 20}
	writeErr := clientFC.writeFrame(OpBinary, payload, false, true)
	if writeErr == nil || !strings.Contains(writeErr.Error(), "payload") {
		t.Fatalf("masked writeFrame over failing transport = %v, want a payload write error", writeErr)
	}

	// Server side (unmasked payload).
	serverFC := &frameCodec{bw: bufio.NewWriterSize(failWriteConn{}, bufSize), isClient: false, maxMsg: 1 << 20}
	writeErr = serverFC.writeFrame(OpBinary, payload, false, true)
	if writeErr == nil || !strings.Contains(writeErr.Error(), "payload") {
		t.Fatalf("unmasked writeFrame over failing transport = %v, want a payload write error", writeErr)
	}

	// A second frame on the same codec hits bufio's sticky error at the
	// header write, reaching the header-error branch: once a flush has
	// failed, the buffered writer refuses every later write, starting
	// with the next frame's header.
	writeErr = clientFC.writeFrame(OpBinary, payload, false, true)
	if writeErr == nil || !strings.Contains(writeErr.Error(), "header") {
		t.Fatalf("second writeFrame on the same codec = %v, want a header write error", writeErr)
	}
}

// TestReadFrameTruncatedLength64 pins the 64-bit length read failure: a
// header announcing a 64-bit length with no following bytes must yield a
// wrapped I/O error.
func TestReadFrameTruncatedLength64(t *testing.T) {
	// 0x81 = fin+text, 0x7f = 127 = "next 8 bytes are the length" — but the
	// connection is closed before any length bytes arrive. Reading a frame
	// that the transport cut off is an abnormal closure (1006), not a clean
	// close: the peer dropped the connection mid-frame.
	c := newTestConn([]byte{0x81, 0x7f}, true)

	_, _, err := c.ReadMessage()
	if err == nil {
		t.Fatal("ReadMessage on a truncated 64-bit length returned no error")
	}
	if code, _, ok := CloseCode(err); !ok || code != StatusAbnormalClosure {
		t.Fatalf("ReadMessage = %v, want close code 1006 (abnormal closure)", err)
	}
}

// TestArmIdleDeadlineFailure pins the armIdle error branch: a transport
// that refuses SetReadDeadline must fail the read, not panic or retry.
func TestArmIdleDeadlineFailure(t *testing.T) {
	c := newSession(newRawConn(errDeadlineConn{}, errDeadlineConn{}, true, 1<<20, time.Second, 0), nil)

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "simulated deadline failure") {
		t.Fatalf("ReadMessage with failing SetReadDeadline = %v, want the deadline error", err)
	}
}

// TestPongReplyFailure pins the ping->pong write failure: receiving a ping
// whose pong cannot be written must end the session with that error.
func TestPongReplyFailure(t *testing.T) {
	nc := &firstPingThenEOFConn{}
	c := newSession(newRawConn(nc, nc, true, 1<<20, 0, 0), nil)

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "simulated write failure") {
		t.Fatalf("ReadMessage on ping with failing pong = %v, want the write error", err)
	}
}

// firstPingThenEOFConn returns one ping frame, then EOF forever, and
// never lets a write through.
type firstPingThenEOFConn struct{ served bool }

func (f *firstPingThenEOFConn) Read(p []byte) (int, error) {
	if !f.served {
		f.served = true

		return copy(p, []byte{0x89, 0x00}), nil // ping, empty payload
	}

	return 0, io.EOF
}
func (f *firstPingThenEOFConn) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}
func (f *firstPingThenEOFConn) SetReadDeadline(time.Time) error { return nil }
func (f *firstPingThenEOFConn) SetWriteDeadline(time.Time) error {
	return nil
}
func (f *firstPingThenEOFConn) SetDeadline(time.Time) error { return nil }
func (f *firstPingThenEOFConn) LocalAddr() net.Addr         { return fakeAddr{} }
func (f *firstPingThenEOFConn) RemoteAddr() net.Addr        { return fakeAddr{} }
func (f *firstPingThenEOFConn) Close() error                { return nil }

// probePingConn blocks Read until its read deadline fires, then reports a
// timeout; its writes always fail. With a short idle window this drives
// the keepalive probe: the first silence fires a probe ping, and the
// failing ping write must end the session.
type probePingConn struct {
	mu sync.Mutex
	rl time.Time
}

func (p *probePingConn) Read(_ []byte) (int, error) {
	p.mu.Lock()
	dl := p.rl
	p.mu.Unlock()
	if dl.IsZero() {
		return 0, io.EOF
	}
	<-time.After(time.Until(dl))

	return 0, os.ErrDeadlineExceeded
}
func (p *probePingConn) Write(_ []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}
func (p *probePingConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rl = t
	return nil
}
func (p *probePingConn) SetWriteDeadline(time.Time) error { return nil }
func (p *probePingConn) SetDeadline(time.Time) error      { return nil }
func (p *probePingConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (p *probePingConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (p *probePingConn) Close() error                     { return nil }

// TestProbePingWriteFailure pins the keepalive probe's write failure:
// silence reaches the idle window, the probe ping cannot be written, and
// the session ends with that error (not a hang and not a kill).
func TestProbePingWriteFailure(t *testing.T) {
	pc := &probePingConn{}
	c := newSession(newRawConn(pc, pc, true, 1<<20, 40*time.Millisecond, 0), nil)

	_, _, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "simulated write failure") {
		t.Fatalf("ReadMessage after probe ping failure = %v, want the write error", err)
	}
}

// TestSanitizeLimits pins the option-limit guard: a non-positive message
// size, a negative idle window, or a negative write bound falls back to the
// library default rather than degrading to "no limit" or "disabled", while
// zero keeps its documented meanings (disabled keepalive, unbounded
// writes).
func TestSanitizeLimits(t *testing.T) {
	up := NewUpgrader(
		WithMaxMessageSize(0),
		WithMaxMessageSize(-1),
		WithIdleTimeout(-time.Second),
		WithWriteTimeout(-time.Second),
	)
	if up.maxMessageSize != defaultMaxMessageSize {
		t.Errorf("maxMessageSize = %d, want default %d", up.maxMessageSize, defaultMaxMessageSize)
	}
	if up.idleTimeout != defaultIdleTimeout {
		t.Errorf("idleTimeout = %v, want default %v", up.idleTimeout, defaultIdleTimeout)
	}
	if up.writeTimeout != defaultWriteTimeout {
		t.Errorf("writeTimeout = %v, want default %v", up.writeTimeout, defaultWriteTimeout)
	}

	// Explicit zeros are preserved: they are documented settings, not
	// misconfiguration.
	up = NewUpgrader(WithMaxMessageSize(1<<20), WithIdleTimeout(0), WithWriteTimeout(0))
	if up.maxMessageSize != 1<<20 || up.idleTimeout != 0 || up.writeTimeout != 0 {
		t.Errorf("explicit values not preserved: max=%d idle=%v write=%v",
			up.maxMessageSize, up.idleTimeout, up.writeTimeout)
	}
}
