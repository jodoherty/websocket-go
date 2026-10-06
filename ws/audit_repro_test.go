// Audit reproductions. Every test in this file asserts the DESIRED behavior
// and therefore FAILS against the audited revision (ab9e936): each one
// reproduces a finding from doc/../websocket-go-findings.md. They are
// regression tests: keep them, fix the implementation, do not weaken the
// assertions to make the implementation pass.
package ws

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"strings"
	"testing"
	"time"
)

// fakeTimeout stands in for a read-deadline expiry on a transport: it
// implements net.Error with Timeout() true, which is all isReadTimeout
// looks for.
type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

// ── Finding 1: keepalive retry after a partially consumed frame ─────────

// midFrameTimeoutConn delivers step1, then one read timeout, then step2.
type midFrameTimeoutConn struct {
	readStep int
	step1    []byte
	step2    []byte
}

func (m *midFrameTimeoutConn) Read(p []byte) (int, error) {
	switch m.readStep {
	case 0:
		m.readStep = 1

		return copy(p, m.step1), nil
	case 1:
		m.readStep = 2

		return 0, fakeTimeout{}
	}
	if n := copy(p, m.step2); n > 0 {
		m.readStep = 3

		return n, nil
	}

	return 0, io.EOF
}
func (m *midFrameTimeoutConn) Write(p []byte) (int, error) { return len(p), nil }
func (m *midFrameTimeoutConn) Close() error               { return nil }
func (m *midFrameTimeoutConn) RemoteAddr() net.Addr       { return fakeAddr{} }
func (m *midFrameTimeoutConn) LocalAddr() net.Addr        { return fakeAddr{} }
func (m *midFrameTimeoutConn) SetDeadline(time.Time) error {
	return nil
}
func (m *midFrameTimeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (m *midFrameTimeoutConn) SetWriteDeadline(time.Time) error { return nil }

// TestAuditKeepaliveRetryAfterPartialFrame: a 4-byte binary frame (header
// 0x82 0x04, payload "A\x82\x01X") is interrupted by a keepalive timeout
// after the header and one payload byte. The retry must preserve the
// original message or terminate the connection — it must not deliver a
// truncated "success" by re-parsing the remaining payload bytes as a new
// frame header.
func TestAuditKeepaliveRetryAfterPartialFrame(t *testing.T) {
	t.Parallel()
	m := &midFrameTimeoutConn{
		step1: []byte{0x82, 0x04, 0x41}, // header + first payload byte "A"
		step2: []byte{0x82, 0x01, 0x58}, // the remaining payload bytes
	}
	raw := newRawConn(m, m, true, 1<<20, time.Second, 0)
	ev, err := raw.ReadEvent()
	if err == nil && string(ev.Payload) == "X" {
		t.Fatalf("keepalive retry delivered %q: the partially consumed frame's "+
			"remaining bytes were re-read as a new frame, corrupting the message boundary",
			ev.Payload)
	}
}

// ── Finding 2: failed application ping/pong leaves the connection open ──

// failedWriteConn is a transport whose writes always fail.
type failedWriteConn struct {
	closed bool
}

func (f *failedWriteConn) Read(p []byte) (int, error)    { return 0, io.EOF }
func (f *failedWriteConn) Write(p []byte) (int, error)  { return 0, io.ErrClosedPipe }
func (f *failedWriteConn) Close() error                 { f.closed = true; return nil }
func (f *failedWriteConn) RemoteAddr() net.Addr         { return fakeAddr{} }
func (f *failedWriteConn) LocalAddr() net.Addr          { return fakeAddr{} }
func (f *failedWriteConn) SetDeadline(time.Time) error  { return nil }
func (f *failedWriteConn) SetReadDeadline(time.Time) error {
	return nil
}
func (f *failedWriteConn) SetWriteDeadline(time.Time) error { return nil }

// TestAuditControlWriteFailureIsTerminal: a transport-level ping or pong
// write failure must fail the connection exactly as a data-write failure
// does (terminal state, transport closed), not just return an error.
func TestAuditControlWriteFailureIsTerminal(t *testing.T) {
	for name, call := range map[string]func(*RawConn) error{
		"Ping": func(c *RawConn) error { return c.Ping([]byte("x")) },
		"Pong": func(c *RawConn) error { return c.Pong([]byte("x")) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &failedWriteConn{}
			raw := newRawConn(f, f, true, 1<<20, 0, 0)
			if err := call(raw); err == nil {
				t.Fatal("control write unexpectedly succeeded")
			}
			if !raw.Closed() {
				t.Error("Closed() = false after a failed control write: the connection was not made terminal")
			}
			if !f.closed {
				t.Error("transport not closed after a failed control write: a blocked reader would not be woken")
			}
		})
	}
}

// ── Finding 3: fragmented writes permit illegal message interleaving ───

// TestAuditFragmentedWriteRejectsNewDataStart: while a fragmented message
// is in progress, a new data message must not be started (RFC 6455 §5.4) —
// not via WriteFrame and not via WriteMessage. Continuations and control
// frames remain legal.
func TestAuditFragmentedWriteRejectsNewDataStart(t *testing.T) {
	t.Parallel()
	raw := newTestRawConn(nil, true)
	if err := raw.WriteFrame(OpBinary, []byte("start"), true); err != nil {
		t.Fatalf("fragment start: %v", err)
	}
	if err := raw.WriteFrame(OpBinary, []byte("new"), false); err == nil {
		t.Error("WriteFrame started a new data message while another was mid-fragment")
	}
	if err := raw.WriteMessage(OpBinary, []byte("new")); err == nil {
		t.Error("WriteMessage started a new data message while another was mid-fragment")
	}
	// Control traffic stays legal mid-fragment (RFC 6455 §5.5).
	if err := raw.Ping(nil); err != nil {
		t.Errorf("ping mid-fragment must stay legal: %v", err)
	}
	// Finishing the fragment re-opens normal writes.
	fresh := newTestRawConn(nil, true)
	if err := fresh.WriteFrame(OpBinary, []byte("start"), true); err != nil {
		t.Fatalf("fragment start (fresh): %v", err)
	}
	if err := fresh.WriteFrame(OpContinuation, []byte("end"), false); err != nil {
		t.Fatalf("continuation: %v", err)
	}
	if err := fresh.WriteMessage(OpBinary, []byte("next")); err != nil {
		t.Errorf("write after the fragment completed: %v", err)
	}
}

// ── Finding 4: context cancellation does not interrupt the handshake ────

// TestAuditDialCancellationInterruptsHandshake: cancelling the establishment
// context while the 101 response is pending must unblock Dial; it may not
// wait for the (deadline-free) transport to die on its own.
func TestAuditDialCancellationInterruptsHandshake(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, "ws://cancel.example.local/ws", WithDialer(
			func(context.Context, *url.URL) (net.Conn, error) { return clientConn, nil }))
		done <- err
	}()
	// Wait for the request to arrive at the peer.
	buf := make([]byte, 4096)
	for !containsCRLFCRLF(buf) {
		n, err := serverConn.Read(buf)
		if err != nil {
			t.Fatalf("peer read of the handshake request: %v", err)
		}
		if n == 0 {
			t.Fatal("peer read returned zero")
		}
		buf = buf[:n]
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Dial did not return within 2s of context cancellation while the response was pending")
	}
}

// containsCRLFCRLF reports whether buf ends with or contains the end of an
// HTTP head.
func containsCRLFCRLF(buf []byte) bool {
	for i := 0; i+3 < len(buf); i++ {
		if buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n' {
			return true
		}
	}

	return false
}

// ── Finding 6: compression negotiation rejects valid peers ──────────────

// TestAuditServerWindowBitsDirection (6A): server_max_window_bits=10 in a
// 101 response configures the SERVER's compressor; this client's full-window
// decompressor decodes it fine. The response must be accepted.
func TestAuditServerWindowBitsDirection(t *testing.T) {
	t.Parallel()
	ok, err := verifyCompressionResponse(true,
		[]string{"permessage-deflate; server_no_context_takeover; server_max_window_bits=10"})
	if err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
	if !ok {
		t.Fatal("valid response reported as not negotiated")
	}
}

// TestAuditAlternativeDeflateOffers (6B): RFC 7692 §7 permits multiple
// permessage-deflate offers as alternative configurations, ordered by
// preference. The first alternative demands a window this implementation
// cannot supply; the second can be supported and must be selected.
func TestAuditAlternativeDeflateOffers(t *testing.T) {
	t.Parallel()
	resp, err := negotiateCompression([]string{
		"permessage-deflate; server_max_window_bits=10",
		"permessage-deflate",
	})
	if err != nil {
		t.Fatalf("alternative offers rejected: %v", err)
	}
	if resp != deflateResponseHeader {
		t.Fatalf("response = %q, want %q", resp, deflateResponseHeader)
	}
}

// ── Finding 7: nonminimal frame lengths are accepted ────────────────────

// TestAuditNonminimalFrameLengthRejected: RFC 6455 §5.2 requires the
// smallest length encoding. The 16-bit form below 126 and the 64-bit form
// below 65536 must be rejected; the canonical boundary forms stay accepted.
func TestAuditNonminimalFrameLengthRejected(t *testing.T) {
	t.Parallel()
	// One-byte payload in the 16-bit form: must be rejected.
	c := newTestCodec([]byte{0x82, 0x7e, 0x00, 0x01, 0x58}, true)
	if _, err := c.readFrame(); err == nil {
		t.Error("16-bit length form for a 1-byte payload accepted; want protocol rejection")
	}
	// One-byte payload in the 64-bit form: must be rejected.
	c = newTestCodec([]byte{0x82, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58}, true)
	if _, err := c.readFrame(); err == nil {
		t.Error("64-bit length form for a 1-byte payload accepted; want protocol rejection")
	}
	// Boundary: exactly 126 bytes must use the 16-bit form and is legal.
	payload := make([]byte, 126)
	for i := range payload {
		payload[i] = 0xa5
	}
	wire := append([]byte{0x82, 0x7e, 0x00, 0x7e}, payload...)
	c = newTestCodec(wire, true)
	f, err := c.readFrame()
	if err != nil || len(f.payload) != 126 {
		t.Fatalf("canonical 16-bit form for 126 bytes: (%+v, %v), want the 126-byte payload", f, err)
	}
}

// ── Finding 9: compressed messages can be silently truncated ────────────

// TestAuditMultipleFinalDeflateBlocks: RFC 7692 §7.2.1 permits byte-aligned
// final DEFLATE blocks followed by more blocks. A peer sending two final
// stored blocks (payload "AB") plus the §7.2.3.4 tail must deliver the full
// message, not just the first block.
func TestAuditMultipleFinalDeflateBlocks(t *testing.T) {
	t.Parallel()
	// Two final stored blocks: "A" then "B", then the permessage-deflate
	// tail (00 00 FF FF + the extra BFINAL empty block this decoder appends
	// for real peers is not present here — the RFC tail suffices for the
	// wire form the audit reproduced, extended to the decoder's tail).
	payload := []byte{
		0x01, 0x01, 0x00, 0xfe, 0xff, 0x41, // final stored block: "A"
		0x01, 0x01, 0x00, 0xfe, 0xff, 0x42, // final stored block: "B"
		0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff,
	}
	wire := append([]byte{0xc2, 0x7e, 0x00, byte(len(payload))}, payload...) // RSV1 + binary
	raw := newTestRawConn(wire, true)
	raw.applyCompression()
	ev, err := raw.ReadEvent()
	if err != nil {
		t.Fatalf("multi-block compressed message failed: %v", err)
	}
	if string(ev.Payload) != "AB" {
		t.Fatalf("payload = %q, want %q: the decoder stopped at the first BFINAL block and discarded the rest",
			ev.Payload, "AB")
	}
}

// ── Finding 11: abrupt disconnects look like clean closure ──────────────

// TestAuditAbruptEOFIsNotCleanClose: a bare transport EOF must not match
// io.EOF, which is the documented clean-close signal; RFC 6455 §7.1.5
// assigns 1006 (abnormal closure) to transport loss.
func TestAuditAbruptEOFIsNotCleanClose(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	raw := newRawConn(clientConn, clientConn, true, 1<<20, 0, 0)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = serverConn.Close()
	}()
	_, err := raw.ReadEvent()
	if err == nil {
		t.Fatal("ReadEvent returned no error on transport loss")
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("abrupt transport EOF matches io.EOF (%v): the documented clean-close "+
			"check cannot distinguish transport loss from a normal close", err)
	}
	// Contrast: a normal close frame IS the clean close.
	sess := newTestConn([]byte{0x88, 0x02, 0x03, 0xe8}, true) // close 1000
	if _, _, cleanErr := sess.ReadMessage(); !errors.Is(cleanErr, io.EOF) {
		t.Fatalf("normal close frame should read as io.EOF, got %v", cleanErr)
	}
}

// ── Finding 12: handler panics leak hijacked connections ────────────────

type trackedListener struct {
	net.Listener
	mu    sync.Mutex
	conns []*closingConn
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &closingConn{Conn: conn}
	l.mu.Lock()
	l.conns = append(l.conns, tc)
	l.mu.Unlock()

	return tc, nil
}

func (l *trackedListener) allClosed(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		n, closed := len(l.conns), true
		for _, c := range l.conns {
			if !c.closed.Load() {
				closed = false
			}
		}
		l.mu.Unlock()
		if n > 0 && closed {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}

	return false
}

type closingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closingConn) Close() error {
	c.closed.Store(true)

	return c.Conn.Close()
}

// TestAuditHandlerPanicClosesConnection: a panic in the application
// callback must still tear the upgraded connection down; net/http's
// recovery path deliberately skips hijacked connections, so without
// deferred teardown the transport leaks.
func TestAuditHandlerPanicClosesConnection(t *testing.T) {
	run := func(t *testing.T, h http.Handler, name string) {
		t.Helper()
		ts := httptest.NewUnstartedServer(h)
		tracked := &trackedListener{Listener: ts.Listener}
		ts.Listener = tracked
		ts.Start()
		defer ts.Close()

		s, err := Dial(context.Background(), "ws://"+strings.TrimPrefix(ts.URL, "http://"))
		if err != nil {
			t.Fatalf("%s: Dial: %v", name, err)
		}
		defer s.Close(StatusNormalClosure, "")
		t.Logf("%s: handler panicked (recovered by net/http; the log dump is expected)", name)
		if !tracked.allClosed(2 * time.Second) {
			t.Fatalf("%s: the hijacked transport was never closed after the handler panicked: connection leaked", name)
		}
	}
	t.Run("Handle", func(t *testing.T) {
		run(t, NewUpgrader().Handle(func(*http.Request, *Session) error { panic("boom") }), "Handle")
	})
	t.Run("HandleRaw", func(t *testing.T) {
		run(t, NewUpgrader().HandleRaw(func(*http.Request, *RawConn) error { panic("boom") }), "HandleRaw")
	})
}

// ── Finding 13: writes erase application-managed deadlines ──────────────

type writeDeadlineProbe struct {
	net.Conn
	mu   sync.Mutex
	last time.Time
}

func (w *writeDeadlineProbe) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.last = t
	w.mu.Unlock()

	return w.Conn.SetWriteDeadline(t)
}

func (w *writeDeadlineProbe) lastWriteDeadline() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.last
}

// TestAuditWritePreservesApplicationDeadline: with the library write
// timeout disabled (0), an application-set write deadline must survive a
// successful message write, not be cleared to the zero time.
func TestAuditWritePreservesApplicationDeadline(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	probe := &writeDeadlineProbe{Conn: clientConn}
	raw := newRawConn(probe, clientConn, true, 1<<20, 0, 0)
	appDeadline := time.Now().Add(10 * time.Second)
	if err := raw.SetWriteDeadline(appDeadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	go func() {
		buf := make([]byte, 32)
		_, _ = io.ReadFull(serverConn, buf)
	}()
	if err := raw.WriteMessage(OpBinary, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if last := probe.lastWriteDeadline(); !last.Equal(appDeadline) {
		t.Fatalf("write deadline after a successful write = %v, want the preserved %v: "+
			"the write cleared an application-managed deadline", last, appDeadline)
	}
}

// ── Finding 14: valid quoted extension values are rejected ──────────────

// TestAuditQuotedWindowBitsValue: RFC 6455 §9.1 permits quoted-string
// parameter values; server_max_window_bits="15" is the value 15.
func TestAuditQuotedWindowBitsValue(t *testing.T) {
	t.Parallel()
	params, err := parseCompressionParams(`permessage-deflate; server_max_window_bits="15"`)
	if err != nil {
		t.Fatalf("valid quoted value rejected: %v", err)
	}
	if params.serverWindowBits != 15 {
		t.Fatalf("window bits = %d, want 15", params.serverWindowBits)
	}
	// A quoted value that is not a token must still be rejected.
	if _, err := parseCompressionParams(`permessage-deflate; server_max_window_bits="15x"`); err == nil {
		t.Error("quoted non-numeric window bits accepted; want rejection")
	}
}