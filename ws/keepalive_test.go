package ws

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// The keepalive timing used to live in a pure decision function
// (lastActivity, now, idle → ping?, deadline). The redesign moved the
// decision into the read loop (probe on timeout), so the pure, clock-free
// unit is now the probe state machine itself: a silence timeout either
// probes (first time) or kills (repeat), and the read-deadline error is
// distinguished from real transport errors.

func TestProbeDecision(t *testing.T) {
	if probeDecision(false) != probePing {
		t.Fatal("first silence timeout must probe with a ping")
	}
	if probeDecision(true) != probeKill {
		t.Fatal("second silence timeout must kill")
	}
}

// TestIsReadTimeout pins the error classification the read loop relies on:
// a deadline timeout must not be treated as a transport error (which would
// end the connection without probing), and a real error must not be treated
// as a timeout (which would probe forever).
func TestIsReadTimeout(t *testing.T) {
	deadlineErr := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	if !isReadTimeout(deadlineErr) {
		t.Fatal("wrapped deadline error not classified as a timeout")
	}
	if !isReadTimeout(os.ErrDeadlineExceeded) {
		t.Fatal("bare deadline error not classified as a timeout")
	}
	if isReadTimeout(errors.New("connection reset")) {
		t.Fatal("plain error classified as a timeout")
	}
	if isReadTimeout(&net.OpError{Op: "read", Err: errors.New("connection reset")}) {
		t.Fatal("wrapped reset classified as a timeout")
	}
}

// fakeTimeoutError stands in for a read-deadline expiry on a transport: it
// implements net.Error with Timeout() true, which is all isReadTimeout looks
// for.
type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

// midFrameTimeoutConn delivers step1, then one read timeout, then step2. It
// models a keepalive read timeout firing in the middle of a frame: the first
// read pulls step1, the second read times out, and the third onward pulls
// step2 (the bytes that were pending when the timeout fired).
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

		return 0, fakeTimeoutError{}
	}
	if n := copy(p, m.step2); n > 0 {
		m.readStep = 3

		return n, nil
	}

	return 0, io.EOF
}
func (m *midFrameTimeoutConn) Write(p []byte) (int, error) { return len(p), nil }
func (m *midFrameTimeoutConn) Close() error                { return nil }
func (m *midFrameTimeoutConn) RemoteAddr() net.Addr        { return fakeAddr{} }
func (m *midFrameTimeoutConn) LocalAddr() net.Addr         { return fakeAddr{} }
func (m *midFrameTimeoutConn) SetDeadline(time.Time) error {
	return nil
}
func (m *midFrameTimeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (m *midFrameTimeoutConn) SetWriteDeadline(time.Time) error { return nil }

// TestKeepaliveRetryAfterPartialFrame: a keepalive read timeout that fires
// after some frame bytes have already been pulled must not re-read those
// bytes as a fresh frame header. The retry either preserves the original
// message or makes the connection terminal — it never delivers a truncated
// "success" by reinterpreting the remainder of the interrupted frame.
func TestKeepaliveRetryAfterPartialFrame(t *testing.T) {
	t.Parallel()
	t.Run("partial-frame", func(t *testing.T) {
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
		if !raw.Closed() {
			t.Error("a retry that would re-read a partially consumed frame must make the connection terminal")
		}
	})
	t.Run("clean-retry", func(t *testing.T) {
		t.Parallel()
		// The timeout fires before any payload byte is pulled (step1 empty),
		// so the retry is safe: the probe is sent and the next frame is read
		// normally from step2.
		m := &midFrameTimeoutConn{
			step1: []byte{},                                   // nothing pulled before the timeout
			step2: []byte{0x82, 0x04, 0x41, 0x42, 0x43, 0x44}, // a whole frame
		}
		raw := newRawConn(m, m, true, 1<<20, time.Second, 0)
		ev, err := raw.ReadEvent()
		if err != nil || len(ev.Payload) != 4 || string(ev.Payload) != "ABCD" {
			t.Fatalf("clean retry read = (%q, %v), want %q, nil", ev.Payload, err, "ABCD")
		}
		if raw.Closed() {
			t.Error("a clean retry must keep the connection open")
		}
	})
}
