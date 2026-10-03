package ws

import (
	"errors"
	"net"
	"os"
	"testing"
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
