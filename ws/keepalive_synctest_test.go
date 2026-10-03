package ws

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// This file drives the keepalive read loop with a fake clock — the one place
// testing/synctest fits this library:
//
//   - The blocking points are a fake net.Conn whose Read selects over
//     bubble channels and a bubble timer — durably blocking, so the fake
//     clock advances exactly to the deadlines. No real I/O is involved.
//   - Nothing in the scenario hands a mutex between goroutines, which is the
//     case synctest cannot model (a mutex waiter is not durably blocked, so
//     the clock would never advance — see longrunning_test.go).
//
// What it pins deterministically: a probe ping fires at exactly the idle
// boundary (never earlier), a dead peer is killed at exactly 2x the window,
// and a peer kept alive by frames is never killed.
//
// Determinism rule used throughout: after synctest.Sleep crosses a deadline
// and unblocks the reader, a synctest.Wait() is required before asserting on
// the reader's side effects (a recorded ping, etc.), to let it reach its
// next durably-blocked state. Assertions must use control frames (pong) to
// keep the read loop running; a data frame makes ReadMessage return.

// gatedConn is a fake net.Conn for synctest bubbles. Reads block until a
// frame is pushed (bubble channel) or the read deadline fires (bubble timer
// from time.After, set through SetReadDeadline). Writes are recorded so the
// test can observe probe pings and their (fake-clock) times.
type gatedConn struct {
	mu      sync.Mutex
	buf     []byte
	dataSig chan struct{} // bubble channel; one token per push
	readDL  <-chan time.Time

	pingMu sync.Mutex
	pings  []time.Time
}

func newGatedConn() *gatedConn {
	return &gatedConn{
		dataSig: make(chan struct{}, 1),
		readDL:  nil, // no deadline: the case is skipped in a select
	}
}

// push makes a frame available to read, then signals the reader.
func (g *gatedConn) push(frame []byte) {
	g.mu.Lock()
	g.buf = append(g.buf, frame...)
	g.mu.Unlock()
	select {
	case g.dataSig <- struct{}{}:
	default:
	}
}

func (g *gatedConn) Read(p []byte) (int, error) {
	for {
		g.mu.Lock()
		if len(g.buf) > 0 {
			n := copy(p, g.buf)
			g.buf = g.buf[n:]
			g.mu.Unlock()
			return n, nil
		}
		dl := g.readDL
		g.mu.Unlock()
		select {
		case <-g.dataSig:
			// A frame was pushed; loop and read it.
		case <-dl:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (g *gatedConn) Write(p []byte) (int, error) {
	if len(p) > 0 && (p[0]&0x0f) == OpPing {
		g.pingMu.Lock()
		g.pings = append(g.pings, time.Now())
		g.pingMu.Unlock()
	}
	return len(p), nil
}

func (g *gatedConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		g.mu.Lock()
		g.readDL = nil
		g.mu.Unlock()
		return nil
	}
	g.mu.Lock()
	g.readDL = time.After(time.Until(t)) // bubble timer
	g.mu.Unlock()
	return nil
}
func (g *gatedConn) SetWriteDeadline(time.Time) error { return nil }
func (g *gatedConn) SetDeadline(time.Time) error      { return nil }
func (g *gatedConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (g *gatedConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (g *gatedConn) Close() error                     { return nil }

func (g *gatedConn) pingCount() int {
	g.pingMu.Lock()
	defer g.pingMu.Unlock()
	return len(g.pings)
}

func (g *gatedConn) pingTimes() []time.Time {
	g.pingMu.Lock()
	defer g.pingMu.Unlock()
	return append([]time.Time(nil), g.pings...)
}

// startRead runs ReadMessage in the bubble and reports its result.
func startRead(t *testing.T, c *Conn) <-chan error {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.ReadMessage()
		errc <- err
	}()
	return errc
}

func requireTimeout(t *testing.T, err error) {
	t.Helper()
	var nerr net.Error
	if err == nil || !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("want a timeout net.Error, got %v", err)
	}
}

// TestKeepaliveProbesThenKillsDeadPeer pins the exact fake-clock timeline
// for a silent dead peer: no ping before the first window, a probe ping at
// exactly the idle boundary, and a timeout kill at exactly twice the window.
func TestKeepaliveProbesThenKillsDeadPeer(t *testing.T) {
	idle := time.Second
	synctest.Test(t, func(t *testing.T) {
		nc := newGatedConn()
		c := newConn(nc, nc, true, 1<<20, idle, 0)
		probeAt := c.lastActivity.Add(idle) // the exact deadline the first arm sets
		errc := startRead(t, c)
		synctest.Wait() // the reader is durably blocked with a deadline at idle

		synctest.Sleep(idle - 100*time.Millisecond) // t = idle-100ms
		synctest.Wait()
		if n := nc.pingCount(); n != 0 {
			t.Fatalf("%d pings before the idle window elapsed, want 0", n)
		}
		synctest.Sleep(100 * time.Millisecond) // t = idle
		synctest.Wait()                        // the reader has probed (ping #1) and re-blocked at 2*idle
		if n := nc.pingCount(); n != 1 {
			t.Fatalf("%d pings at the idle boundary, want 1", n)
		}
		if at := nc.pingTimes()[0]; !at.Equal(probeAt) {
			t.Fatalf("probe ping at %v, want exactly %v", at, probeAt)
		}
		synctest.Sleep(idle) // t = 2*idle: the grace window expires
		requireTimeout(t, <-errc)
	})
}

// TestKeepaliveAlivePeerSurvives pins that a peer kept alive by frames is
// never killed: pongs pushed just before each deadline keep resetting the
// clock, so the connection is still connected far past the point where a
// dead peer would have been probed and killed.
func TestKeepaliveAlivePeerSurvives(t *testing.T) {
	idle := time.Second
	synctest.Test(t, func(t *testing.T) {
		nc := newGatedConn()
		c := newConn(nc, nc, true, 1<<20, idle, 0)
		errc := startRead(t, c)
		synctest.Wait() // deadline at idle

		synctest.Sleep(idle) // t = idle: probe #1
		synctest.Wait()      // the reader has probed and re-blocked at 2*idle
		if n := nc.pingCount(); n != 1 {
			t.Fatalf("%d pings at the idle boundary, want 1", n)
		}
		nc.push([]byte{0x8a, 0x00}) // the peer answers the probe
		synctest.Wait()             // consumed at t=idle; the clock restarts

		// The restarted clock means probe #2 lands one full window later;
		// answering it keeps the connection alive past the point where a
		// dead peer would be killed.
		synctest.Sleep(idle) // t = 2*idle: probe #2
		synctest.Wait()
		if n := nc.pingCount(); n != 2 {
			t.Fatalf("%d pings by t=2*idle, want 2 (a dead peer would be killed, not probed)", n)
		}
		nc.push([]byte{0x8a, 0x00}) // the peer answers again
		synctest.Wait()

		select {
		case err := <-errc:
			t.Fatalf("alive peer killed: %v", err)
		default:
		}
		// End the bubble cleanly: a close frame lets the reader return.
		nc.push([]byte{0x88, 0x00})
		synctest.Wait()
	})
}

// TestKeepaliveActivityResetsClock pins that any frame — here a pong —
// refreshes the clock: activity at half the window moves the first probe
// (and thus the kill point) past where it would have been without it.
func TestKeepaliveActivityResetsClock(t *testing.T) {
	idle := time.Second
	synctest.Test(t, func(t *testing.T) {
		nc := newGatedConn()
		c := newConn(nc, nc, true, 1<<20, idle, 0)
		errc := startRead(t, c)
		synctest.Wait() // deadline at idle

		synctest.Sleep(idle / 2)    // t = 0.5*idle
		nc.push([]byte{0x8a, 0x00}) // a pong: activity, keeps the loop running
		synctest.Wait()             // reader consumes at t=0.5, deadline now 1.5*idle

		synctest.Sleep(idle / 2) // t = idle
		synctest.Wait()
		// Without the reset, the first probe would fire at t=idle; with it,
		// the clock restarted at 0.5*idle, so no ping yet.
		if n := nc.pingCount(); n != 0 {
			t.Fatalf("%d pings at t=idle after activity reset, want 0", n)
		}
		select {
		case <-errc:
			t.Fatal("ReadMessage returned before the reset clock could expire")
		default:
		}
		// End the bubble cleanly: a close frame lets the reader return.
		nc.push([]byte{0x88, 0x00})
		synctest.Wait()
	})
}
