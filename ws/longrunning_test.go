package ws

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// These tests target the long-running-server failure modes: a write to a
// blackhole must not wedge [Conn.Close], and a background writer needs a
// race-free signal that the connection is gone.
//
// Why not synctest here: synctest advances its fake clock only when every
// goroutine in the bubble is durably blocked, and a goroutine waiting on a
// sync.Mutex is *not* durably blocked. The wedge is exactly "writer holds
// c.mu inside a write; closer waits on that same c.mu" — so synctest would
// see the closer as possibly-progressing, refuse to advance the clock, and
// panic as a deadlock. A fake net.Conn whose Write blocks on a channel is
// the right tool; the write deadline is honored with a real (short) timer so
// the outcome is deterministic even though the wall-clock is bounded and tiny.

// deadlineConn is a net.Conn whose Write blocks until either the test closes
// its stuck channel (a write that "succeeds") or the write deadline set by
// the library fires (a write that fails). Once the first deadline has fired
// the conn is marked dead and later writes fail immediately, so a best-effort
// close-frame write does not also block for its own 5 s bound.
type deadlineConn struct {
	mu         sync.Mutex
	deadline   time.Time
	writeTried bool
	dead       bool
	entered    chan struct{} // closed when Write is first entered
	stuck      chan struct{} // closing it lets a pending Write succeed
	closed     chan struct{} // closed when Close is called
}

func (d *deadlineConn) Read(p []byte) (int, error) { return 0, io.EOF }

func (d *deadlineConn) Write(p []byte) (int, error) {
	d.mu.Lock()
	first := !d.writeTried
	d.writeTried = true
	if d.dead {
		d.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	dl := d.deadline
	d.mu.Unlock()

	if first {
		close(d.entered)
	}
	if dl.IsZero() {
		<-d.stuck // no deadline: block until the test releases us
		return len(p), nil
	}
	select {
	case <-d.stuck:
		return len(p), nil
	case <-time.After(time.Until(dl)):
		d.mu.Lock()
		d.dead = true
		d.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
}

func (d *deadlineConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadline = t
	return nil
}
func (d *deadlineConn) SetReadDeadline(time.Time) error { return nil }
func (d *deadlineConn) SetDeadline(time.Time) error     { return nil }
func (d *deadlineConn) LocalAddr() net.Addr             { return fakeAddr{} }
func (d *deadlineConn) RemoteAddr() net.Addr            { return fakeAddr{} }
func (d *deadlineConn) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}

// TestWriteDeadlineUnsticksClose is the regression test for the wedge: a
// WriteMessage stuck on a blackhole holds the write mutex, and a concurrent
// Close must complete once the write deadline fires — not block forever. On
// the pre-fix code Close never returns, so the bound below fails.
func TestWriteDeadlineUnsticksClose(t *testing.T) {
	nc := &deadlineConn{
		entered: make(chan struct{}),
		stuck:   make(chan struct{}), // never closed: a permanent blackhole
		closed:  make(chan struct{}),
	}
	c := newConn(nc, nc, true, 1<<20, 0, 20*time.Millisecond)

	// A writer stuck on the blackhole, holding the write mutex.
	werr := make(chan error, 1)
	go func() { werr <- c.WriteMessage(OpText, make([]byte, 64<<10)) }()

	// Deterministically wait until the writer has taken c.mu and is blocked
	// inside Write (no real sleep: this is a channel signal).
	<-nc.entered

	// A concurrent Close must now complete after the write deadline fires.
	cerr := make(chan error, 1)
	go func() { cerr <- c.Close(StatusNormalClosure, "") }()

	select {
	case <-cerr:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s: the stuck write still holds the write mutex (wedge not fixed)")
	}

	// The stuck writer must have failed with a deadline, not blocked.
	select {
	case w := <-werr:
		if !errors.Is(w, os.ErrDeadlineExceeded) {
			t.Fatalf("stuck write returned %v, want a deadline error", w)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stuck writer did not fail within 2s")
	}

	if !c.Closed() {
		t.Fatal("Conn not marked closed after Close")
	}
	select {
	case <-nc.closed:
	default:
		t.Fatal("underlying transport Close was not called")
	}
}

// immediateConn is a net.Conn whose writes succeed at once, recording the
// last write deadline set on it.
type immediateConn struct {
	mu sync.Mutex
	dl time.Time
}

func (i *immediateConn) Read(p []byte) (int, error)  { return 0, io.EOF }
func (i *immediateConn) Write(p []byte) (int, error) { return len(p), nil }
func (i *immediateConn) Close() error                { return nil }
func (i *immediateConn) LocalAddr() net.Addr         { return fakeAddr{} }
func (i *immediateConn) RemoteAddr() net.Addr        { return fakeAddr{} }
func (i *immediateConn) SetDeadline(time.Time) error { return nil }
func (i *immediateConn) SetReadDeadline(time.Time) error {
	return nil
}
func (i *immediateConn) SetWriteDeadline(t time.Time) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.dl = t
	return nil
}
func (i *immediateConn) lastDeadline() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.dl
}

// TestWriteDeadlineClearedAfterSuccess guards the deferred clear: after a
// successful write the deadline must be reset so a later write is not cut off
// by a stale, already-spent deadline.
func TestWriteDeadlineClearedAfterSuccess(t *testing.T) {
	nc := &immediateConn{}
	c := newConn(nc, nc, true, 1<<20, 0, 50*time.Millisecond)

	if err := c.WriteMessage(OpText, []byte("one")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if dl := nc.lastDeadline(); !dl.IsZero() {
		t.Fatalf("write deadline not cleared after a successful write: %v", dl)
	}
	if err := c.WriteMessage(OpText, []byte("two")); err != nil {
		t.Fatalf("second write: %v", err)
	}
}

// TestClosedSignal pins the race-free close signal a background writer needs:
// false while open, true after Close. The concurrent read loop exists to
// exercise the atomic read under the race detector; the value a concurrent
// reader observes is legitimately either, so only the stable endpoints are
// asserted.
func TestClosedSignal(t *testing.T) {
	c := newConn(&immediateConn{}, &immediateConn{}, true, 1<<20, 0, 0)
	if c.Closed() {
		t.Fatal("Closed() true on a fresh connection")
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = c.Closed()
			}
		}()
	}
	_ = c.Close(StatusNormalClosure, "")
	wg.Wait()

	if !c.Closed() {
		t.Fatal("Closed() false after Close")
	}
}
