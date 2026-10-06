package ws

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
// the conn is marked dead and later writes fail immediately, so teardown
// after the failed write never blocks a second time.
type deadlineConn struct {
	mu         sync.Mutex
	deadline   time.Time
	writeTried bool
	dead       bool
	entered    chan struct{} // closed when Write is first entered
	stuck      chan struct{} // closing it lets a pending Write succeed
	closed     chan struct{} // closed when Close is called
}

func (d *deadlineConn) Read(_ []byte) (int, error) { return 0, io.EOF }

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
	c := newRawConn(nc, nc, true, 1<<20, 0, 20*time.Millisecond)

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
	mu    sync.Mutex
	dl    time.Time
	armed time.Time
}

func (i *immediateConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
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
	if !t.IsZero() {
		i.armed = t
	}
	i.dl = t
	return nil
}
func (i *immediateConn) lastDeadline() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.dl
}

// lastArmed returns the most recent non-zero write deadline: the bound a
// write was made under, even when a later clear has already reset dl.
func (i *immediateConn) lastArmed() time.Time {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.armed
}

// TestWriteDeadlineClearedAfterSuccess guards the deferred clear: after a
// successful write the deadline must be reset so a later write is not cut off
// by a stale, already-spent deadline.
func TestWriteDeadlineClearedAfterSuccess(t *testing.T) {
	nc := &immediateConn{}
	c := newRawConn(nc, nc, true, 1<<20, 0, 50*time.Millisecond)

	err := c.WriteMessage(OpText, []byte("one"))
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	dl := nc.lastDeadline()
	if !dl.IsZero() {
		t.Fatalf("write deadline not cleared after a successful write: %v", dl)
	}
	err = c.WriteMessage(OpText, []byte("two"))
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
}

// TestWriteTransportFailureFailsConnection pins the transport-failure
// contract: a write that reaches the transport and fails marks the
// connection dead with the error recorded — later writes and Close return
// that error at once, Closed() reports it, and the transport is closed so
// a reader blocked in ReadMessage wakes now and a hijacked conn cannot
// leak if the read path is not currently in a read.
func TestWriteTransportFailureFailsConnection(t *testing.T) {
	nc := &closedConn{inner: failWriteConn{}, closed: make(chan struct{})}
	c := newSession(newRawConn(nc, nc, true, 1<<20, 0, 0), nil)

	writeErr := c.WriteMessage(OpBinary, []byte("gone"))
	if writeErr == nil {
		t.Fatal("write to a failing transport succeeded")
	}
	if !c.Closed() {
		t.Fatal("connection not closed after a transport write failure")
	}
	select {
	case <-nc.closed:
	default:
		t.Fatal("transport was not closed by the failed write")
	}
	second := c.WriteMessage(OpBinary, []byte("again"))
	if !errors.Is(second, writeErr) {
		t.Fatalf("second write = %v, want the recorded %v", second, writeErr)
	}
	err := c.Close(StatusNormalClosure, "")
	if !errors.Is(err, writeErr) {
		t.Fatalf("Close = %v, want the recorded %v", err, writeErr)
	}
	_, _, err = c.ReadMessage()
	if !errors.Is(err, writeErr) {
		t.Fatalf("ReadMessage = %v, want the recorded %v", err, writeErr)
	}
}

// TestWriteFrameTransportFailureFailsConnection pins the same verdict on
// the raw frame-write path: a failed transport write marks the connection
// closed with the error recorded, closes the transport, and later writes
// return the recorded error at once.
func TestWriteFrameTransportFailureFailsConnection(t *testing.T) {
	nc := &closedConn{inner: failWriteConn{}, closed: make(chan struct{})}
	c := newRawConn(nc, nc, true, 1<<20, 0, 0)

	writeErr := c.WriteFrame(OpBinary, []byte("gone"), false)
	if writeErr == nil {
		t.Fatal("frame write to a failing transport succeeded")
	}
	if !c.Closed() {
		t.Fatal("connection not closed after a failed frame write")
	}
	select {
	case <-nc.closed:
	default:
		t.Fatal("transport was not closed by the failed frame write")
	}
	second := c.WriteFrame(OpBinary, []byte("again"), false)
	if !errors.Is(second, writeErr) {
		t.Fatalf("second frame write = %v, want the recorded %v", second, writeErr)
	}
}

// closedConn wraps a net.Conn, recording when the transport was closed.
type closedConn struct {
	inner  net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closedConn) Read(p []byte) (int, error)         { return c.inner.Read(p) }
func (c *closedConn) Write(p []byte) (int, error)        { return c.inner.Write(p) }
func (c *closedConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *closedConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *closedConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *closedConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *closedConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
func (c *closedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.inner.Close()
}

// TestWriteFailureAfterConcurrentClose pins the ordering when a Close wins
// the race against an in-flight write: the transport write then fails, but
// the closer's recorded error must survive — the transport error must not
// overwrite what the concurrent Close recorded.
func TestWriteFailureAfterConcurrentClose(t *testing.T) {
	var c *RawConn
	nc := hookWriteConn{hook: func() {
		// Simulate a Close that completed while this write was in flight:
		// state and closeErr are set exactly as [RawConn.Close] would set
		// them. Same goroutine, so no synchronization is needed.
		c.state.Store(stClosed)
		c.closeErr = closeErrFor(StatusGoingAway, "bye")
	}}
	c = newRawConn(nc, nc, true, 1<<20, 0, 0)

	err := c.WriteMessage(OpBinary, []byte("x"))
	if err == nil {
		t.Fatal("write to a failing transport succeeded")
	}
	var ce *CloseError
	if !errors.As(c.closedWriteErr(), &ce) || ce.Code != StatusGoingAway {
		t.Fatalf("recorded error = %v, want the closer's 1001 CloseError", c.closedWriteErr())
	}
}

// hookWriteConn is a net.Conn whose Write runs a hook before failing — a
// deterministic stand-in for a concurrent Close winning mid-write.
type hookWriteConn struct{ hook func() }

func (h hookWriteConn) Read(_ []byte) (int, error) { return 0, io.EOF }
func (h hookWriteConn) Write(_ []byte) (int, error) {
	h.hook()
	return 0, errors.New("simulated write failure")
}
func (h hookWriteConn) Close() error                { return nil }
func (h hookWriteConn) LocalAddr() net.Addr         { return fakeAddr{} }
func (h hookWriteConn) RemoteAddr() net.Addr        { return fakeAddr{} }
func (h hookWriteConn) SetDeadline(time.Time) error { return nil }
func (h hookWriteConn) SetReadDeadline(time.Time) error {
	return nil
}
func (h hookWriteConn) SetWriteDeadline(time.Time) error { return nil }

// TestCloseRespectsWriteTimeout pins the close-frame write bound for a
// connection with [WithWriteTimeout]: the close must arm the connection's
// own bound, not a separate constant, so a caller that tuned the write
// timeout to bound teardown gets that bound.
func TestCloseRespectsWriteTimeout(t *testing.T) {
	nc := &immediateConn{}
	c := newRawConn(nc, nc, true, 1<<20, 0, 250*time.Millisecond)

	err := c.Close(StatusNormalClosure, "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Close: got %v, want io.EOF for a normal closure", err)
	}
	dl := nc.lastArmed()
	if d := time.Until(dl) - 250*time.Millisecond; d < -100*time.Millisecond || d > 100*time.Millisecond {
		t.Fatalf("close armed a write deadline %v out, want about 250ms", time.Until(dl))
	}
}

// TestCloseFallbackBoundWithoutWriteTimeout covers the other branch: with no
// write timeout set, the fixed closeWriteTimeout must still arm, so an
// untuned connection cannot be held open forever by a silent peer.
func TestCloseFallbackBoundWithoutWriteTimeout(t *testing.T) {
	nc := &immediateConn{}
	c := newRawConn(nc, nc, true, 1<<20, 0, 0)

	err := c.Close(StatusNormalClosure, "")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Close: got %v, want io.EOF for a normal closure", err)
	}
	dl := nc.lastArmed()
	if d := time.Until(dl) - closeWriteTimeout; d < -100*time.Millisecond || d > 100*time.Millisecond {
		t.Fatalf("close armed a write deadline %v out, want about %v", time.Until(dl), closeWriteTimeout)
	}
}

// TestClosedSignal pins the race-free close signal a background writer needs:
// false while open, true after Close. The concurrent read loop exists to
// exercise the atomic read under the race detector; the value a concurrent
// reader observes is legitimately either, so only the stable endpoints are
// asserted.
func TestClosedSignal(t *testing.T) {
	c := newRawConn(&immediateConn{}, &immediateConn{}, true, 1<<20, 0, 0)
	if c.Closed() {
		t.Fatal("Closed() true on a fresh connection")
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				_ = c.Closed()
			}
		})
	}
	_ = c.Close(StatusNormalClosure, "")
	wg.Wait()

	if !c.Closed() {
		t.Fatal("Closed() false after Close")
	}
}

// TestTerminalReadErrorLeavesConnectionClosed pins finish's state store: a
// terminal error recorded by the read path (here a transport EOF) must
// leave the connection closed — Closed() true, and a later write fails with
// the recorded error. If the state store were skipped the connection would
// be in a torn state: the terminal error recorded but the connection still
// open, so the later write would silently succeed.
func TestTerminalReadErrorLeavesConnectionClosed(t *testing.T) {
	// An empty stream: the first read hits EOF, a terminal transport error.
	fc := &fakeConn{}
	c := newSession(newRawConn(fc, fc, true, 1<<20, 0, 0), nil)
	_, _, err := c.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("terminal read = %v, want io.EOF", err)
	}
	if !c.Closed() {
		t.Fatal("Closed() false after the terminal read error")
	}
	err = c.WriteText("late")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("write after terminal error = %v, want the recorded error (io.EOF)", err)
	}
}

// TestDefaultWriteTimeoutApplies pins the default write bound: it must be a
// positive bound on both faces, never zero. Zero is the documented
// opt-out (unbounded writes); a zero default would let a blackholed peer
// wedge a write — and, with it, Close — forever.
func TestDefaultWriteTimeoutApplies(t *testing.T) {
	if defaultWriteTimeout <= 0 {
		t.Fatalf("default write bound = %v, want a positive bound", defaultWriteTimeout)
	}
	if got := NewUpgrader().writeTimeout; got <= 0 {
		t.Fatalf("server default write bound = %v, want the positive default", got)
	}

	// Client face: a dialed session must carry the same bound.
	up := NewUpgrader()
	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, _ *Session) error { return nil }))
	s := httptest.NewServer(mux)
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, wsURL(s.URL)+"/ws")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(StatusNormalClosure, "")
	if got := c.raw.writeTimeout; got <= 0 {
		t.Fatalf("client default write bound = %v, want the positive default", got)
	}
}
