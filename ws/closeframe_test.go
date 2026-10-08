package ws

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// TestShutdown pins [RawConn.Shutdown]'s contract: it puts the close frame on
// the wire and reports the status of *that write* — not how the connection
// ended, which is what the read's terminal error reports — and it leaves the
// transport up.
func TestShutdown(t *testing.T) {
	t.Parallel()

	t.Run("writeSucceeds", func(t *testing.T) {
		t.Parallel()
		// A real TCP pair: the server accepts and reads, so the client's
		// close frame reaches the wire.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, okErr := ln.Accept()
				if okErr != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 256)
				for {
					_, readErr := conn.Read(buf)
					if readErr != nil {
						_ = conn.Close()

						return
					}
				}
			}
		}()
		serverConn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		client := newRawConn(serverConn, serverConn, true, 1<<20, 0, 0)

		writeErr := client.Shutdown(StatusGoingAway, "bye")
		if writeErr != nil {
			t.Fatalf("Shutdown on a live transport = %v, want nil (frame written)", writeErr)
		}
		// Shutdown half-closes the write side only: the connection is
		// closing, not closed, and a second Shutdown sends no second frame
		// (RFC 6455 5.5.1) — it reports that this side is already done.
		if !client.Closed() {
			t.Fatal("Closed() false after Shutdown; the write side should be shut")
		}
		second := client.Shutdown(StatusNormalClosure, "")
		if !errors.Is(second, ErrClosed) {
			t.Fatalf("second Shutdown = %v, want ErrClosed (no second close frame)", second)
		}
		// Close is the transport teardown, and it is idempotent.
		closeErr := client.Close()
		if closeErr != nil {
			t.Fatalf("Close = %v, want nil", closeErr)
		}
		closeErr = client.Close()
		if closeErr != nil {
			t.Fatalf("second Close = %v, want nil (idempotent)", closeErr)
		}
		_ = serverConn.Close()
	})

	t.Run("stalledTransport", func(t *testing.T) {
		t.Parallel()
		// A blackhole transport whose Write blocks until the write bound
		// fires: Shutdown must report the write failure, and a close frame
		// that cannot reach the peer fails the connection like any other
		// broken-pipe write.
		nc := &deadlineConn{
			entered: make(chan struct{}),
			stuck:   make(chan struct{}), // never closed: a permanent blackhole
			closed:  make(chan struct{}),
		}
		client := newRawConn(nc, nc, true, 1<<20, 0, 50*time.Millisecond)
		writeErr := client.Shutdown(StatusGoingAway, "gone")
		if !errors.Is(writeErr, os.ErrDeadlineExceeded) {
			t.Fatalf("Shutdown on a stalled transport = %v, want the deadline error", writeErr)
		}
		// The connection is failed: a later write reports the recorded
		// error at once instead of re-stalling.
		late := client.WriteText("late")
		if !errors.Is(late, writeErr) {
			t.Fatalf("write after a failed Shutdown = %v, want the recorded %v", late, writeErr)
		}
	})

	t.Run("alreadyClosed", func(t *testing.T) {
		t.Parallel()
		s, c := pipeConnPair()
		drain(t, s)
		drain(t, c)
		sayGoodbye(c, StatusNormalClosure, "")
		writeErr := c.raw.Shutdown(StatusGoingAway, "late")
		if !errors.Is(writeErr, ErrClosed) {
			t.Fatalf("Shutdown after a normal close = %v, want ErrClosed", writeErr)
		}
	})

	t.Run("badCode", func(t *testing.T) {
		t.Parallel()
		s, c := pipeConnPair()
		drain(t, s)
		drain(t, c)
		writeErr := c.raw.Shutdown(999, "")
		if writeErr == nil || !errors.Is(writeErr, errBadCloseCode) {
			t.Fatalf("Shutdown(999) = %v, want errBadCloseCode", writeErr)
		}
		// The connection is untouched: a write still succeeds, and the
		// polite close still works afterwards.
		writeErr2 := c.WriteText("still open")
		if writeErr2 != nil {
			t.Fatalf("write after a refused Shutdown = %v, want nil", writeErr2)
		}
		sayGoodbye(c, StatusNormalClosure, "")
	})
}

// TestCloseIsAbrupt pins [RawConn.Close] as pure teardown: it never blocks,
// never writes, and sends no close frame. A connection closed without a
// preceding Shutdown is an abrupt close — the peer sees the transport go down
// with no Close frame, which RFC 6455 7.1.5 resolves to 1006.
func TestCloseIsAbrupt(t *testing.T) {
	t.Parallel()
	fc := &fakeConn{}
	c := newRawConn(fc, fc, false, 1<<20, 0, 0)

	closeErr := c.Close()
	if closeErr != nil {
		t.Fatalf("Close = %v, want nil", closeErr)
	}
	if len(fc.written) != 0 {
		t.Fatalf("Close wrote %d bytes to the wire, want none (no close frame)", len(fc.written))
	}
	if !c.Closed() {
		t.Fatal("Closed() false after Close")
	}
	// The peer end sees no Close frame at all: the transport simply ends.
	peer := newRawConn(&fakeConn{}, &fakeConn{}, true, 1<<20, 0, 0)
	peerCloseErr := peer.Close()
	if peerCloseErr != nil {
		t.Fatalf("peer Close = %v, want nil", peerCloseErr)
	}
}

// TestCloseNeverBlocksOnAStalledTransport is the regression for the wedge the
// old blocking Close had: teardown takes no write lock and performs no write,
// so a peer that has stopped reading cannot hold it open.
func TestCloseNeverBlocksOnAStalledTransport(t *testing.T) {
	t.Parallel()
	nc := &deadlineConn{
		entered: make(chan struct{}),
		stuck:   make(chan struct{}), // never closed: a permanent blackhole
		closed:  make(chan struct{}),
	}
	c := newRawConn(nc, nc, true, 1<<20, 0, time.Hour)

	// Wedge a writer inside Write, holding the write mutex for the full
	// (here: one hour) write bound.
	stuck := make(chan error, 1)
	go func() { stuck <- c.WriteMessage(OpText, make([]byte, 64<<10)) }()
	<-nc.entered

	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind a stuck writer: teardown must not take the write lock")
	}
}

// TestShutdownLeavesTheReadSideLive is the CLOSING state as RFC 6455 draws it:
// §5.5.1 forbids sending more *data* frames after a Close frame, but says
// nothing about receiving, and §7.1.5 defines the connection's close code as
// the first Close frame *received*. So after Shutdown the peer's frames must
// still arrive, and its close must still resolve the connection.
func TestShutdownLeavesTheReadSideLive(t *testing.T) {
	t.Parallel()
	sr, cr := net.Pipe()
	server := newRawConn(sr, sr, false, 1<<20, 0, 0)
	client := newRawConn(cr, cr, true, 1<<20, 0, 0)
	defer server.Close()
	defer client.Close()

	// The client pumps first: net.Pipe is synchronous, so the server's close
	// frame needs a reader before it can be written at all.
	clientDone := make(chan error, 1)
	go func() {
		for {
			_, err := client.ReadEvent()
			if err != nil {
				clientDone <- err

				return
			}
		}
	}()

	// The server shuts its write side, then keeps reading — the §7.1.1
	// shutdown(SHUT_WR) then recv-until-0 shape.
	shutdownErr := server.Shutdown(StatusGoingAway, "leaving")
	if shutdownErr != nil {
		t.Fatalf("server Shutdown = %v, want nil", shutdownErr)
	}
	// A data write after Shutdown is refused (§5.5.1).
	writeErr := server.WriteText("too late")
	if !errors.Is(writeErr, ErrClosed) {
		t.Fatalf("write after Shutdown = %v, want ErrClosed", writeErr)
	}

	ev, err := server.ReadEvent()
	if err != nil {
		t.Fatalf("server ReadEvent after Shutdown = %v, want the client's close event", err)
	}
	if ev.Op != OpClose {
		t.Fatalf("server read %v after Shutdown, want the peer's OpClose", ev.Op)
	}
	// Both frames exchanged: §5.5.1 requires the transport down, so the next
	// read is the terminal and the read loop ends on its own.
	_, err = server.ReadEvent()
	if !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("server second read = %v, want the terminal error", err)
	}
	<-clientDone
}

// TestShutdownWireRaw pins what Shutdown puts on the wire: the peer's close
// arrives as an OpClose event with the code and reason intact, so the
// write-status API and the event API cannot drift apart.
func TestShutdownWireRaw(t *testing.T) {
	t.Parallel()
	sr, cr := net.Pipe()
	server := newRawConn(sr, sr, false, 1<<20, 0, 0)
	client := newRawConn(cr, cr, true, 1<<20, 0, 0)

	// Both ends pump in their own goroutines (one reader per transport);
	// the main goroutine only writes and asserts.
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for {
			_, eventErr := client.ReadEvent()
			if eventErr != nil {
				return
			}
		}
	}()
	serverEvent := make(chan Event, 1)
	serverErr := make(chan error, 1)
	go func() {
		event, err := server.ReadEvent()
		serverEvent <- event
		serverErr <- err
	}()

	writeErr := client.Shutdown(StatusGoingAway, "bye")
	if writeErr != nil {
		t.Fatalf("Shutdown = %v, want nil", writeErr)
	}

	// The server saw the peer's close as an event: code and reason intact.
	select {
	case event := <-serverEvent:
		if event.Op != OpClose || event.Code != StatusGoingAway || event.Reason != "bye" {
			t.Fatalf("server ReadEvent = %+v, want the 1001 \"bye\" close event", event)
		}
		readErr := <-serverErr
		if readErr != nil {
			t.Fatalf("server ReadEvent error = %v, want nil", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never delivered the close event")
	}
	// Release the loop's close replies, which have no readers past this
	// point, by tearing both transports down.
	sayGoodbye(server, StatusNormalClosure, "")
	sayGoodbye(client, StatusNormalClosure, "")
	<-clientDone
}

// TestDrain pins [RawConn.Drain]: the read side run to its terminal as one
// call — the middle step of RFC 6455 §7.1.1 (Shutdown, drain, Close) —
// discarding the traffic on the way and reporting only the terminal, so the
// writer's half of the connection learns the close code (§7.1.5) without
// running the message loop.
func TestDrain(t *testing.T) {
	t.Parallel()

	// pipe is a raw pair over net.Pipe — synchronous, so every write
	// blocks until the other end reads and the draining side is always
	// started before the initiator writes.
	pipe := func() (peer, conn *RawConn) {
		sr, cr := net.Pipe()

		return newRawConn(sr, sr, false, 1<<20, 0, 0), newRawConn(cr, cr, true, 1<<20, 0, 0)
	}

	// drainPeer reads a raw peer to its terminal so the drained side's
	// writes (the close echo) complete.
	drainPeer := func(t *testing.T, peer *RawConn) <-chan struct{} {
		t.Helper()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				_, err := peer.ReadEvent()
				if err != nil {
					return
				}
			}
		}()

		return done
	}

	// startDrain runs conn.Drain and reports its terminal.
	startDrain := func(conn *RawConn) <-chan error {
		done := make(chan error, 1)
		go func() { done <- conn.Drain() }()

		return done
	}

	t.Run("learnsPeerCloseCode", func(t *testing.T) {
		t.Parallel()
		// The peer initiates with an application code; the writer's half
		// drains instead of running the loop.
		peer, conn := pipe()
		drainDone := startDrain(conn)
		_ = peer.Shutdown(4001, "app reason")
		done := drainPeer(t, peer)
		drainErr := <-drainDone
		var ce *CloseError
		if !errors.As(drainErr, &ce) {
			t.Fatalf("Drain = %v, want a *CloseError", drainErr)
		}
		if ce.Code != 4001 || ce.Reason != "app reason" {
			t.Fatalf("Drain close = %d %q, want 4001 %q", ce.Code, ce.Reason, "app reason")
		}
		<-done
		_ = conn.Close()
	})

	t.Run("cleanEndIsEOF", func(t *testing.T) {
		t.Parallel()
		peer, conn := pipe()
		drainDone := startDrain(conn)
		_ = peer.Shutdown(StatusNormalClosure, "")
		done := drainPeer(t, peer)
		drainErr := <-drainDone
		if !errors.Is(drainErr, io.EOF) {
			t.Fatalf("Drain = %v, want io.EOF (clean end)", drainErr)
		}
		<-done
		_ = conn.Close()
	})

	t.Run("discardsPingAndData", func(t *testing.T) {
		t.Parallel()
		// The peer pings, sends data, then closes. The drain consumes all
		// of it: RawConn never pongs on the application's behalf, so the
		// first thing the peer reads back must be the close echo, not a
		// pong.
		peer, conn := pipe()
		first := make(chan Event, 1)
		go func() {
			_ = peer.Ping([]byte("hb"))
			_ = peer.WriteMessage(OpText, []byte("late data"))
			_ = peer.Shutdown(4002, "done")
			for {
				ev, err := peer.ReadEvent()
				if err != nil {
					return
				}
				select {
				case first <- ev:
				default:
				}
			}
		}()
		drainErr := conn.Drain()
		var ce *CloseError
		if !errors.As(drainErr, &ce) || ce.Code != 4002 {
			t.Fatalf("Drain = %v, want close 4002", drainErr)
		}
		select {
		case ev := <-first:
			if ev.Op != OpClose || ev.Code != 4002 {
				t.Fatalf("peer's first event back = %+v, want the close echo (no pong before it)", ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("peer never read the close echo back")
		}
		_ = conn.Close()
	})

	t.Run("alreadyTerminalFastFails", func(t *testing.T) {
		t.Parallel()
		// Read to the terminal first; a second Drain returns the recorded
		// terminal at once, without touching the transport.
		peer, conn := pipe()
		firstDone := startDrain(conn)
		_ = peer.Shutdown(StatusGoingAway, "gone")
		done := drainPeer(t, peer)
		first := <-firstDone
		var ce *CloseError
		if !errors.As(first, &ce) || ce.Code != StatusGoingAway {
			t.Fatalf("first Drain = %v, want close 1001", first)
		}
		second := conn.Drain()
		var again *CloseError
		if !errors.As(second, &again) || again.Code != StatusGoingAway {
			t.Fatalf("second Drain = %v, want the same recorded terminal", second)
		}
		<-done
	})

	t.Run("abruptCloseReportsCleanEnd", func(t *testing.T) {
		t.Parallel()
		// A Close without a Shutdown tears the transport down without a
		// terminal error of its own: Drain reports a clean end, at once.
		peer, conn := pipe()
		closeErr := conn.Close()
		if closeErr != nil {
			t.Fatalf("Close = %v, want nil", closeErr)
		}
		drainErr := conn.Drain()
		if !errors.Is(drainErr, io.EOF) {
			t.Fatalf("Drain after abrupt Close = %v, want io.EOF", drainErr)
		}
		_ = peer.Close()
	})
}

// TestSessionDrain is TestDrain on the session face: the same terminal
// contract — the writer's half learns the peer's close code without running
// the message loop.
func TestSessionDrain(t *testing.T) {
	t.Parallel()
	server, client := pipeConnPair()
	drainDone := make(chan error, 1)
	go func() { drainDone <- client.Drain() }()
	_ = server.Shutdown(4003, "server says")
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			_, _, err := server.ReadMessage()
			if err != nil {
				return
			}
		}
	}()
	drainErr := <-drainDone
	var ce *CloseError
	if !errors.As(drainErr, &ce) || ce.Code != 4003 || ce.Reason != "server says" {
		t.Fatalf("Drain = %v, want close 4003 %q", drainErr, "server says")
	}
	<-serverDone
}
