package ws

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestCloseFrame pins [RawConn.CloseFrame]'s contract: the low-level half of
// [RawConn.Close] that reports the close-frame write status instead of the
// recorded terminal error.
func TestCloseFrame(t *testing.T) {
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

		writeErr := client.CloseFrame(StatusGoingAway, "bye")
		if writeErr != nil {
			t.Fatalf("CloseFrame on a live transport = %v, want nil (frame written)", writeErr)
		}
		// Close after CloseFrame: the recorded terminal error, idempotent.
		termErr := client.Close(StatusNormalClosure, "")
		code, reason, ok := CloseCode(termErr)
		if !ok || code != StatusGoingAway || reason != "bye" {
			t.Fatalf("Close after CloseFrame = %v (%d %q), want the recorded 1001 bye",
				termErr, code, reason)
		}
		_ = serverConn.Close()
	})

	t.Run("stalledTransport", func(t *testing.T) {
		t.Parallel()
		// A blackhole transport whose Write blocks until the write bound
		// fires: CloseFrame must report the write failure, not the
		// terminal error.
		nc := &deadlineConn{
			entered: make(chan struct{}),
			stuck:   make(chan struct{}), // never closed: a permanent blackhole
			closed:  make(chan struct{}),
		}
		client := newRawConn(nc, nc, true, 1<<20, 0, 50*time.Millisecond)
		writeErr := client.CloseFrame(StatusGoingAway, "gone")
		if !errors.Is(writeErr, os.ErrDeadlineExceeded) {
			t.Fatalf("CloseFrame on a stalled transport = %v, want the deadline error", writeErr)
		}
		// The connection is failed: a later write reports the recorded
		// close error at once instead of re-stalling.
		late := client.WriteText("late")
		code, _, ok := CloseCode(late)
		if !ok || code != StatusGoingAway {
			t.Fatalf("write after a failed CloseFrame = %v, want the recorded 1001", late)
		}
	})

	t.Run("alreadyClosed", func(t *testing.T) {
		t.Parallel()
		s, c := pipeConnPair()
		drain(t, s)
		drain(t, c)
		_ = c.Close(StatusNormalClosure, "")
		writeErr := c.raw.CloseFrame(StatusGoingAway, "late")
		if !errors.Is(writeErr, ErrClosed) {
			t.Fatalf("CloseFrame after a normal close = %v, want ErrClosed", writeErr)
		}
	})

	t.Run("badCode", func(t *testing.T) {
		t.Parallel()
		s, c := pipeConnPair()
		drain(t, s)
		drain(t, c)
		writeErr := c.raw.CloseFrame(999, "")
		if writeErr == nil || !errors.Is(writeErr, errBadCloseCode) {
			t.Fatalf("CloseFrame(999) = %v, want errBadCloseCode", writeErr)
		}
		// The connection is untouched: a write still succeeds, and the
		// ordinary Close still works.
		writeErr2 := c.WriteText("still open")
		if writeErr2 != nil {
			t.Fatalf("write after a refused CloseFrame = %v, want nil", writeErr2)
		}
		_ = c.Close(StatusNormalClosure, "")
	})
}

// TestCloseFrameRawWire pins what CloseFrame puts on the wire: the peer's
// close arrives as an OpClose event with the code and reason intact, so the
// write-status API and the event API cannot drift apart.
func TestCloseFrameRawWire(t *testing.T) {
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

	writeErr := client.CloseFrame(StatusGoingAway, "bye")
	if writeErr != nil {
		t.Fatalf("CloseFrame = %v, want nil", writeErr)
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
	_ = server.Close(StatusNormalClosure, "")
	_ = client.Close(StatusNormalClosure, "")
	<-clientDone
}
