package ws

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// This file hammers the session and raw state machines from multiple
// goroutines to find data races, lost close codes, and deadlocks. Run with:
//
//	go test ./ws -race -count=5 -run
//	'TestConcurrent|TestAutoPong|TestPongConcurrent|TestRawConcurrent|TestRead|TestWrite'
//
// The documented contract under test:
//   - WriteMessage, WriteFrame, Pong, and Close are safe from any goroutine.
//   - ReadMessage / ReadEvent is single-goroutine, but may race with a
//     concurrent Close — and the read goroutine may itself write (session
//     auto-pong, the raw application's pong answer), so the write path
//     must survive reader-goroutine writes interleaved with app writes.
//   - The first close wins; every other caller observes the same recorded
//     error, and closeErr is stable once state becomes stClosed.
//
// net.Pipe is synchronous: every write blocks until the other end reads.
// Any test that closes a connection without something reading the far end
// deadlocks in the close-frame write, so every test keeps a drain
// goroutine on any end it is not reading itself, and waits on drains with
// timeouts rather than trusting they will finish.

// pipeConnPair builds two Sessions facing each other over an in-memory
// pipe — no sockets, no TLS, so the tests are fast and hermetic.
func pipeConnPair() (server, client *Session) {
	sr, cr := net.Pipe()
	return newSession(newRawConn(sr, sr, false, 1<<20, 0, 0), nil),
		newSession(newRawConn(cr, cr, true, 1<<20, 0, 0), nil)
}

// drain reads conn until it terminates, then signals done. Use it on a pipe
// end the test does not read itself, so close-frame writes have a reader.
func drain(tb testing.TB, conn *Session) <-chan struct{} {
	tb.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			// The documented termination signals are an error — [io.EOF] for a
			// normal closure, anything else an abnormal end — so checking err
			// alone is sufficient and the loop cannot spin on a 1000 close.
			if err != nil {
				return
			}
		}
	}()
	tb.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			tb.Errorf("drain on conn %d did not terminate", conn.ID())
		}
	})
	return done
}

// stressIters repeats each test body; 1 under -short.
func stressIters(t *testing.T) int {
	t.Helper()
	if testing.Short() {
		return 1
	}
	return 200
}

// sayGoodbyeRead runs the full RFC 6455 §7.1.1 close on a session: shut the
// write side, run the read side to its terminal with Drain (that read is
// what records the close code, §7.1.5), then take the transport down. Use
// it when a test needs the recorded close code to be the peer's.
func sayGoodbyeRead(c *Session, code int, reason string) {
	_ = c.Shutdown(code, reason)
	_ = c.Drain()
	_ = c.Close()
}

// TestConcurrentClose: N goroutines call Shutdown with different codes at
// once. Exactly one gets its close frame onto the wire; the rest must report
// that this side is already done, so no second Close frame is ever sent
// (RFC 6455 5.5.1).
func TestConcurrentClose(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		drain(t, s)
		drain(t, c)
		const n = 16
		errs := make([]error, n)
		var wg sync.WaitGroup
		for g := range n {
			wg.Go(func() {
				// Distinct, valid, non-normal codes so the winner is
				// identifiable.
				errs[g] = c.Shutdown(2000+g, "closer")
			})
		}
		wg.Wait()
		sayGoodbye(s, StatusNormalClosure, "") // release the s-side drain
		winners := 0
		for g, e := range errs {
			if e == nil {
				winners++
				continue
			}
			// A loser reports either that this side is already shut
			// (ErrClosed) or, if the peer's answer had already resolved the
			// handshake by the time it tried, the recorded close error.
			var ce *CloseError
			if !errors.Is(e, ErrClosed) && !errors.As(e, &ce) {
				t.Fatalf("iteration %d: goroutine %d saw %v, want nil, ErrClosed, or a recorded close error", i, g, e)
			}
		}
		if winners != 1 {
			t.Fatalf("iteration %d: %d goroutines wrote a close frame, want exactly 1", i, winners)
		}
		_ = c.Close()
	}
}

// TestReadAfterClose is the regression test for the closeErr data race: a
// reader that observes state == stClosed must read a stable, published
// closeErr. Previously closeErr was written after the state transition
// without a lock, racing exactly this path.
func TestReadAfterClose(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		// s pumps, so it answers c's close frame with its own; c then reads
		// that answer, which is what §7.1.5 makes the connection's close code.
		drain(t, s)
		shutdownErr := c.Shutdown(StatusMessageTooBig, "too big")
		if shutdownErr != nil {
			t.Fatalf("iteration %d: Shutdown: %v", i, shutdownErr)
		}
		op, data, err := c.ReadMessage()
		if op != 0 || data != nil {
			t.Fatalf("iteration %d: ReadMessage after close = (%d, %v, %v), want (0, nil, ...)", i, op, data, err)
		}
		code, reason, ok := CloseCode(err)
		if !ok || code != StatusMessageTooBig || reason != "too big" {
			t.Fatalf("iteration %d: CloseCode(%v) = (%d, %q, %v), want (1009, \"too big\", true)", i, err, code, reason, ok)
		}
	}
}

// TestWriteWhileClosing races many writers against a single Close; the
// writers must terminate with either nil or the recorded close error, never
// panic, and never observe a torn state.
func TestWriteWhileClosing(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		drain(t, s)
		drain(t, c)
		const n = 8
		msg := make([]byte, 64)
		errs := make([]error, n)
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for g := range n {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						errs[g] = nil
						return
					default:
					}
					writeErr := c.WriteMessage(OpText, msg)
					if writeErr != nil {
						errs[g] = writeErr
						return
					}
				}
			})
		}
		time.Sleep(time.Millisecond) // let the writers start
		sayGoodbye(c, StatusGoingAway, "closing")
		close(stop)
		wg.Wait()
		for g, err := range errs {
			if err == nil {
				continue
			}
			// A writer that lost the race reports either that this side is
			// shut (ErrClosed, the write half went down first) or the
			// recorded close error (the peer's answer resolved the
			// handshake before the write was attempted).
			if errors.Is(err, ErrClosed) {
				continue
			}
			var ce *CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("iteration %d: writer %d got %v, want ErrClosed or *CloseError", i, g, err)
			}
			if ce.Code != StatusGoingAway {
				t.Fatalf("iteration %d: writer %d saw code %d, want %d", i, g, ce.Code, StatusGoingAway)
			}
		}
	}
}

// TestReadWhileClosing runs the read loop and a concurrent local Close on
// the same connection. Whichever wins, the read must terminate with a
// consistent terminal error — and the race detector must stay quiet.
func TestReadWhileClosing(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		drain(t, c) // so s's close-frame write has a reader
		type outcome struct {
			op  Op
			err error
		}
		out := make(chan outcome, 1)
		go func() {
			op, _, err := s.ReadMessage()
			out <- outcome{op, err}
		}()
		// Either the local close wins (transport error from the closed
		// pipe) or the read races ahead of it. Both are fine; a hang or
		// panic is not.
		sayGoodbye(c, StatusPolicyViolation, "race test")
		sayGoodbye(s, StatusPolicyViolation, "race test")
		select {
		case r := <-out:
			if r.op != 0 {
				t.Fatalf("iteration %d: read after teardown returned op %d", i, r.op)
			}
			if r.err == nil {
				t.Fatalf("iteration %d: ReadMessage returned nil error after teardown", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: ReadMessage did not terminate after close", i)
		}
	}
}

// TestConcurrentWriteAndReadExercisesLocks runs the documented happy path
// under contention: a reader loop, several concurrent writers, and a final
// close. The point is to make the write mutex and the state machine do a
// lot of interleaving in a small, repeatable way.
func TestConcurrentWriteAndReadExercisesLocks(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		// Drains on both ends: on a synchronous pipe every close needs the
		// other side to keep reading until teardown, so neither drain may
		// exit early.
		doneS := drain(t, s)
		doneC := drain(t, c)
		const writers = 4
		var wg sync.WaitGroup
		for range writers {
			wg.Go(func() {
				for {
					writeErr := c.WriteMessage(OpText, []byte("abcdefgh"))
					if writeErr != nil {
						return
					}
				}
			})
		}
		time.Sleep(100 * time.Millisecond) // let the writers interleave
		sayGoodbye(c, StatusNormalClosure, "")
		select {
		case <-doneC:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: client side never terminated", i)
		}
		select {
		case <-doneS:
		case <-time.After(10 * time.Second):
			t.Fatalf("iteration %d: server side never terminated", i)
		}
		wg.Wait() // writers must all have been released by the close
	}
}

// TestWriteAfterCloseErrors pins the write-after-close contract: a write on
// a closed connection must never report success. After a non-normal close it
// carries the recorded code and reason; after a normal closure (1000) it is
// ErrClosed, because a normal closure records a nil terminal error and
// silent success for an unsent frame would spin a writer goroutine forever.
//
// The recorded code is the one *received*, so each case reads the connection
// to its terminal after Shutdown: s answers the close frame, and reading that
// answer is what records the code (§7.1.5).
func TestWriteAfterCloseErrors(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		drain(t, s) // reads c's close frame and answers it
		sayGoodbyeRead(c, StatusPolicyViolation, "gone")
		err := c.WriteMessage(OpText, []byte("x"))
		if err == nil {
			t.Fatalf("iteration %d: write after non-normal close returned nil", i)
		} else {
			code, _, ok := CloseCode(err)
			if !ok || code != StatusPolicyViolation {
				t.Fatalf("iteration %d: write error %v, want code 1008", i, err)
			}
		}

		s2, c2 := pipeConnPair()
		drain(t, s2)
		sayGoodbyeRead(c2, StatusNormalClosure, "")
		err = c2.WriteMessage(OpText, []byte("x"))
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("iteration %d: write after normal close = %v, want ErrClosed", i, err)
		}
	}
}

// TestAutoPongInterleavesWithAppWrites is the production interleaving the
// other tests in this file do not create: the session read goroutine
// answers pings with pongs inline, so it writes on the very write path the
// app's writer goroutines use. The write mutex and the write scratch must
// survive reader-goroutine writes interleaved with app writes; the race
// detector is the judge.
func TestAutoPongInterleavesWithAppWrites(t *testing.T) {
	for i := range stressIters(t) {
		sr, cr := net.Pipe()
		peer := newRawConn(sr, sr, false, 1<<20, 0, 0)
		c := newSession(newRawConn(cr, cr, true, 1<<20, 0, 0), nil)

		// peer's read loop consumes c's app text and c's auto-pongs.
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			for {
				_, eventErr := peer.ReadEvent()
				if eventErr != nil {
					return
				}
			}
		}()

		// c's read loop: auto-pongs every ping and stays alive until
		// close — pings are consumed inline, data frames never arrive.
		cTerm := make(chan error, 1)
		go func() {
			for {
				_, _, err := c.ReadMessage()
				if err != nil {
					cTerm <- err
					return
				}
			}
		}()

		const writers = 4
		var wg sync.WaitGroup
		for range writers {
			wg.Go(func() {
				for {
					writeErr := c.WriteMessage(OpText, []byte("app-write"))
					if writeErr != nil {
						return
					}
				}
			})
		}

		// Feed c pings so its read goroutine auto-pongs — writes — while
		// the app writers run.
		for k := range 16 {
			pingErr := peer.WriteFrame(OpPing, []byte{byte(k)}, false)
			if pingErr != nil {
				break
			}
		}

		sayGoodbye(c, StatusNormalClosure, "")
		wg.Wait()
		select {
		case err := <-cTerm:
			if err == nil {
				t.Fatalf("iteration %d: c's read loop ended with nil error", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: c's read loop did not terminate", i)
		}
		select {
		case <-peerDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: peer's read loop did not terminate", i)
		}
	}
}

// TestPongConcurrentWithWrites pins the "Pong is safe from any goroutine"
// half of the contract on the raw face, where Pong lives (the session
// surface does not expose it): dedicated Pong goroutines and WriteFrame
// goroutines hammer the same write path, ending in a Close.
func TestPongConcurrentWithWrites(t *testing.T) {
	for i := range stressIters(t) {
		sr, cr := net.Pipe()
		peer := newRawConn(sr, sr, false, 1<<20, 0, 0)
		c := newRawConn(cr, cr, true, 1<<20, 0, 0)

		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			for {
				_, eventErr := peer.ReadEvent()
				if eventErr != nil {
					return
				}
			}
		}()

		const writers = 4
		var wg sync.WaitGroup
		for range writers {
			wg.Go(func() {
				for {
					writeErr := c.WriteFrame(OpText, []byte("x"), false)
					if writeErr != nil {
						return
					}
				}
			})
		}
		for range 2 {
			wg.Go(func() {
				for {
					pongErr := c.Pong([]byte("probe"))
					if pongErr != nil {
						return
					}
				}
			})
		}
		sayGoodbye(c, StatusNormalClosure, "")
		wg.Wait()
		select {
		case <-peerDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: peer's read loop did not terminate", i)
		}
	}
}

// TestRawConcurrentReadWriteClose is the raw face under the same stress:
// a ReadEvent loop that answers pings with Pong — the documented raw
// pattern, the application is the responder — while app writers hammer
// WriteFrame and a final Close lands. Raw mode has no auto-pong, so this
// is the only way the read goroutine writes here.
func TestRawConcurrentReadWriteClose(t *testing.T) {
	for i := range stressIters(t) {
		sr, cr := net.Pipe()
		peer := newRawConn(sr, sr, false, 1<<20, 0, 0)
		c := newRawConn(cr, cr, true, 1<<20, 0, 0)

		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			for {
				_, eventErr := peer.ReadEvent()
				if eventErr != nil {
					return
				}
			}
		}()

		// c's read loop answers pings itself, exactly as the raw
		// examples do — the read goroutine writes the pong.
		cTerm := make(chan error, 1)
		go func() {
			for {
				ev, err := c.ReadEvent()
				if err != nil {
					cTerm <- err
					return
				}
				if ev.Op == OpPing {
					pingErr := c.Pong(ev.Payload)
					if pingErr != nil {
						cTerm <- pingErr
						return
					}
				}
			}
		}()

		const writers = 4
		var wg sync.WaitGroup
		for range writers {
			wg.Go(func() {
				for {
					writeErr := c.WriteFrame(OpText, []byte("raw-write"), false)
					if writeErr != nil {
						return
					}
				}
			})
		}

		for k := range 16 {
			pingErr := peer.WriteFrame(OpPing, []byte{byte(k)}, false)
			if pingErr != nil {
				break
			}
		}

		sayGoodbye(c, StatusNormalClosure, "")
		wg.Wait()
		select {
		case err := <-cTerm:
			if err == nil {
				t.Fatalf("iteration %d: raw read loop ended with nil error", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: raw read loop did not terminate", i)
		}
		select {
		case <-peerDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: peer's read loop did not terminate", i)
		}
	}
}

// TestDrainRacesClose: Drain and Close racing on one connection must end in
// a terminal, not a panic, a hang, or a torn state — the read side and the
// transport teardown may observe each other in either order.
func TestDrainRacesClose(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		// All three race: the drain, the teardown, and the close-frame
		// send (whose write blocks on the synchronous pipe until the
		// drain reads it).
		errs := make([]error, 3)
		var wg sync.WaitGroup
		wg.Go(func() { errs[0] = s.Drain() })
		wg.Go(func() { errs[1] = c.Close() })
		wg.Go(func() { errs[2] = c.Shutdown(StatusGoingAway, "bye") })
		wg.Wait()
		// The drain always ends in a terminal: the clean end, the
		// recorded close, or the transport error when Close cut the pipe
		// first.
		if errs[0] == nil {
			t.Fatalf("iteration %d: Drain = nil, want a terminal error", i)
		}
		if errs[1] != nil {
			t.Fatalf("iteration %d: Close = %v, want nil", i, errs[1])
		}
	}
}
