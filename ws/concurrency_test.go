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

// TestConcurrentClose: N goroutines call Close with different codes at once.
// Exactly one wins; every caller must observe the winner's recorded error.
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
				errs[g] = c.Close(2000+g, "closer")
			})
		}
		wg.Wait()
		_ = s.Close(StatusNormalClosure, "") // release the s-side drain
		for g, e := range errs {
			if g == 0 {
				continue
			}
			if !errors.Is(e, errs[0]) {
				t.Fatalf("iteration %d: goroutine %d saw %v, goroutine 0 saw %v", i, g, e, errs[0])
			}
		}
		var ce *CloseError
		if !errors.As(errs[0], &ce) {
			t.Fatalf("iteration %d: concurrent Close produced %v, want *CloseError", i, errs[0])
		}
		if ce.Code < 2000 || ce.Code > 2000+n-1 {
			t.Fatalf("iteration %d: winner code %d out of range", i, ce.Code)
		}
	}
}

// TestReadAfterClose is the regression test for the closeErr data race: a
// reader that observes state == stClosed must read a stable, published
// closeErr. Previously closeErr was written after the state transition
// without a lock, racing exactly this path.
func TestReadAfterClose(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		// The drain may consume the close frame first and win the close
		// race; either winner records the same code and reason, so the
		// assertions below hold in both cases.
		drain(t, s)
		err := c.Close(StatusMessageTooBig, "too big")
		if err != nil {
			var ce *CloseError
			if ok := errors.As(err, &ce); !ok || ce.Code != StatusMessageTooBig || ce.Reason != "too big" {
				t.Fatalf("iteration %d: Close: %v", i, err)
			}
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
		_ = c.Close(StatusGoingAway, "closing")
		close(stop)
		wg.Wait()
		for g, err := range errs {
			if err == nil {
				continue
			}
			var ce *CloseError
			if !errors.As(err, &ce) {
				t.Fatalf("iteration %d: writer %d got %v, want *CloseError", i, g, err)
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
		_ = c.Close(StatusPolicyViolation, "race test")
		_ = s.Close(StatusPolicyViolation, "race test")
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
		_ = c.Close(StatusNormalClosure, "")
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
func TestWriteAfterCloseErrors(t *testing.T) {
	for i := range stressIters(t) {
		s, c := pipeConnPair()
		drain(t, s) // reads c's close frame so the close completes
		_ = c.Close(StatusPolicyViolation, "gone")
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
		_ = c2.Close(StatusNormalClosure, "")
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

		_ = c.Close(StatusNormalClosure, "")
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
		_ = c.Close(StatusNormalClosure, "")
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

		_ = c.Close(StatusNormalClosure, "")
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
