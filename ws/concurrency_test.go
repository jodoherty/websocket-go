package ws

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// This file hammers the Conn state machine from multiple goroutines to find
// data races, lost close codes, and deadlocks. Run with:
//
//	go test ./ws -race -run TestConcurrent -count=5
//
// The documented contract under test:
//   - WriteMessage and Close are safe from any goroutine.
//   - ReadMessage is single-goroutine, but may race with a concurrent Close.
//   - The first close wins; every other caller observes the same recorded
//     error, and closeErr is stable once state becomes stClosed.
//
// net.Pipe is synchronous: every write blocks until the other end reads.
// Any test that closes a connection without something reading the far end
// deadlocks in the close-frame write, so every test keeps a drain
// goroutine on any end it is not reading itself, and waits on drains with
// timeouts rather than trusting they will finish.

// pipeConnPair builds two Conns facing each other over an in-memory pipe —
// no sockets, no TLS, so the tests are fast and hermetic.
func pipeConnPair() (server, client *Conn) {
	sr, cr := net.Pipe()
	return newConn(sr, sr, false, 1<<20, 0, 0), newConn(cr, cr, true, 1<<20, 0, 0)
}

// drain reads conn until it terminates, then signals done. Use it on a pipe
// end the test does not read itself, so close-frame writes have a reader.
func drain(t *testing.T, conn *Conn) <-chan struct{} {
	t.Helper()
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
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("drain on conn %d did not terminate", conn.ID())
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
			ce, ok := errors.AsType[*CloseError](err)
			if !ok || ce.Code != StatusMessageTooBig || ce.Reason != "too big" {
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
			op  int
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
