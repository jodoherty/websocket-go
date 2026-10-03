package ws

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// This file covers the error branches the happy-path and fuzz tests rarely
// pin down: each readFrame rejection, and armIdle's ping-send path.

func TestReadFrameRejectsMalformed(t *testing.T) {
	cases := []struct {
		name     string
		isClient bool
		maxMsg   int64
		data     []byte
		wantSub  string
	}{
		{
			name:     "reserved bits set",
			isClient: true,
			data:     []byte{0x91, 0x00}, // RSV1 on a text frame
			wantSub:  "reserved bits",
		},
		{
			name:     "client received masked frame",
			isClient: true,
			data:     []byte{0x81, 0x85, 0, 1, 2, 3, 'H', 'i', 'X', 'X', 'X'},
			wantSub:  "masking violation",
		},
		{
			name:     "server received unmasked frame",
			isClient: false,
			data:     []byte{0x81, 0x02, 'H', 'i'},
			wantSub:  "masking violation",
		},
		{
			name:     "64-bit length with high bit set",
			isClient: true,
			data:     []byte{0x81, 127, 0x01, 0, 0, 0, 0, 0, 0, 0, 0},
			wantSub:  "frame too large",
		},
		{
			name:     "frame exceeds maxMsg",
			isClient: true,
			maxMsg:   100,
			data:     []byte{0x81, 126, 0x01, 0x2c}, // 300-byte unmasked frame, header only
			wantSub:  "exceeds the",
		},
		{
			name:     "control frame without FIN",
			isClient: true,
			data:     []byte{0x09, 0x00}, // ping, fin=0
			wantSub:  "invalid control frame",
		},
		{
			name:     "control frame over 125 bytes",
			isClient: true,
			data:     []byte{0x89, 126, 0, 200}, // ping, 16-bit length 200
			wantSub:  "invalid control frame",
		},
	}
	for _, tc := range cases {
		maxMsg := tc.maxMsg
		if maxMsg == 0 {
			maxMsg = 1 << 20
		}
		t.Run(tc.name, func(t *testing.T) {
			fc := newTestCodec(tc.data, tc.isClient)
			fc.maxMsg = maxMsg
			_, err := fc.readFrame()
			if err == nil {
				t.Fatal("readFrame accepted a malformed frame")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q, want substring %q", err, tc.wantSub)
			}
		})
	}
}

// TestKeepaliveProbeSequence covers the redesigned keepalive end to end on a
// real pipe: a silent peer is probed with a ping once the idle window
// elapses and killed with a timeout only after a second window. The peer
// end is drained so probe pings never block the synchronous pipe.
func TestKeepaliveProbeSequence(t *testing.T) {
	sr, cr := net.Pipe()
	defer cr.Close()
	defer sr.Close()
	c := newConn(cr, cr, true, 1<<20, 100*time.Millisecond, 0)

	// Drain everything the conn sends (probe pings).
	pings := make(chan int, 8)
	go func() {
		peer := &frameCodec{br: bufio.NewReader(sr), isClient: false, maxMsg: 1 << 20}
		for {
			f, err := peer.readFrame()
			if err != nil {
				return
			}
			if f.opcode == OpPing {
				pings <- 1
			}
		}
	}()

	start := time.Now()
	_, _, err := c.ReadMessage()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("ReadMessage returned nil from a silent peer")
	}
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("ReadMessage error = %v, want a timeout", err)
	}
	// Silence is fatal at 2*idle (100ms to first probe + 100ms grace), and
	// no earlier: allow a wide window, but not less than the full sequence.
	if elapsed < 180*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("silent peer killed after %v, want ~200ms (idle probe + grace)", elapsed)
	}
	select {
	case <-pings:
		// At least one probe ping went out before the kill.
	default:
		t.Fatal("no keepalive ping observed before the kill")
	}
}

// TestArmIdleDisabled covers the idleTimeout == 0 early return.
func TestArmIdleDisabled(t *testing.T) {
	sr, cr := net.Pipe()
	defer cr.Close()
	defer sr.Close()
	c := newConn(cr, cr, true, 1<<20, 0, 0)
	c.lastActivity = time.Time{} // arbitrarily stale
	if err := c.armIdle(); err != nil {
		t.Fatalf("armIdle with idleTimeout 0: %v", err)
	}

	// No deadline may be armed: a read of the silent pipe must still be
	// blocked when we check, not time out.
	peer := &frameCodec{br: bufio.NewReader(sr), isClient: false, maxMsg: 1 << 20}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = peer.readFrame() // blocks: no data, no deadline
	}()
	select {
	case <-done:
		t.Fatal("read returned; a deadline or error must have fired")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestReadMessageControlAndFragmentBranches covers the ReadMessage branches
// the happy-path tests skip: transparent pong, automatic pong reply,
// continuation without a start, data frame mid-fragment, unknown opcode,
// full fragmentation, and fragment overflow.
func TestReadMessageControlAndFragmentBranches(t *testing.T) {
	// Unmasked frames: these conns are clients.
	t.Run("pong is transparent", func(t *testing.T) {
		c := newTestConn([]byte{0x8a, 0x00, 0x81, 0x02, 'H', 'i'}, true)
		op, data, err := c.ReadMessage()
		if err != nil || op != OpText || string(data) != "Hi" {
			t.Fatalf("ReadMessage = (%d, %q, %v)", op, data, err)
		}
	})
	t.Run("ping gets an automatic pong", func(t *testing.T) {
		fc := &fakeConn{data: []byte{0x89, 0x00, 0x81, 0x02, 'H', 'i'}}
		c := newConn(fc, fc, true, 1<<20, 0, 0)
		op, data, err := c.ReadMessage()
		if err != nil || op != OpText || string(data) != "Hi" {
			t.Fatalf("ReadMessage = (%d, %q, %v)", op, data, err)
		}
		// The client masks its outbound frames, so the pong is a masked
		// frame: 0x8a, mask bit set, then a 4-byte key. The payload is
		// empty, so there is nothing after the key.
		if len(fc.written) != 6 || fc.written[0] != 0x8a || fc.written[1]&0x80 == 0 {
			t.Fatalf("pong not written correctly: % x", fc.written)
		}
	})
	t.Run("continuation without start", func(t *testing.T) {
		c := newTestConn([]byte{0x80, 0x02, 'c', 'd'}, true)
		if _, _, err := c.ReadMessage(); err == nil || !strings.Contains(err.Error(), "continuation frame without start") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("data frame mid-fragment", func(t *testing.T) {
		c := newTestConn([]byte{0x01, 0x01, 'a', 0x81, 0x00}, true)
		if _, _, err := c.ReadMessage(); err == nil || !strings.Contains(err.Error(), "in progress") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unknown opcode", func(t *testing.T) {
		c := newTestConn([]byte{0x83, 0x00}, true)
		if _, _, err := c.ReadMessage(); err == nil || !strings.Contains(err.Error(), "unknown opcode") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("full fragmentation", func(t *testing.T) {
		c := newTestConn([]byte{0x01, 0x02, 'a', 'b', 0x80, 0x02, 'c', 'd'}, true)
		op, data, err := c.ReadMessage()
		if err != nil || op != OpText || string(data) != "abcd" {
			t.Fatalf("ReadMessage = (%d, %q, %v)", op, data, err)
		}
	})
	t.Run("fragment overflow", func(t *testing.T) {
		fc := &fakeConn{data: []byte{0x01, 0x02, 'a', 'b', 0x80, 0x02, 'c', 'd'}}
		c := newConn(fc, fc, true, 3, 0, 0) // maxMsg 3 < 2+2 total
		if _, _, err := c.ReadMessage(); err == nil || !errors.Is(err, errMessageTooBig) {
			t.Fatalf("err = %v, want errMessageTooBig", err)
		}
	})
}

// TestWriteErrorPaths covers the "write fails while open" branches: a
// broken pipe must fail the write, and the codec must surface bufio errors.
func TestWriteErrorPaths(t *testing.T) {
	sr, cr := net.Pipe()
	c := newConn(cr, cr, true, 1<<20, 0, 0)
	// Closing the peer's end breaks our writes: a synchronous pipe fails
	// in-flight writes once the other end goes away.
	sr.Close()
	select {
	case <-time.After(2 * time.Second):
		// A blocked write to a half-closed synchronous pipe can linger;
		// run the write in the background if it does not fail promptly.
	default:
	}
	errCh := make(chan error, 1)
	go func() { errCh <- c.WriteMessage(OpText, []byte("x")) }()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("WriteMessage to a broken pipe returned nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WriteMessage to a broken pipe never returned")
	}

	// The codec itself must surface a failing underlying writer.
	fw := &failWriter{}
	fc := frameCodec{bw: bufio.NewWriter(fw), isClient: false, maxMsg: 1 << 20}
	if err := fc.writeFrame(OpText, []byte("x")); err == nil {
		t.Fatal("writeFrame over a failing writer returned nil")
	}
}

// failWriter fails every write, forcing the codec's error branches.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }
