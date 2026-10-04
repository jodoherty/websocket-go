package ws

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRawEventSequence pins the raw read contract end to end: events arrive
// in wire order, each ping and pong is delivered (not consumed), no pong is
// written automatically, the close is replied to and then delivered as a
// resolved OpClose event, and the read ends with the terminal error.
func TestRawEventSequence(t *testing.T) {
	t.Parallel()
	// A wire sequence exercising every event kind: a text message, a
	// ping, a pong, and a close with a status.
	data := []byte{
		0x81, 0x02, 'H', 'i', // text "Hi"
		0x89, 0x02, 'p', 'p', // ping "pp"
		0x8A, 0x02, 'q', 'q', // pong "qq"
		0x88, 0x05, 0x03, 0xE9, 'b', 'y', 'e', // close 1001 "bye"
	}
	fc := &fakeConn{data: data}
	c := newRawConn(fc, fc, true, 1<<20, 0, 0)

	ev, err := c.ReadEvent()
	if err != nil || ev.Op != OpText || string(ev.Payload) != "Hi" {
		t.Fatalf("first event = (%+v, %v), want text \"Hi\"", ev, err)
	}

	ev, err = c.ReadEvent()
	if err != nil || ev.Op != OpPing || string(ev.Payload) != "pp" {
		t.Fatalf("second event = (%+v, %v), want ping \"pp\"", ev, err)
	}
	// The raw conn is the responder: no pong may have been written.
	if len(fc.written) != 0 {
		t.Fatalf("raw conn auto-wrote % x, want nothing (no automatic pong)", fc.written)
	}

	ev, err = c.ReadEvent()
	if err != nil || ev.Op != OpPong || string(ev.Payload) != "qq" {
		t.Fatalf("third event = (%+v, %v), want pong \"qq\"", ev, err)
	}

	ev, err = c.ReadEvent()
	if err != nil || ev.Op != OpClose || ev.Code != StatusGoingAway || ev.Reason != "bye" {
		t.Fatalf("fourth event = (%+v, %v), want close 1001 \"bye\"", ev, err)
	}
	// The close was replied to: the reply is a (client-masked) close frame.
	if len(fc.written) != 2+maskKeyLen+closeCodeBytes+3 || Op(fc.written[0]&opcodeMask) != OpClose {
		t.Fatalf("close reply % x, want a masked close frame", fc.written)
	}

	_, err = c.ReadEvent()
	var ce *CloseError
	if !errors.As(err, &ce) || ce.Code != StatusGoingAway {
		t.Fatalf("terminal error = %v, want the 1001 CloseError", err)
	}
}

// TestRawPongAnswer pins the raw responder loop: the application answers the
// delivered ping with its own payload via Pong, and the frame on the wire
// carries it.
func TestRawPongAnswer(t *testing.T) {
	t.Parallel()
	fc := &fakeConn{data: []byte{0x89, 0x02, 'p', 'p'}}
	c := newRawConn(fc, fc, true, 1<<20, 0, 0)

	ev, err := c.ReadEvent()
	if err != nil || ev.Op != OpPing {
		t.Fatalf("event = (%+v, %v), want a ping", ev, err)
	}
	err = c.Pong([]byte("reply"))
	if err != nil {
		t.Fatalf("Pong: %v", err)
	}
	// Client frames are masked: opcode, length|mask, key, payload.
	if len(fc.written) != 2+maskKeyLen+5 || Op(fc.written[0]&opcodeMask) != OpPong {
		t.Fatalf("pong frame % x, want a masked pong with the answer", fc.written)
	}

	// A pong payload over the control limit is refused before the wire.
	err = c.Pong(make([]byte, maxControlPayload+1))
	if err == nil {
		t.Fatal("oversized Pong succeeded, want a size refusal")
	}
	if len(fc.written) != 2+maskKeyLen+5 {
		t.Fatal("refused Pong reached the wire")
	}
}

// TestRawFragmentedWrite pins the fragmented write contract: a start frame
// plus a continuation frame are reassembled by the peer into the one
// message the read reports.
func TestRawFragmentedWrite(t *testing.T) {
	t.Parallel()
	sr, cr := net.Pipe()
	server := newSession(newRawConn(sr, sr, false, 1<<20, 0, 0), nil)
	client := newRawConn(cr, cr, true, 1<<20, 0, 0)

	out := make(chan struct {
		op   Op
		data string
		err  error
	}, 1)
	go func() {
		op, data, err := server.ReadMessage()
		out <- struct {
			op   Op
			data string
			err  error
		}{op, string(data), err}
		// Drain, so the client's close frame has a reader on the
		// synchronous pipe.
		for {
			_, _, readErr := server.ReadMessage()
			if readErr != nil {
				return
			}
		}
	}()

	startErr := client.WriteFrame(OpText, []byte("Hel"), true)
	if startErr != nil {
		t.Fatalf("start frame: %v", startErr)
	}
	contErr := client.WriteFrame(OpContinuation, []byte("lo"), false)
	if contErr != nil {
		t.Fatalf("continuation frame: %v", contErr)
	}
	res := <-out
	if res.err != nil || res.op != OpText || res.data != "Hello" {
		t.Fatalf("peer read = (%d, %q, %v), want one reassembled text message \"Hello\"",
			res.op, res.data, res.err)
	}
	// Close returns the terminal error: io.EOF for a normal closure.
	closeErr := client.Close(StatusNormalClosure, "")
	if !errors.Is(closeErr, io.EOF) {
		t.Fatalf("close: %v, want io.EOF", closeErr)
	}
}

// TestMCDCRawWriteFrame pins WriteFrame's opcode handling, one subtest per
// required independence pair: which opcodes are writable, the control-
// frame shape rules, the standalone continuation, and the UTF-8 rule —
// applied to a single-frame text message, not to fragments, because a
// fragment boundary may split a rune.
func TestMCDCRawWriteFrame(t *testing.T) {
	t.Parallel()
	// A fresh pipe pair per subtest, with the server's single reader
	// draining, so subtests can run in parallel.
	fresh := func(t *testing.T) *RawConn {
		t.Helper()
		sr, cr := net.Pipe()
		server := newSession(newRawConn(sr, sr, false, 1<<20, 0, 0), nil)
		client := newRawConn(cr, cr, true, 1<<20, 0, 0)
		go func() {
			for {
				_, _, readErr := server.ReadMessage()
				if readErr != nil {
					return
				}
			}
		}()
		t.Cleanup(func() { _ = client.Close(StatusNormalClosure, "") })

		return client
	}
	invalid := []byte{0xff}

	t.Run("oversized-ping", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		pingErr := c.WriteFrame(OpPing, make([]byte, maxControlPayload+1), false)
		if pingErr == nil {
			t.Fatal("oversized ping succeeded, want a size refusal")
		}
		// The same size as a data frame passes: the limit is the
		// control-frame one.
		textErr := c.WriteFrame(OpText, make([]byte, maxControlPayload+1), false)
		if textErr != nil {
			t.Fatalf("text of the same size: %v, want success", textErr)
		}
	})
	t.Run("oversized-pong", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		pingErr := c.WriteFrame(OpPong, make([]byte, maxControlPayload+1), false)
		if pingErr == nil {
			t.Fatal("oversized pong succeeded, want a size refusal")
		}
		binaryErr := c.WriteFrame(OpBinary, make([]byte, maxControlPayload+1), false)
		if binaryErr != nil {
			t.Fatalf("binary of the same size: %v, want success", binaryErr)
		}
	})
	t.Run("unknown-opcode", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf1Err := c.WriteFrame(3, []byte("x"), false)
		if wf1Err == nil {
			t.Fatal("opcode 3 write succeeded, want a protocol refusal")
		}
		wf2Err := c.WriteFrame(OpText, []byte("x"), false)
		if wf2Err != nil {
			t.Fatalf("a writable opcode: %v, want success", wf2Err)
		}
	})
	t.Run("close-not-writable", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		// Every writable data opcode goes out...
		wf3Err := c.WriteFrame(OpText, []byte("t"), false)
		if wf3Err != nil {
			t.Fatalf("text: %v", wf3Err)
		}
		wf4Err := c.WriteFrame(OpBinary, []byte("b"), false)
		if wf4Err != nil {
			t.Fatalf("binary: %v", wf4Err)
		}
		wf5Err := c.WriteFrame(OpText, []byte("start"), true)
		if wf5Err != nil {
			t.Fatalf("text start: %v", wf5Err)
		}
		wf6Err := c.WriteFrame(OpContinuation, []byte("end"), false)
		if wf6Err != nil {
			t.Fatalf("continuation after a start: %v", wf6Err)
		}
		// ...but the close frame is reserved for Close.
		wf7Err := c.WriteFrame(OpClose, []byte{}, false)
		if wf7Err == nil {
			t.Fatal("close frame write succeeded, want a refusal")
		}
	})
	t.Run("control-fragment", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf8Err := c.WriteFrame(OpPing, []byte{}, true)
		if wf8Err == nil {
			t.Fatal("fragmented ping succeeded, want a refusal")
		}
		wf9Err := c.WriteFrame(OpText, []byte{}, true)
		if wf9Err != nil {
			t.Fatalf("fragmented text start: %v, want success", wf9Err)
		}
	})
	t.Run("standalone-continuation", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf10Err := c.WriteFrame(OpContinuation, []byte("x"), false)
		if wf10Err == nil {
			t.Fatal("standalone continuation succeeded, want a refusal")
		}
		// The same frame with a start frame in flight goes out.
		wf11Err := c.WriteFrame(OpBinary, []byte("start"), true)
		if wf11Err != nil {
			t.Fatalf("binary start: %v", wf11Err)
		}
		wf12Err := c.WriteFrame(OpContinuation, []byte("x"), false)
		if wf12Err != nil {
			t.Fatalf("continuation after the start: %v, want success", wf12Err)
		}
	})
	t.Run("continuation-after-text-start", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf13Err := c.WriteFrame(OpText, []byte("Hel"), true)
		if wf13Err != nil {
			t.Fatalf("text start: %v", wf13Err)
		}
		wf14Err := c.WriteFrame(OpContinuation, []byte("lo"), false)
		if wf14Err != nil {
			t.Fatalf("continuation: %v, want success", wf14Err)
		}
	})
	t.Run("continuation-after-binary-start", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf15Err := c.WriteFrame(OpBinary, []byte{0x01}, true)
		if wf15Err != nil {
			t.Fatalf("binary start: %v", wf15Err)
		}
		wf16Err := c.WriteFrame(OpContinuation, []byte{0x02}, false)
		if wf16Err != nil {
			t.Fatalf("continuation: %v, want success", wf16Err)
		}
	})
	t.Run("text-single-frame-utf8", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf17Err := c.WriteFrame(OpText, invalid, false)
		if wf17Err == nil {
			t.Fatal("invalid single-frame text succeeded, want a refusal")
		}
	})
	t.Run("text-fragment-passes", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		// A fragment may hold half a rune: not valid UTF-8 on its own,
		// so the single-frame check must not apply to it.
		wf18Err := c.WriteFrame(OpText, []byte{0xc3}, true)
		if wf18Err != nil {
			t.Fatalf("text fragment with a rune first byte: %v, want success", wf18Err)
		}
		wf19Err := c.WriteFrame(OpContinuation, []byte{0xa9}, false)
		if wf19Err != nil {
			t.Fatalf("final fragment: %v, want success", wf19Err)
		}
	})
	t.Run("binary-passes-invalid-bytes", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf20Err := c.WriteFrame(OpBinary, invalid, false)
		if wf20Err != nil {
			t.Fatalf("binary with invalid bytes: %v, want success", wf20Err)
		}
	})
	t.Run("valid-text", func(t *testing.T) {
		t.Parallel()
		c := fresh(t)
		wf21Err := c.WriteFrame(OpText, []byte("fine"), false)
		if wf21Err != nil {
			t.Fatalf("valid single-frame text: %v, want success", wf21Err)
		}
	})
}

// TestDialRawDefaults pins DialRaw's two raw defaults: keepalive probes are
// off (no idle timeout armed), and an explicit WithIdleTimeout enables them
// exactly as it does for Dial.
func TestDialRawDefaults(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(Handle(func(_ *http.Request, c *Session) error {
		for {
			_, _, readErr := c.ReadMessage()
			if readErr != nil {
				return readErr
			}
		}
	}))
	defer srv.Close()

	c, err := DialRaw(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer c.Close(StatusNormalClosure, "")
	if c.idleTimeout != 0 {
		t.Fatalf("DialRaw armed an idle timeout of %v, want keepalive off by default", c.idleTimeout)
	}
}

// TestDialRawIdleTimeoutOptIn is the companion to TestDialRawDefaults: the
// window is applied when asked for, and the pump's keepalive probe is
// visible to the raw application — its answer arrives as an OpPong event.
func TestDialRawIdleTimeoutOptIn(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(Handle(func(_ *http.Request, c *Session) error {
		for {
			_, _, readErr := c.ReadMessage()
			if readErr != nil {
				return readErr
			}
		}
	}))
	defer srv.Close()

	c, err := DialRaw(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"),
		WithIdleTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer c.Close(StatusNormalClosure, "")
	if c.idleTimeout != 50*time.Millisecond {
		t.Fatalf("idle timeout = %v, want the requested window", c.idleTimeout)
	}
	// Stay silent past the window: the pump probes with a ping, the
	// session server auto-pongs, and the answer surfaces as an event.
	start := time.Now()
	ev, err := c.ReadEvent()
	if err != nil || ev.Op != OpPong {
		t.Fatalf("event = (%+v, %v), want the keepalive probe's answer pong", ev, err)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("pong arrived after %v, want the pump to have probed at the idle window", elapsed)
	}
}

// TestRawServerFaces pins the raw server side: UpgradeRaw hands the handler
// a *RawConn that sees the client's ping as an event and answers it, and
// HandleRaw runs the handler to the close.
func TestRawServerFaces(t *testing.T) {
	t.Parallel()
	up := NewUpgrader(WithCheckOrigin(func(*http.Request) bool { return true }))
	// The handler is typed *RawConn; the round trips below prove it drove
	// the protocol: it read the ping event, answered it, and closed the
	// session itself when told to.
	srv := httptest.NewServer(up.HandleRaw(func(_ *http.Request, c *RawConn) error {
		for {
			ev, err := c.ReadEvent()
			if err != nil {
				return err
			}
			if ev.Op == OpPing {
				err = c.Pong(ev.Payload)
				if err != nil {
					return err
				}

				continue
			}
			if ev.Op == OpText {
				// The client asked the handler to end: close, and let
				// HandleRaw tear down.
				return c.Close(StatusNormalClosure, "server done")
			}
		}
	}))
	defer srv.Close()

	client, err := DialRaw(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("DialRaw: %v", err)
	}
	defer client.Close(StatusNormalClosure, "")

	err = client.Ping([]byte("to-server"))
	if err != nil {
		t.Fatalf("client Ping: %v", err)
	}
	ev, err := client.ReadEvent()
	if err != nil || ev.Op != OpPong || string(ev.Payload) != "to-server" {
		t.Fatalf("event = (%+v, %v), want the server's pong echoing the payload", ev, err)
	}
	// Now the handler closes the session itself; the client observes it as
	// a close event, then the terminal error.
	err = client.WriteMessage(OpText, []byte("close me"))
	if err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	ev, err = client.ReadEvent()
	if err != nil || ev.Op != OpClose || ev.Code != StatusNormalClosure || ev.Reason != "server done" {
		t.Fatalf("event = (%+v, %v), want the server's 1000 close event", ev, err)
	}
	_, err = client.ReadEvent()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("terminal error = %v, want io.EOF", err)
	}
}
