package ws

import (
	"bufio"
	"bytes"
	"errors"
	"testing"
)

// encodeDataFrame encodes one data frame with the given opcode; fin=false
// clears the FIN bit so the frame starts (or continues) a fragmented
// message instead.
func encodeDataFrame(t *testing.T, isClient bool, fin bool, opcode int, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fc := frameCodec{bw: bufio.NewWriter(&buf), isClient: isClient, maxMsg: 1 << 20}
	err := fc.writeFrame(opcode, payload, false)
	if err != nil {
		t.Fatalf("encodeDataFrame: %v", err)
	}
	out := buf.Bytes()
	if !fin {
		out[0] &^= 0x80
	}

	return out
}

// TestTextUTF8Validation pins RFC 6455 §5.6: a non-UTF-8 text message fails
// the connection with 1007 (invalid data type) — single-frame, reassembled
// from fragments, and compressed — while binary payloads pass through
// unchecked and valid text (including multibyte) is delivered.
func TestTextUTF8Validation(t *testing.T) {
	t.Parallel()

	bad := []byte{0xff, 0xfe, 0x01, 0x20}

	t.Run("single-frame text fails with 1007", func(t *testing.T) {
		t.Parallel()
		c := newTestConn(encodeFrameForBudget(t, true, bad), false)
		_, _, err := c.ReadMessage()
		var cerr *CloseError
		if !errors.As(err, &cerr) || cerr.Code != StatusInvalidDataType {
			t.Fatalf("invalid UTF-8 text: %v, want CloseError 1007", err)
		}
		if cerr.Reason == "" {
			t.Fatal("1007 without a reason")
		}
		if !c.Closed() {
			t.Fatal("connection not closed after invalid-UTF-8 text")
		}
	})

	t.Run("fragmented text reassembling to invalid UTF-8 fails", func(t *testing.T) {
		t.Parallel()
		// 0xc3 0x28 reassembled is not valid UTF-8 (a two-byte rune start
		// followed by an ASCII byte): one frame each.
		frames := encodeDataFrame(t, true, false, OpText, []byte{0xc3})
		frames = append(frames, encodeDataFrame(t, true, true, OpContinuation, []byte{0x28})...)
		c := newTestConn(frames, false)
		_, _, err := c.ReadMessage()
		var cerr *CloseError
		if !errors.As(err, &cerr) || cerr.Code != StatusInvalidDataType {
			t.Fatalf("fragmented invalid text: %v, want CloseError 1007", err)
		}
	})

	t.Run("compressed text with invalid UTF-8 fails", func(t *testing.T) {
		t.Parallel()
		stream := deflateStream(t, bad)
		frame := append([]byte{0xC1, byte(len(stream))}, stream...) //nolint:gosec // tiny stream, 7-bit length
		c := deflateTestConn(frame, true)
		_, _, err := c.ReadMessage()
		var cerr *CloseError
		if !errors.As(err, &cerr) || cerr.Code != StatusInvalidDataType {
			t.Fatalf("compressed invalid text: %v, want CloseError 1007", err)
		}
	})

	t.Run("binary with invalid bytes is delivered", func(t *testing.T) {
		t.Parallel()
		c := newTestConn(encodeDataFrame(t, true, true, OpBinary, bad), false)
		op, data, err := c.ReadMessage()
		if err != nil || op != OpBinary || !bytes.Equal(data, bad) {
			t.Fatalf("binary passthrough: (%d, %x, %v), want (2, %x, nil)", op, data, err, bad)
		}
	})

	t.Run("multibyte text is delivered", func(t *testing.T) {
		t.Parallel()
		good := []byte("héllo ☃")
		c := newTestConn(encodeFrameForBudget(t, true, good), false)
		op, data, err := c.ReadMessage()
		if err != nil || op != OpText || !bytes.Equal(data, good) {
			t.Fatalf("multibyte text: (%d, %q, %v), want delivered", op, data, err)
		}
	})
}

// TestWriteTextUTF8Validation pins the write side: an OpText write that is
// not valid UTF-8 fails before reaching the wire and leaves the connection
// open; OpBinary with the same bytes succeeds.
func TestWriteTextUTF8Validation(t *testing.T) {
	t.Parallel()

	bad := []byte{0xff, 0xfe}
	c := newTestConn(nil, false)

	err := c.WriteMessage(OpText, bad)
	if err == nil {
		t.Fatal("OpText with invalid UTF-8 accepted, want error")
	}
	if !errors.Is(err, errInvalidUTF8) {
		t.Fatalf("error = %v, want errInvalidUTF8", err)
	}
	if c.Closed() {
		t.Fatal("rejected write closed the connection; it should stay open")
	}
	err = c.WriteMessage(OpBinary, bad)
	if err != nil {
		t.Fatalf("OpBinary with the same bytes: %v, want success", err)
	}
	err = c.WriteMessage(OpText, []byte("ok"))
	if err != nil {
		t.Fatalf("subsequent valid OpText: %v, want success", err)
	}
}

// TestMCDCTextUTF8 traces
// "opcode == OpText && !utf8.Valid(data)" in WriteMessage and
// "msgOp == OpText && !utf8.Valid(payload)" in ReadMessage.
func TestMCDCTextUTF8(t *testing.T) {
	t.Parallel()

	bad := []byte{0xff, 0xfe}

	t.Run("write-opcode", func(t *testing.T) {
		t.Parallel()
		c := newTestConn(nil, false)
		err := c.WriteMessage(OpText, bad)
		if err == nil {
			t.Fatal("OpText invalid UTF-8 accepted, want error")
		}
		// The same bytes as a binary message pass the check.
		err = c.WriteMessage(OpBinary, bad)
		if err != nil {
			t.Fatalf("OpBinary invalid bytes: %v, want success", err)
		}
	})

	t.Run("write-utf8", func(t *testing.T) {
		t.Parallel()
		c := newTestConn(nil, false)
		err := c.WriteMessage(OpText, bad)
		if err == nil {
			t.Fatal("OpText invalid UTF-8 accepted, want error")
		}
		// The same opcode with valid text passes the check.
		err = c.WriteMessage(OpText, []byte("ok"))
		if err != nil {
			t.Fatalf("OpText valid: %v, want success", err)
		}
	})

	t.Run("read-opcode", func(t *testing.T) {
		t.Parallel()
		// Invalid bytes in a text frame fail with 1007...
		_, _, err := newTestConn(encodeDataFrame(t, true, true, OpText, bad), false).ReadMessage()
		var cerr *CloseError
		if !errors.As(err, &cerr) || cerr.Code != StatusInvalidDataType {
			t.Fatalf("text: %v, want CloseError 1007", err)
		}
		// ...while the same bytes in a binary frame are delivered.
		_, _, err = newTestConn(encodeDataFrame(t, true, true, OpBinary, bad), false).ReadMessage()
		if err != nil {
			t.Fatalf("binary: %v, want delivery", err)
		}
	})

	t.Run("read-utf8", func(t *testing.T) {
		t.Parallel()
		// Invalid text fails with 1007...
		_, _, err := newTestConn(encodeFrameForBudget(t, true, bad), false).ReadMessage()
		var cerr *CloseError
		if !errors.As(err, &cerr) || cerr.Code != StatusInvalidDataType {
			t.Fatalf("invalid text: %v, want CloseError 1007", err)
		}
		// ...while valid text is delivered.
		_, _, err = newTestConn(encodeFrameForBudget(t, true, []byte("ok")), false).ReadMessage()
		if err != nil {
			t.Fatalf("valid text: %v, want delivery", err)
		}
	})
}
