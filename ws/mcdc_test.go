package ws

// MC/DC test matrix. Modified Condition/Decision Coverage (DO-178C,
// ISO 26262) requires that, for every decision with two or more
// conditions, each condition be shown to independently affect the
// decision's outcome: a pair of executions in which only that condition
// changes, every other condition holds, and the decision flips.
//
// Go's coverage profiles are basic-block-granular and record no
// condition values, and instrumenting the library to record them would
// break short-circuit semantics (isReadTimeout's second operand reads
// the variable the first sets). So this file pairs with cmd/mcdc, which
// statically enumerates every compound decision in the package, computes
// the required independence pairs from the boolean structure, and
// verifies that each pair below is traced to a subtest asserting the
// observable outcome that only the decision's flip produces. A new or
// changed compound decision fails the gate until it is traced here.
//
// Every subtest name is one required pair: its doc comment states the
// two truth assignments (by condition order in the expression).

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestMCDCControlFrame traces
// "frm.isControl() && (!frm.fin || size > maxControlPayload)" — three
// atomic conditions, plus the inner OR as its own decision.
func TestMCDCControlFrame(t *testing.T) {
	t.Parallel()

	t.Run("isControl", func(t *testing.T) {
		t.Parallel()
		// (isControl=T, !fin=T, size>125=F) flips to (F, T, F): same
		// non-FIN small frame, only the opcode changes.
		control := newTestConn([]byte{0x09, 0x01, 'x'}, true) // ping, non-FIN
		_, _, err := control.ReadMessage()
		if err == nil ||
			!strings.Contains(err.Error(), "invalid control frame") {
			t.Fatalf("non-FIN control frame: %v, want invalid control frame", err)
		}

		data := newTestConn([]byte{0x01, 0x01, 'x'}, true) // text, non-FIN
		_, _, err = data.ReadMessage()
		if err == nil ||
			strings.Contains(err.Error(), "invalid control frame") {
			t.Fatalf("non-FIN data frame: %v, want a pending-fragment EOF", err)
		}
	})

	t.Run("fin", func(t *testing.T) {
		t.Parallel()
		// (isControl=T, !fin=T, size>125=F) flips to (T, F, F): also the
		// inner OR's (!fin) pair. FIN and payload size held... size held
		// small; only the FIN bit changes.
		fin := newTestConn([]byte{0x89, 0x01, 'x'}, true) // ping, FIN, 1B
		_, _, err := fin.ReadMessage()
		if err == nil ||
			strings.Contains(err.Error(), "invalid control frame") {
			t.Fatalf("FIN control frame: %v, want a pending-frame EOF", err)
		}

		noFin := newTestConn([]byte{0x09, 0x01, 'x'}, true)
		_, _, err = noFin.ReadMessage()
		if err == nil ||
			!strings.Contains(err.Error(), "invalid control frame") {
			t.Fatalf("non-FIN control frame: %v, want invalid control frame", err)
		}
	})

	t.Run("size", func(t *testing.T) {
		t.Parallel()
		// (isControl=T, !fin=F, size>125=T) flips to (T, F, F): also the
		// inner OR's (size) pair. FIN control frames, payload 126 vs 125
		// bytes.
		small := append([]byte{0x89, 0x7d}, make([]byte, 125)...)
		_, _, err := newTestConn(small, true).ReadMessage()
		if err == nil ||
			strings.Contains(err.Error(), "invalid control frame") {
			t.Fatalf("125-byte control frame: %v, want a pending-frame EOF", err)
		}

		large := append([]byte{0x89, 0x7e, 0x00, 0x7e}, make([]byte, 126)...)
		_, _, err = newTestConn(large, true).ReadMessage()
		if err == nil ||
			!strings.Contains(err.Error(), "invalid control frame") {
			t.Fatalf("126-byte control frame: %v, want invalid control frame", err)
		}
	})
}

// TestMCDCIsReadTimeout traces
// "errors.As(err, &nerr) && nerr.Timeout()".

// fakeNetError is a net.Error whose Timeout() answer is under test
// control — DNSError's timeout flag is unexported.
type fakeNetError struct{ isTimeout bool }

func (fakeNetError) Error() string { return "fake net error" }
func (e fakeNetError) Timeout() bool {
	return e.isTimeout
}
func (fakeNetError) Temporary() bool { return false }

func TestMCDCIsReadTimeout(t *testing.T) {
	t.Parallel()

	t.Run("as", func(t *testing.T) {
		t.Parallel()
		// (As=T, Timeout=T) flips to (F, T): a timeout error that is a
		// net.Error vs. one that is not.
		if !isReadTimeout(fakeNetError{isTimeout: true}) {
			t.Fatal("a timeout net.Error must count as a read timeout")
		}
		if isReadTimeout(errors.New("plain error")) {
			t.Fatal("a non-net error must not count as a read timeout")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		// (As=T, Timeout=T) flips to (T, F): both are net.Errors, only
		// Timeout() differs.
		if !isReadTimeout(fakeNetError{isTimeout: true}) {
			t.Fatal("a timeout net.Error must count as a read timeout")
		}
		if isReadTimeout(fakeNetError{isTimeout: false}) {
			t.Fatal("a non-timeout net.Error must not count as a read timeout")
		}
	})
}

// TestMCDCWriteMessageOpcode traces
// "opcode != OpText && opcode != OpBinary". The write proceeds to the
// transport (and fails there, observably) when the decision is false.
func TestMCDCWriteMessageOpcode(t *testing.T) {
	t.Parallel()

	// A fresh connection whose transport never writes: an accepted
	// opcode fails in the flush, a rejected opcode fails in validation.
	fresh := func() *RawConn {
		return newRawConn(failWriteConn{}, failWriteConn{}, true, 1<<20, 0, 0)
	}
	proceeded := func(t *testing.T, opcode int) {
		t.Helper()
		err := fresh().WriteMessage(opcode, []byte("x"))
		if err == nil || strings.Contains(err.Error(), "requires OpText or OpBinary") {
			t.Fatalf("WriteMessage(%d): %v, want the write to reach the transport", opcode, err)
		}
	}
	rejected := func(t *testing.T, opcode int) {
		t.Helper()
		err := fresh().WriteMessage(opcode, []byte("x"))
		if err == nil || !strings.Contains(err.Error(), "requires OpText or OpBinary") {
			t.Fatalf("WriteMessage(%d): %v, want an opcode rejection", opcode, err)
		}
	}

	t.Run("notText", func(t *testing.T) {
		t.Parallel()
		// (notText=F, notBinary=T) flips to (T, T).
		proceeded(t, OpText)
		rejected(t, OpPing)
	})

	t.Run("notBinary", func(t *testing.T) {
		t.Parallel()
		// (notText=T, notBinary=F) flips to (T, T).
		proceeded(t, OpBinary)
		rejected(t, OpPing)
	})
}

// TestMCDCCloseCodeRange traces
// "code < closeCodeMin || code > closeCodeMax".
func TestMCDCCloseCodeRange(t *testing.T) {
	t.Parallel()

	fresh := func() *RawConn {
		return newRawConn(failWriteConn{}, failWriteConn{}, true, 1<<20, 0, 0)
	}
	badCode := func(code int) bool {
		err := fresh().Close(code, "probe")

		return errors.Is(err, errBadCloseCode)
	}

	t.Run("belowMin", func(t *testing.T) {
		t.Parallel()
		// (belowMin=T, aboveMax=F) flips to (F, F).
		if !badCode(closeCodeMin - 1) {
			t.Fatalf("Close(%d) must be rejected", closeCodeMin-1)
		}
		if badCode(closeCodeMin) {
			t.Fatalf("Close(%d) must be accepted", closeCodeMin)
		}
	})

	t.Run("aboveMax", func(t *testing.T) {
		t.Parallel()
		// (belowMin=F, aboveMax=T) flips to (F, F).
		if !badCode(closeCodeMax + 1) {
			t.Fatalf("Close(%d) must be rejected", closeCodeMax+1)
		}
		if badCode(closeCodeMax) {
			t.Fatalf("Close(%d) must be accepted", closeCodeMax)
		}
	})
}

// TestMCDCCloseCodePayload traces
// "code != StatusNoStatusReceived && code != StatusAbnormalClosure".
// The decision is visible in the frame: 1005/1006 carry no payload.
func TestMCDCCloseCodePayload(t *testing.T) {
	t.Parallel()

	// Server side, so the close frame is unmasked and decodable by
	// inspection.
	closeFrame := func(code int, reason string) []byte {
		transport := &fakeConn{}
		c := newRawConn(transport, transport, false, 1<<20, 0, 0)
		_ = c.Close(code, reason)

		return transport.written
	}
	// 1000 = 0x03E8, so Close(1000, "x") is 0x88 0x03 0x03E8 'x'.
	withPayload := []byte{0x88, 0x03, 0x03, 0xE8, 'x'}
	noPayload := []byte{0x88, 0x00}

	t.Run("noStatusReceived", func(t *testing.T) {
		t.Parallel()
		// (not1005=F, not1006=T) flips to (T, T).
		if frame := closeFrame(StatusNoStatusReceived, "ignored"); !bytes.Equal(frame, noPayload) {
			t.Fatalf("Close(1005) frame = % X, want % X (no payload)", frame, noPayload)
		}
		if frame := closeFrame(StatusNormalClosure, "x"); !bytes.Equal(frame, withPayload) {
			t.Fatalf("Close(1000) frame = % X, want % X (code + reason)", frame, withPayload)
		}
	})

	t.Run("abnormalClosure", func(t *testing.T) {
		t.Parallel()
		// (not1005=T, not1006=F) flips to (T, T).
		if frame := closeFrame(StatusAbnormalClosure, "ignored"); !bytes.Equal(frame, noPayload) {
			t.Fatalf("Close(1006) frame = % X, want % X (no payload)", frame, noPayload)
		}
		if frame := closeFrame(StatusNormalClosure, "x"); !bytes.Equal(frame, withPayload) {
			t.Fatalf("Close(1000) frame = % X, want % X (code + reason)", frame, withPayload)
		}
	})
}

// TestMCDCRequireClientCert traces
// "u.requireClientCert && ClientCert(request) == nil".
func TestMCDCRequireClientCert(t *testing.T) {
	t.Parallel()

	allowOrigin := func(*http.Request) bool { return true }
	noCert := &http.Request{Header: http.Header{}, URL: &url.URL{}}
	withCert := &http.Request{
		Header: http.Header{}, URL: &url.URL{},
		TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}},
	}
	rejected := func(t *testing.T, require bool, request *http.Request) bool {
		t.Helper()
		up := NewUpgrader(WithCheckOrigin(allowOrigin))
		if require {
			up = NewUpgrader(WithCheckOrigin(allowOrigin), WithRequireClientCert())
		}

		return up.checkPolicy(httptest.NewRecorder(), request) != nil
	}

	t.Run("require", func(t *testing.T) {
		t.Parallel()
		// (require=T, cert=nil) flips to (F, cert=nil).
		if !rejected(t, true, noCert) {
			t.Fatal("WithRequireClientCert without a certificate must be rejected")
		}
		if rejected(t, false, noCert) {
			t.Fatal("without WithRequireClientCert, a missing certificate must pass")
		}
	})

	t.Run("cert", func(t *testing.T) {
		t.Parallel()
		// (require=T, cert=nil) flips to (T, cert=present).
		if rejected(t, true, withCert) {
			t.Fatal("a presented client certificate must satisfy WithRequireClientCert")
		}
		if !rejected(t, true, noCert) {
			t.Fatal("WithRequireClientCert without a certificate must be rejected")
		}
	})
}

// TestMCDCDialScheme traces
// "parsed.Scheme != wsScheme && parsed.Scheme != wssScheme". The check
// runs before any dial, so a refused port is irrelevant: what is
// observed is whether the scheme error is the one produced here.
func TestMCDCDialScheme(t *testing.T) {
	t.Parallel()

	badScheme := func(t *testing.T, rawurl string) bool {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := Dial(ctx, rawurl, WithDialTimeout(100*time.Millisecond))

		return errors.Is(err, errBadScheme)
	}

	t.Run("notWs", func(t *testing.T) {
		t.Parallel()
		// (notWs=F, notWss=T) flips to (T, T).
		if badScheme(t, "ws://127.0.0.1:1/ws") {
			t.Fatal("ws:// must pass the scheme check")
		}
		if !badScheme(t, "http://127.0.0.1:1/ws") {
			t.Fatal("http:// must fail the scheme check")
		}
	})

	t.Run("notWss", func(t *testing.T) {
		t.Parallel()
		// (notWs=T, notWss=F) flips to (T, T).
		if badScheme(t, "wss://127.0.0.1:1/ws") {
			t.Fatal("wss:// must pass the scheme check")
		}
		if !badScheme(t, "http://127.0.0.1:1/ws") {
			t.Fatal("http:// must fail the scheme check")
		}
	})
}

// TestMCDCHandleCloseCode traces
// "code < closeCodeMin || code > closeCodeMax" in Upgrader.Handle: a close
// code carried by a handler-returned *CloseError but out of range cannot go
// on the wire, so Handle remaps it to 1002 instead of leaking the
// connection.
func TestMCDCHandleCloseCode(t *testing.T) {
	t.Parallel()

	// seen returns the terminal error the client's ReadMessage reports when
	// the handler closes with the given code: nil for a normal closure, a
	// *CloseError carrying the code on the wire otherwise.
	seen := func(t *testing.T, code int) error {
		t.Helper()
		up := NewUpgrader(WithCheckOrigin(func(*http.Request) bool { return true }))
		mux := http.NewServeMux()
		mux.Handle("/ws", up.Handle(func(_ *http.Request, _ *Conn) error {
			return &CloseError{Code: code, Reason: "probe"}
		}))
		s := httptest.NewServer(mux)
		t.Cleanup(s.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := Dial(ctx, "ws"+strings.TrimPrefix(s.URL, "http")+"/ws")
		if err != nil {
			t.Fatalf("dial handler code %d: %v", code, err)
		}
		_, _, termErr := c.ReadMessage()

		return termErr
	}

	t.Run("belowMin", func(t *testing.T) {
		t.Parallel()
		// (belowMin=T, aboveMax=F) flips to (F, F): 999 is remapped to
		// 1002; 1000 closes normally (nil terminal error) instead.
		if code, _, ok := CloseCode(seen(t, closeCodeMin-1)); !ok || code != StatusProtocolError {
			t.Fatalf("handler code %d: client close code %d (ok=%v), want 1002 remap", closeCodeMin-1, code, ok)
		}
		if code, _, ok := CloseCode(seen(t, closeCodeMin)); ok {
			t.Fatalf("handler code %d: close code %d on the wire, want normal closure",
				closeCodeMin, code)
		}
	})

	t.Run("aboveMax", func(t *testing.T) {
		t.Parallel()
		// (belowMin=F, aboveMax=T) flips to (F, F): 5000 is remapped to
		// 1002; 4999 goes through unchanged.
		if code, _, ok := CloseCode(seen(t, closeCodeMax+1)); !ok || code != StatusProtocolError {
			t.Fatalf("handler code %d: client close code %d (ok=%v), want 1002 remap", closeCodeMax+1, code, ok)
		}
		if code, _, ok := CloseCode(seen(t, closeCodeMax)); !ok || code != closeCodeMax {
			t.Fatalf("handler code %d: close code %d (ok=%v), want 4999 unchanged",
				closeCodeMax, code, ok)
		}
	})
}

// TestMCDCTruncateReason traces
// "n > 0 && !utf8.RuneStart(s[n])" in truncateReason: a reason over the
// on-wire limit is cut at maxCloseReason, backing off over continuation
// bytes to a rune boundary.
func TestMCDCTruncateReason(t *testing.T) {
	t.Parallel()

	t.Run("runeBoundary", func(t *testing.T) {
		t.Parallel()
		// (!RuneStart=T) flips to (!RuneStart=F): a 2-byte rune split across
		// the bound backs off one byte; a start byte at the bound does not.
		split := strings.Repeat("\u00e9", 62) // 124 bytes; index 123 is a continuation byte
		got := truncateReason(split)
		if len(got) != maxCloseReason-1 {
			t.Fatalf("split rune truncated to %d bytes, want %d", len(got), maxCloseReason-1)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("truncated split-rune reason is not valid UTF-8: %q", got)
		}
		if got := truncateReason(strings.Repeat("a", maxCloseReason+10)); len(got) != maxCloseReason {
			t.Fatalf("ASCII reason truncated to %d bytes, want %d", len(got), maxCloseReason)
		}
	})

	t.Run("invalidUTF8", func(t *testing.T) {
		t.Parallel()
		// (n>0=T, !RuneStart=T) flips to (n>0=F, !RuneStart=T): an all-
		// continuation (invalid UTF-8) reason runs the loop to n == 0 and
		// yields the empty string instead of a panic.
		got := truncateReason(strings.Repeat("\x80", maxCloseReason+10))
		if got != "" {
			t.Fatalf("all-continuation reason truncated to %q, want empty", got)
		}
		if got := truncateReason("short"); got != "short" {
			t.Fatalf("under-limit reason altered: %q", got)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// permessage-deflate (RFC 7692)

// TestMCDCDeflateRSV traces "rsv1Set && !fc.deflate" in frameCodec.checkRSV:
// RSV1 is a protocol error only when permessage-deflate was not negotiated.
func TestMCDCDeflateRSV(t *testing.T) {
	t.Parallel()
	stream := deflateStream(t, []byte("x"))
	rsv1Frame := append([]byte{0xC1, byte(len(stream))}, stream...) //nolint:gosec // tiny test stream, 7-bit length

	t.Run("rsv1", func(t *testing.T) {
		t.Parallel()
		// (rsv1Set=T, !deflate=T) flips to (F, T): an RSV1 frame and a plain
		// frame on a connection without the extension — only the former is a
		// protocol error.
		_, _, badErr := newTestConn(rsv1Frame, true).ReadMessage()
		if badErr == nil || !strings.Contains(badErr.Error(), "RSV1 set without permessage-deflate") {
			t.Fatalf("RSV1 frame: %v, want RSV1 protocol error", badErr)
		}
		good, _, goodErr := newTestConn([]byte{0x81, 0x01, 'x'}, true).ReadMessage()
		if goodErr != nil || good != OpText {
			t.Fatalf("plain frame: (%d, %v), want text", good, goodErr)
		}
	})

	t.Run("deflate", func(t *testing.T) {
		t.Parallel()
		// (rsv1Set=T, !deflate=F) flips to (T, T): the same RSV1 frame passes
		// when negotiated and fails when not.
		_, _, err := newSession(deflateTestConn(rsv1Frame, true), nil).ReadMessage()
		if err != nil {
			t.Fatalf("negotiated RSV1 frame: %v, want success", err)
		}
		_, _, err = newTestConn(rsv1Frame, true).ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "RSV1 set without permessage-deflate") {
			t.Fatalf("unnegotiated RSV1 frame: %v, want RSV1 protocol error", err)
		}
	})
}

// TestMCDCDeflateControl traces "frm.compressed && frm.isControl()" in
// ReadMessage: the compressed bit on a control frame is a protocol
// violation even when the extension is negotiated.
func TestMCDCDeflateControl(t *testing.T) {
	t.Parallel()

	t.Run("compressed", func(t *testing.T) {
		t.Parallel()
		// (compressed=T, isControl=T) flips to (F, T): an RSV1 ping is a
		// protocol error, a plain ping is answered with a pong.
		_, _, err := newSession(deflateTestConn([]byte{0xC9, 0x01, 'x'}, true), nil).ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "control frame") {
			t.Fatalf("RSV1 ping: %v, want control-frame protocol error", err)
		}
		_, _, err = newSession(deflateTestConn([]byte{0x89, 0x01, 'x'}, true), nil).ReadMessage()
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("plain ping: %v, want pong-then-EOF", err)
		}
	})

	t.Run("isControl", func(t *testing.T) {
		t.Parallel()
		// (compressed=T, isControl=T) flips to (T, F): an RSV1 ping is a
		// protocol error; an RSV1 data frame is a valid compressed message.
		_, _, err := newSession(deflateTestConn([]byte{0xC9, 0x01, 'x'}, true), nil).ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "control frame") {
			t.Fatalf("RSV1 ping: %v, want control-frame protocol error", err)
		}
		stream := deflateStream(t, []byte("x"))
		frm := append([]byte{0xC1, byte(len(stream))}, stream...) //nolint:gosec // tiny test stream, 7-bit length
		_, _, err = newSession(deflateTestConn(frm, true), nil).ReadMessage()
		if err != nil {
			t.Fatalf("RSV1 data frame: %v, want success", err)
		}
	})
}

// TestMCDCDeflateServerWindow traces "bits != 0 && bits < maxWindowBits" in
// negotiateCompression: a server_max_window_bits demand below the full 15
// bits is declined (no extension in the response), other offers are
// accepted.
func TestMCDCDeflateServerWindow(t *testing.T) {
	t.Parallel()

	t.Run("bits", func(t *testing.T) {
		t.Parallel()
		// (bits!=0=F, bits<15=T) flips to (T, T): no window demand is
		// accepted; a 10-bit demand is declined.
		ext, err := negotiateCompression(splitExtensionGroups(offerHeader("permessage-deflate")))
		if err != nil || ext != deflateResponseHeader {
			t.Fatalf("no window demand: (%q, %v), want the extension", ext, err)
		}
		ext, err = negotiateCompression(splitExtensionGroups(
			offerHeader("permessage-deflate; server_max_window_bits=10")))
		if err != nil || ext != "" {
			t.Fatalf("10-bit demand: (%q, %v), want declined", ext, err)
		}
	})

	t.Run("belowMax", func(t *testing.T) {
		t.Parallel()
		// (bits!=0=T, bits<15=T) flips to (T, F): a 10-bit demand is
		// declined; the full 15-bit demand is accepted.
		ext, err := negotiateCompression(splitExtensionGroups(
			offerHeader("permessage-deflate; server_max_window_bits=10")))
		if err != nil || ext != "" {
			t.Fatalf("10-bit demand: (%q, %v), want declined", ext, err)
		}
		ext, err = negotiateCompression(splitExtensionGroups(
			offerHeader("permessage-deflate; server_max_window_bits=15")))
		if err != nil || ext != deflateResponseHeader {
			t.Fatalf("15-bit demand: (%q, %v), want the extension", ext, err)
		}
	})
}

// TestMCDCDeflateClientWindow traces "bits != 0 && bits < maxWindowBits" in
// verifyCompressionResponse: a response that caps the client window below
// the full 15 bits fails the dial; other responses are accepted.
func TestMCDCDeflateClientWindow(t *testing.T) {
	t.Parallel()

	t.Run("bits", func(t *testing.T) {
		t.Parallel()
		// (bits!=0=F, bits<15=T) flips to (T, T): no window cap is
		// accepted; a 10-bit cap fails the dial.
		_, err := dialWithServerExtension(t, "permessage-deflate")
		if err != nil {
			t.Fatalf("no window cap: %v", err)
		}
		_, err = dialWithServerExtension(t, "permessage-deflate; client_max_window_bits=10")
		if err == nil {
			t.Fatal("10-bit cap: dial succeeded, want failure")
		}
	})

	t.Run("belowMax", func(t *testing.T) {
		t.Parallel()
		// (bits!=0=T, bits<15=T) flips to (T, F): a 10-bit cap fails the
		// dial; the full 15-bit cap is accepted.
		_, err := dialWithServerExtension(t, "permessage-deflate; client_max_window_bits=10")
		if err == nil {
			t.Fatal("10-bit cap: dial succeeded, want failure")
		}
		_, err = dialWithServerExtension(t, "permessage-deflate; client_max_window_bits=15")
		if err != nil {
			t.Fatalf("15-bit cap: %v", err)
		}
	})
}

// TestMCDCDeflateOffered traces "!offered && len(groups) > 0" in
// verifyCompressionResponse: an extension the client never offered fails
// the dial, and only when the response actually carries one.
func TestMCDCDeflateOffered(t *testing.T) {
	t.Parallel()

	t.Run("offered", func(t *testing.T) {
		t.Parallel()
		// (!offered=T, len>0=T) flips to (F, T): with compression disabled
		// the extension is not offered, so a response carrying it fails the
		// dial; with compression enabled the same response is accepted.
		_, err := dialWithServerExtension(t, "permessage-deflate", WithCompression(false))
		if err == nil {
			t.Fatal("unoffered extension: dial succeeded, want failure")
		}
		_, err = dialWithServerExtension(t, "permessage-deflate")
		if err != nil {
			t.Fatalf("offered extension: %v", err)
		}
	})

	t.Run("groups", func(t *testing.T) {
		t.Parallel()
		// (!offered=T, len>0=F) flips to (T, T): with compression disabled a
		// response without the extension is accepted; one with it fails.
		_, err := dialWithServerExtension(t, "", WithCompression(false))
		if err != nil {
			t.Fatalf("no extension, not offered: %v", err)
		}
		_, err = dialWithServerExtension(t, "permessage-deflate", WithCompression(false))
		if err == nil {
			t.Fatal("extension present, not offered: dial succeeded, want failure")
		}
	})
}

// TestMCDCDeflateWindowBits traces the two compound decisions in
// parseWindowBits: "len(value) > 1 && value[0] == '0'" (leading zeros) and
// "err != nil || bits < 8 || bits > maxWindowBits" (plus its nested OR)
// (range and format validation of max_window_bits values).
func TestMCDCDeflateWindowBits(t *testing.T) {
	t.Parallel()

	t.Run("leadingZeroLen", func(t *testing.T) {
		t.Parallel()
		// (len>1=T, [0]=='0'=T) flips to (F, T): "010" is a leading zero;
		// "0" skips the check and fails the range check instead.
		_, err := parseWindowBits("010")
		if err == nil || !strings.Contains(err.Error(), "leading zero") {
			t.Fatalf("010: %v, want leading-zero error", err)
		}
		_, err = parseWindowBits("0")
		if err == nil || !strings.Contains(err.Error(), "out of range") {
			t.Fatalf("0: %v, want out-of-range error", err)
		}
	})

	t.Run("leadingZeroFirst", func(t *testing.T) {
		t.Parallel()
		// (len>1=T, [0]=='0'=T) flips to (T, F): "010" is a leading zero;
		// "10" is a valid value.
		_, err := parseWindowBits("010")
		if err == nil {
			t.Fatalf("010: %v, want leading-zero error", err)
		}
		bits, err := parseWindowBits("10")
		if err != nil || bits != 10 {
			t.Fatalf("10: (%d, %v), want 10", bits, err)
		}
	})

	t.Run("decode", func(t *testing.T) {
		t.Parallel()
		// (decodeErr=T, ..) flips to (F, F, F): "abc" is not a number; "10"
		// decodes in range.
		_, err := parseWindowBits("abc")
		if err == nil {
			t.Fatalf("abc: %v, want out-of-range error", err)
		}
		bits, err := parseWindowBits("10")
		if err != nil || bits != 10 {
			t.Fatalf("10: (%d, %v), want 10", bits, err)
		}
	})

	t.Run("below", func(t *testing.T) {
		t.Parallel()
		// (decodeErr=F, bits<8=T, ..) flips to (F, F, F): "7" is below the
		// range floor; "10" is in range.
		_, err := parseWindowBits("7")
		if err == nil {
			t.Fatalf("7: %v, want out-of-range error", err)
		}
		bits, err := parseWindowBits("10")
		if err != nil || bits != 10 {
			t.Fatalf("10: (%d, %v), want 10", bits, err)
		}
	})

	t.Run("above", func(t *testing.T) {
		t.Parallel()
		// (decodeErr=F, bits<8=F, bits>15=T) flips to (F, F, F): "16" is
		// above the range ceiling; "15" is in range.
		_, err := parseWindowBits("16")
		if err == nil {
			t.Fatalf("16: %v, want out-of-range error", err)
		}
		bits, err := parseWindowBits("15")
		if err != nil || bits != 15 {
			t.Fatalf("15: (%d, %v), want 15", bits, err)
		}
	})
}
