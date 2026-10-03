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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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
	fresh := func() *Conn {
		return newConn(failWriteConn{}, failWriteConn{}, true, 1<<20, 0, 0)
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

	fresh := func() *Conn {
		return newConn(failWriteConn{}, failWriteConn{}, true, 1<<20, 0, 0)
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
		c := newConn(transport, transport, false, 1<<20, 0, 0)
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
