package ws

// protocol_test.go pins the RFC 6455 §4.1 handshake-validation rules and
// the §7.1.5/§7.4 close-frame status-code rules: a close frame must carry
// a usable status code or the connection is failed with 1002, and codes
// that must not be set on the wire (1004, 1005, 1006, 1015) are never
// sent.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // RFC 6455 mandates SHA-1 in the handshake
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// acceptAnyOrigin accepts every Origin; these tests exercise protocol
// validation, not origin policy.
func acceptAnyOrigin(*http.Request) bool { return true }

// maskedCloseFrame builds a masked client→server close frame with the
// given raw payload.
func maskedCloseFrame(payload []byte) []byte {
	mask := [4]byte{0xde, 0xad, 0xbe, 0xef}
	// A close payload is at most 125 bytes, so the length fits a byte.
	buf := []byte{0x88, byte(len(payload)) | 0x80} //nolint:gosec // close payload <= 125
	buf = append(buf, mask[:]...)
	for i := range payload {
		buf = append(buf, payload[i]^mask[i&3])
	}

	return buf
}

// closeReply extracts the payload of the close frame the server wrote to
// fc, if it wrote one.
func closeReply(fc *fakeConn) (payload []byte, ok bool) {
	data := fc.written
	if len(data) < 2 || data[0]&0x0f != OpClose || data[1]&0x80 != 0 {
		return nil, false
	}
	ln := int(data[1] & 0x7f)
	if len(data) < 2+ln {
		return nil, false
	}

	return data[2 : 2+ln], true
}

// replyCode returns the status code in a close reply payload, or -1 for an
// empty payload (no status).
func replyCode(payload []byte) int {
	if len(payload) < closeCodeBytes {
		return -1
	}

	return int(binary.BigEndian.Uint16(payload[:closeCodeBytes]))
}

// runPeerClose feeds one masked close frame to a fresh server-side Conn
// and reports the ReadMessage outcome and the status code of the close
// reply on the wire.
func runPeerClose(t *testing.T, payload []byte) (string, int) {
	t.Helper()
	fc := &fakeConn{data: maskedCloseFrame(payload)}
	c := newConn(fc, fc, false, 1<<20, 0, 0)
	_, _, err := c.ReadMessage()
	errStr := "nil"
	if err != nil {
		errStr = err.Error()
	}
	reply, ok := closeReply(fc)
	if !ok {
		t.Fatalf("server wrote no close reply; read error %q", errStr)
	}

	return errStr, replyCode(reply)
}

// TestMCDCCloseCode traces
// "code >= closeCodeMin && code <= closeCodeMax && !mustNotSetCloseCode(code)".
func TestMCDCCloseCode(t *testing.T) {
	t.Parallel()

	t.Run("min", func(t *testing.T) {
		t.Parallel()
		// code 999 (below 1000) fails with 1002; 1000 closes normally and
		// is echoed.
		errStr, reply := runPeerClose(t, []byte{0x03, 0xe7}) // 999
		if !strings.Contains(errStr, "unusable status code 999") {
			t.Fatalf("999: %q, want unusable status code 999", errStr)
		}
		if reply != StatusProtocolError {
			t.Fatalf("999: reply %d, want 1002", reply)
		}
		errStr, reply = runPeerClose(t, []byte{0x03, 0xe8}) // 1000
		if errStr != "EOF" {
			t.Fatalf("1000: %q, want clean close (io.EOF)", errStr)
		}
		if reply != StatusNormalClosure {
			t.Fatalf("1000: reply %d, want 1000", reply)
		}
	})

	t.Run("max", func(t *testing.T) {
		t.Parallel()
		// code 5000 (above 4999) fails with 1002; 1000 closes normally.
		errStr, reply := runPeerClose(t, []byte{0x13, 0x88}) // 5000
		if !strings.Contains(errStr, "unusable status code 5000") {
			t.Fatalf("5000: %q, want unusable status code 5000", errStr)
		}
		if reply != StatusProtocolError {
			t.Fatalf("5000: reply %d, want 1002", reply)
		}
		_, reply = runPeerClose(t, []byte{0x03, 0xe8}) // 1000
		if reply != StatusNormalClosure {
			t.Fatalf("1000: reply %d, want 1000", reply)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		t.Parallel()
		// 1004, 1005, 1006, 1015 must not be set as a status on the wire:
		// the connection fails with 1002 and the code is not echoed.
		for _, code := range []int{1004, 1005, 1006, 1015} {
			// Codes in 1000-4999 fit two bytes.
			errStr, reply := runPeerClose(t, []byte{byte(code >> 8), byte(code)}) //nolint:gosec // 1000 <= code <= 4999
			if !strings.Contains(errStr, fmt.Sprintf("unusable status code %d", code)) {
				t.Fatalf("code %d: %q, want unusable status code %d", code, errStr, code)
			}
			if reply != StatusProtocolError {
				t.Fatalf("code %d: reply %d, want 1002 (not echoed)", code, reply)
			}
		}
		_, reply := runPeerClose(t, []byte{0x03, 0xe8}) // 1000
		if reply != StatusNormalClosure {
			t.Fatalf("1000: reply %d, want 1000", reply)
		}
	})

	t.Run("oneByte", func(t *testing.T) {
		t.Parallel()
		// A close frame with a 1-byte payload is a protocol error (§7.1.5),
		// not a "no status" close.
		errStr, reply := runPeerClose(t, []byte{0x03})
		if !strings.Contains(errStr, "one-byte payload") {
			t.Fatalf("1-byte payload: %q, want one-byte payload protocol error", errStr)
		}
		if reply != StatusProtocolError {
			t.Fatalf("1-byte payload: reply %d, want 1002", reply)
		}
	})

	t.Run("noStatus", func(t *testing.T) {
		t.Parallel()
		// An empty payload closes normally (io.EOF); the reply carries no
		// status.
		errStr, reply := runPeerClose(t, nil)
		if errStr != "EOF" {
			t.Fatalf("no status: %q, want clean close (io.EOF)", errStr)
		}
		if reply != -1 {
			t.Fatalf("no status: reply code %d, want empty payload", reply)
		}
	})

	t.Run("goingAway", func(t *testing.T) {
		t.Parallel()
		// A usable code is echoed back and reported with its reason.
		errStr, reply := runPeerClose(t, []byte{0x03, 0xe9, 'g', 'b', 'y'}) // 1001 "gby"
		if !strings.Contains(errStr, "closed with code 1001") {
			t.Fatalf("1001: %q, want closed with code 1001", errStr)
		}
		if reply != StatusGoingAway {
			t.Fatalf("1001: reply %d, want 1001", reply)
		}
	})
}

// TestLocalCloseForbiddenCodes checks that local Close never puts a
// must-not-set code on the wire: the close frame goes out with an empty
// payload.
func TestLocalCloseForbiddenCodes(t *testing.T) {
	t.Parallel()
	for _, code := range []int{1004, StatusNoStatusReceived, StatusAbnormalClosure, 1015} {
		fc := &fakeConn{}
		c := newConn(fc, fc, false, 1<<20, 0, 0)
		_ = c.Close(code, "reason")
		reply, ok := closeReply(fc)
		if !ok {
			t.Fatalf("code %d: no close frame written", code)
		}
		if len(reply) != 0 {
			t.Fatalf("code %d: close payload %q, want empty (code not set on the wire)", code, reply)
		}
	}
	// A normal code still carries code + reason.
	fc := &fakeConn{}
	c := newConn(fc, fc, false, 1<<20, 0, 0)
	_ = c.Close(StatusGoingAway, "later")
	if reply, ok := closeReply(fc); !ok || replyCode(reply) != StatusGoingAway {
		t.Fatalf("1001: reply %q ok=%v, want code 1001", reply, ok)
	}
}

// TestMCDCWebSocketKey traces
// "decodeErr != nil || len(raw) != wsKeyBytes".
func TestMCDCWebSocketKey(t *testing.T) {
	t.Parallel()
	// status performs a raw handshake with the given Sec-WebSocket-Key
	// against a fresh server and reports the HTTP status of the reply.
	status := func(t *testing.T, key string) int {
		t.Helper()
		up := NewUpgrader(WithCheckOrigin(acceptAnyOrigin))
		srv := httptest.NewServer(up.Handle(func(_ *http.Request, _ *Conn) error { return nil }))
		t.Cleanup(srv.Close)
		host := srv.URL[len("http://"):]
		conn, err := net.Dial("tcp", host)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", host, key)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read handshake response: %v", err)
		}
		if resp.Body != nil {
			_ = resp.Body.Close()
		}

		return resp.StatusCode
	}

	t.Run("decode", func(t *testing.T) {
		t.Parallel()
		// "!!!!" is not base64 at all: 400. The RFC sample key is: 101.
		if got := status(t, "!!!!"); got != http.StatusBadRequest {
			t.Fatalf("invalid base64 key: status %d, want 400", got)
		}
		if got := status(t, "dGhlIHNhbXBsZSBub25jZQ=="); got != http.StatusSwitchingProtocols {
			t.Fatalf("valid key: status %d, want 101", got)
		}
	})

	t.Run("len", func(t *testing.T) {
		t.Parallel()
		// "QUFB" decodes to 3 bytes, not 16: 400. The RFC sample key
		// decodes to 16: 101.
		if got := status(t, "QUFB"); got != http.StatusBadRequest {
			t.Fatalf("3-byte key: status %d, want 400", got)
		}
		if got := status(t, "dGhlIHNhbXBsZSBub25jZQ=="); got != http.StatusSwitchingProtocols {
			t.Fatalf("16-byte key: status %d, want 101", got)
		}
	})
}

// TestSubprotocolEcho pins the client-side rule from RFC 6455 §1.9: the
// 101 response may select no subprotocol, or exactly one of the tokens the
// client offered. A token the client never offered — or several at once —
// fails the dial, because a server that chooses a protocol on its own
// cannot be trusted with the negotiation.
func TestSubprotocolEcho(t *testing.T) {
	t.Parallel()

	// dialEcho answers one handshake with a 101 that carries the given
	// Sec-WebSocket-Protocol header ("" = no header) and reports the Dial
	// outcome.
	dialEcho := func(t *testing.T, offered []string, echo string) (*Conn, error) {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID)) //nolint:gosec // RFC 6455 mandates SHA-1
			accept := base64.StdEncoding.EncodeToString(sum[:])
			var b strings.Builder
			b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
			b.WriteString("Upgrade: websocket\r\n")
			b.WriteString("Connection: Upgrade\r\n")
			if echo != "" {
				fmt.Fprintf(&b, "Sec-WebSocket-Protocol: %s\r\n", echo)
			}
			fmt.Fprintf(&b, "Sec-WebSocket-Accept: %s\r\n\r\n", accept)
			_, _ = conn.Write([]byte(b.String()))
			time.Sleep(time.Second) // hold the connection while the client verifies
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return Dial(ctx, "ws://"+l.Addr().String(), WithSubprotocols(offered...))
	}

	t.Run("none", func(t *testing.T) {
		t.Parallel()
		// No selection: the dial succeeds and Subprotocol() is empty.
		c, err := dialEcho(t, []string{"chat.v1"}, "")
		if err != nil {
			t.Fatalf("no selection: %v, want success", err)
		}
		defer c.Close(StatusNormalClosure, "")
		if got := c.Subprotocol(); got != "" {
			t.Fatalf("Subprotocol() = %q, want empty", got)
		}
	})

	t.Run("offered", func(t *testing.T) {
		t.Parallel()
		// The one token offered: the dial succeeds with it selected.
		c, err := dialEcho(t, []string{"chat.v1", "chat.v2"}, "chat.v2")
		if err != nil {
			t.Fatalf("offered token: %v, want success", err)
		}
		defer c.Close(StatusNormalClosure, "")
		if got := c.Subprotocol(); got != "chat.v2" {
			t.Fatalf("Subprotocol() = %q, want chat.v2", got)
		}
	})

	t.Run("unoffered", func(t *testing.T) {
		t.Parallel()
		// A token the client never offered: the dial fails.
		_, err := dialEcho(t, []string{"chat.v1"}, "other")
		if err == nil || !strings.Contains(err.Error(), "unoffered subprotocol") {
			t.Fatalf("unoffered token: %v, want unoffered subprotocol rejection", err)
		}
	})

	t.Run("neverOffered", func(t *testing.T) {
		t.Parallel()
		// The client offered nothing, so any selection is unoffered.
		_, err := dialEcho(t, nil, "evil")
		if err == nil || !strings.Contains(err.Error(), "unoffered subprotocol") {
			t.Fatalf("no offer, server echo: %v, want unoffered subprotocol rejection", err)
		}
	})

	t.Run("multiple", func(t *testing.T) {
		t.Parallel()
		// Several selections at once: the dial fails.
		_, err := dialEcho(t, []string{"a", "b"}, "a, b")
		if err == nil || !strings.Contains(err.Error(), "multiple subprotocols") {
			t.Fatalf("multiple selections: %v, want multiple subprotocols rejection", err)
		}
	})
}

// TestRequestWithBodyRejected: RFC 6455 §4.1 — a GET with a body must be
// rejected before the protocol switch.
func TestRequestWithBodyRejected(t *testing.T) {
	up := NewUpgrader(WithCheckOrigin(acceptAnyOrigin))
	srv := httptest.NewServer(up.Handle(func(_ *http.Request, _ *Conn) error {
		t.Error("handler ran despite a request body")

		return nil
	}))
	defer srv.Close()
	host := srv.URL[len("http://"):]
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\nContent-Length: 3\r\n\r\nabc", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 for request with body", resp.StatusCode)
	}
}

// TestMCDCUpgrade101 traces the 101-response token check in
// readHandshakeResponse: the negated headerContainsToken("Upgrade",
// "websocket") OR the negated headerContainsToken("Connection",
// "Upgrade").
func TestMCDCUpgrade101(t *testing.T) {
	t.Parallel()

	// dialAgainst101 listens once, answers any handshake with a 101 that
	// carries exactly the given extra headers (plus the correct
	// Sec-WebSocket-Accept), and reports the Dial outcome.
	dialAgainst101 := func(t *testing.T, headers []string) error {
		t.Helper()
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + wsGUID)) //nolint:gosec // RFC 6455 mandates SHA-1
			accept := base64.StdEncoding.EncodeToString(sum[:])
			var b strings.Builder
			b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
			for _, h := range headers {
				b.WriteString(h + "\r\n")
			}
			fmt.Fprintf(&b, "Sec-WebSocket-Accept: %s\r\n\r\n", accept)
			_, _ = conn.Write([]byte(b.String()))
			time.Sleep(time.Second) // hold the connection while the client verifies
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, dialErr := Dial(ctx, "ws://"+l.Addr().String())
		if dialErr != nil {
			return dialErr
		}
		_ = c.Close(StatusNormalClosure, "")

		return nil
	}

	t.Run("upgrade", func(t *testing.T) {
		t.Parallel()
		// A 101 without "Upgrade: websocket" is rejected; with both
		// upgrade tokens it is accepted.
		err := dialAgainst101(t, []string{"Connection: Upgrade"})
		if err == nil || !strings.Contains(err.Error(), "missing the upgrade headers") {
			t.Fatalf("no Upgrade header: %v, want missing the upgrade headers", err)
		}
		err = dialAgainst101(t, []string{"Upgrade: websocket", "Connection: Upgrade"})
		if err != nil {
			t.Fatalf("both upgrade tokens: %v, want success", err)
		}
	})

	t.Run("connection", func(t *testing.T) {
		t.Parallel()
		// A 101 without "Connection: Upgrade" is rejected; with both
		// upgrade tokens it is accepted.
		err := dialAgainst101(t, []string{"Upgrade: websocket"})
		if err == nil || !strings.Contains(err.Error(), "missing the upgrade headers") {
			t.Fatalf("no Connection header: %v, want missing the upgrade headers", err)
		}
		err = dialAgainst101(t, []string{"Upgrade: websocket", "Connection: Upgrade"})
		if err != nil {
			t.Fatalf("both upgrade tokens: %v, want success", err)
		}
	})
}

// TestMCDCSubprotocol traces
// "r <= 0x20 || r >= 0x7f || strings.ContainsRune(subprotocolSeparators, r)"
// in validSubprotocol.
func TestMCDCSubprotocol(t *testing.T) {
	t.Parallel()

	t.Run("low", func(t *testing.T) {
		t.Parallel()
		// A control character is rejected; a printable token is accepted
		// (same otherwise).
		if validSubprotocol("\x01") {
			t.Fatal(`"\x01" accepted, want rejected`)
		}
		if !validSubprotocol("a") {
			t.Fatal(`"a" rejected, want accepted`)
		}
	})

	t.Run("high", func(t *testing.T) {
		t.Parallel()
		// DEL (0x7f) is rejected; a printable token is accepted.
		if validSubprotocol("\x7f") {
			t.Fatal(`"\x7f" accepted, want rejected`)
		}
		if !validSubprotocol("a") {
			t.Fatal(`"a" rejected, want accepted`)
		}
	})

	t.Run("quote", func(t *testing.T) {
		t.Parallel()
		// A double quote (a separator) is rejected; a printable token
		// is accepted.
		if validSubprotocol("\"") {
			t.Fatal(`"\"" accepted, want rejected`)
		}
		if !validSubprotocol("a") {
			t.Fatal(`"a" rejected, want accepted`)
		}
	})

	t.Run("dial", func(t *testing.T) {
		t.Parallel()
		// An invalid subprotocol fails the Dial before anything is sent.
		srv := echoServer(t)
		host := "ws" + strings.TrimPrefix(srv.URL, "http")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := Dial(ctx, host, WithSubprotocols("bad\r\nX-Inject: 1"))
		if err == nil || !strings.Contains(err.Error(), "invalid subprotocol") {
			t.Fatalf("injection subprotocol: %v, want invalid subprotocol", err)
		}
		_, err = Dial(ctx, host, WithSubprotocols("vnc1"))
		if err != nil {
			t.Fatalf("valid subprotocol: %v, want success", err)
		}
	})
}

// TestSubprotocolSeparators pins the RFC 2616 separator rejection in
// validSubprotocol (RFC 6455 §1.9: 1#token): each separator in a token is
// rejected; printable non-separators are accepted.
func TestSubprotocolSeparators(t *testing.T) {
	t.Parallel()

	for _, s := range []string{"a;b", "a=b", "a,b", "a:b", "a/b", `a\b`,
		"a(b", "a[b", "a?b", "a@b", "a<b", "a>b", "a{b", "a}b", "a\"b"} {
		if validSubprotocol(s) {
			t.Fatalf("%q accepted, want rejected", s)
		}
	}
	for _, s := range []string{"vnc1", "chat-v2", "a_b", "chat.v2"} {
		if !validSubprotocol(s) {
			t.Fatalf("%q rejected, want accepted", s)
		}
	}
}

// TestClientRejectsLineBreakHeader: a header value containing CR or LF
// would inject request lines; reject it instead.
func TestClientRejectsLineBreakHeader(t *testing.T) {
	srv := echoServer(t)
	host := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := Dial(ctx, host, WithHeader("X-Test", "a\nb"))
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("line-break header: %v, want line break rejection", err)
	}
	// The same injection via the header key: canonicalization does not
	// strip CR/LF from keys, so the key must be checked too.
	_, err = Dial(ctx, host, WithHeader("X-Test\r\nX-Inject: 1", "v"))
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("line-break header key: %v, want line break rejection", err)
	}
}

// rawUpgrade performs a raw client handshake against the given upgrader
// and returns the HTTP response Upgrade produced (101 with the negotiated
// headers, or the rejection status).
func rawUpgrade(t *testing.T, up *Upgrader) *http.Response {
	t.Helper()
	srv := httptest.NewServer(up.Handle(func(_ *http.Request, _ *Conn) error {
		return nil
	}))
	defer srv.Close()
	host := srv.URL[len("http://"):]
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Protocol: chat\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	return resp
}

// TestServerSubprotocolValidation pins the guard on the server's
// advertised subprotocols: a token that is not a valid token (RFC 2616) —
// one that would corrupt the Sec-WebSocket-Protocol header of the 101 —
// fails the handshake with 400 instead of being echoed onto the wire.
// A valid advertised list still negotiates as before.
func TestServerSubprotocolValidation(t *testing.T) {
	t.Parallel()
	t.Run("invalid token fails the handshake", func(t *testing.T) {
		t.Parallel()
		up := NewUpgrader(WithCheckOrigin(acceptAnyOrigin), WithSubprotocols("chat,chat2"))
		resp := rawUpgrade(t, up)
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d, want 400 for an invalid advertised subprotocol", resp.StatusCode)
		}
	})
	t.Run("valid tokens still negotiate", func(t *testing.T) {
		t.Parallel()
		up := NewUpgrader(WithCheckOrigin(acceptAnyOrigin), WithSubprotocols("chat", "other"))
		resp := rawUpgrade(t, up)
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("status %d, want 101", resp.StatusCode)
		}
		if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != "chat" {
			t.Fatalf("Sec-WebSocket-Protocol = %q, want chat", got)
		}
	})
}

// TestReservedExtensionHeaderSkipped pins the reserved-header guard on the
// client's opening request: a user-supplied Sec-WebSocket-Extension header
// (either spelling) must not be written in addition to the package's own
// permessage-deflate offer.
func TestReservedExtensionHeaderSkipped(t *testing.T) {
	t.Parallel()
	fc := &fakeConn{}
	headers := http.Header{}
	headers.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	headers.Set(extHeaderSingular, "x-legacy")
	_, err := writeHandshakeRequest(fc, "/ws", "example.com:80", nil, true, headers)
	if err != nil {
		t.Fatalf("writeHandshakeRequest: %v", err)
	}
	req := fc.written
	if n := bytes.Count(req, []byte("Sec-WebSocket-Extensions:")); n != 1 {
		t.Fatalf("opening request carries %d Sec-WebSocket-Extensions lines, want exactly one:\n%s",
			n, req)
	}
	if n := bytes.Count(req, []byte("Sec-WebSocket-Extension:\r\n")); n != 0 {
		t.Fatalf("opening request carries %d singular Sec-WebSocket-Extension lines, want none:\n%s",
			n, req)
	}
}

// echoServer runs an echo session over the package's own upgrader and
// client, with origin checking disabled.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := NewUpgrader(WithCheckOrigin(acceptAnyOrigin))
	srv := httptest.NewServer(up.Handle(func(_ *http.Request, c *Conn) error {
		for {
			op, data, err := c.ReadMessage()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}

				return err
			}
			err = c.WriteMessage(op, data)
			if err != nil {
				return err
			}
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}
