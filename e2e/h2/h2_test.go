// Package h2e2e is an out-of-module integration test: it drives a real
// golang.org/x/net/http2 server with an extended CONNECT and proves that
// ws.Upgrader.Upgrade serves a WebSocket over that stream end-to-end. It
// lives in its own module (not the root) so the root go.mod — and the
// multiver gate, which must still build on go1.25.0 — never pulls in
// golang.org/x/net. Run it with:
//
//	cd e2e/h2 && GOTOOLCHAIN=go1.26.0 GODEBUG=http2xconnect=1 go test
//
// Two things must hold, both read at package init. http2xconnect=1 makes
// x/net/http2 route extended CONNECT (Issue #71128). The go1.26 toolchain
// matters because from Go 1.27 the stdlib HTTP/2 client owns the
// extended-CONNECT path and still rejects the :protocol pseudo-header
// (Issue #53208); x/net on go1.26 still ships its own transport, which
// handles it.
package h2e2e

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	http2 "golang.org/x/net/http2"

	ws "github.com/jodoherty/websocket-go/ws"
)

func TestExtendedConnectH2RoundTrip(t *testing.T) {
	upgrader := ws.NewUpgrader(ws.WithSubprotocols("chat"))
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Logf("upgrade: %v", err)
			return
		}
		for {
			op, msg, err := s.ReadMessage()
			if err != nil {
				return
			}
			if err := s.WriteMessage(op, msg); err != nil {
				return
			}
		}
	}))
	ts.EnableHTTP2 = true
	if err := http2.ConfigureServer(ts.Config, nil); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ts.TLS = ts.Config.TLSConfig
	ts.StartTLS()
	t.Cleanup(ts.Close)

	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(tr.CloseIdleConnections)

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	req, _ := http.NewRequest(http.MethodConnect, ts.URL, pr)
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Protocol", "chat")

	// The client writes one masked frame to the request body (the tunnel's
	// client-to-server direction) and then closes it; x/net's RoundTrip
	// returns once that body is exhausted, and the server has echoed the frame
	// back on the response body by then. The write runs in a goroutine so the
	// unbuffered pipe does not block on this one.
	go func() {
		_, _ = pw.Write(maskedTextFrame("hello"))
		_ = pw.Close()
	}()

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != acceptKey(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, acceptKey(key))
	}
	if got := res.Header.Get("Sec-WebSocket-Protocol"); got != "chat" {
		t.Fatalf("Sec-WebSocket-Protocol = %q, want chat", got)
	}

	op, payload, err := readFrame(res.Body)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if op != 0x1 || !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("echo = (op=%#x %q), want text hello", op, payload)
	}
}

// acceptKey computes the RFC 6455 §1.3 accept value: base64(sha1(key+GUID)).
func acceptKey(key string) string {
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	_, _ = h.Write([]byte(key))
	_, _ = h.Write([]byte(guid))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// maskedTextFrame builds a masked client-to-server text frame with a fixed
// mask, for payloads of at most 125 bytes.
func maskedTextFrame(payload string) []byte {
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	b := []byte{0x81, 0x80 | byte(len(payload))}
	b = append(b, mask[:]...)
	for i, c := range []byte(payload) {
		b = append(b, c^mask[i%4])
	}

	return b
}

// readFrame reads one (unmasked) frame and returns its opcode and payload.
// It handles short payloads only, which is all the echo test produces.
func readFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	op := hdr[0] & 0x0f
	payload := make([]byte, int(hdr[1]&0x7f))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return op, payload, nil
}
