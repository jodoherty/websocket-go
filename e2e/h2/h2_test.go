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
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	http2 "golang.org/x/net/http2"

	ws "github.com/jodoherty/websocket-go/ws"
)

func TestExtendedConnectH2RoundTrip(t *testing.T) {
	upgrader := ws.NewUpgrader(
		ws.WithSubprotocols("chat"),
		// The extended-CONNECT stream exposes no per-stream deadline, so the
		// deadline options are waived: liveness is bounded by the transport's
		// own idle timeout. With either option nonzero the upgrade would be
		// refused with a 501.
		ws.WithIdleTimeout(0), ws.WithWriteTimeout(0),
	)
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
	req, _ := http.NewRequest(http.MethodConnect, ts.URL, pr)
	req.Header.Set(":protocol", "websocket")
	// No Sec-WebSocket-Key: RFC 8441 §5 supersedes the HTTP/1-only key with
	// :protocol, so the standards-shaped request omits it.
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
	// RFC 8441 §5: no Sec-WebSocket-Accept is generated over a tunnel.
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != "" {
		t.Fatalf("Sec-WebSocket-Accept = %q, want none (the key is HTTP/1-only)", got)
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

// TestExtendedConnectWithoutKey: RFC 8441 §5 — over extended CONNECT,
// Sec-WebSocket-Key/Accept processing is superseded by :protocol. A
// standards-shaped request that omits the HTTP/1-only key must be accepted,
// not rejected with 400.
func TestExtendedConnectWithoutKey(t *testing.T) {
	upgrader := ws.NewUpgrader(ws.WithIdleTimeout(0), ws.WithWriteTimeout(0))
	ts, conns := h2Server(t, upgrader)
	defer conns.CloseAll()
	tr := h2Transport(t)

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, _ := http.NewRequest(http.MethodConnect, ts.URL, pr)
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	// No Sec-WebSocket-Key: that field is HTTP/1-only (RFC 8441 §5).

	res := boundedRoundTrip(t, tr, req, 5*time.Second)
	if res == nil {
		return
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: the extended CONNECT handshake must not "+
			"require the HTTP/1-only Sec-WebSocket-Key", res.StatusCode)
	}
	_ = res.Body.Close()
}

// TestPersistentH2Exchange: with the tunnel open in both directions, the 200
// headers must arrive promptly and each small echo frame must reach the
// client without any further server write, upload completion, or handler
// return. The round-trip test closes the upload after one message, which
// lets handler completion flush buffered output and masks a missing flush.
func TestPersistentH2Exchange(t *testing.T) {
	upgrader := ws.NewUpgrader(ws.WithIdleTimeout(0), ws.WithWriteTimeout(0))
	ts, conns := h2Server(t, upgrader)
	defer conns.CloseAll()
	tr := h2Transport(t)

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, _ := http.NewRequest(http.MethodConnect, ts.URL, pr)
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")

	res := boundedRoundTrip(t, tr, req, 5*time.Second)
	if res == nil {
		return
	}
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != "" {
		t.Fatalf("Sec-WebSocket-Accept = %q, want none (the key is HTTP/1-only)", got)
	}

	// Three small exchanges while the upload stays open in both directions.
	for i := 0; i < 3; i++ {
		payload := fmt.Sprintf("msg-%d", i)
		if _, err := pw.Write(maskedTextFrame(payload)); err != nil {
			t.Fatalf("write %q to the tunnel: %v", payload, err)
		}
		op, got, err := readFrameWithTimeout(res.Body, 3*time.Second)
		if err != nil {
			t.Fatalf("exchange %d (%q): %v — a small server write did not "+
				"reach the client while the tunnel stayed open", i, payload, err)
		}
		if op != 0x1 || string(got) != payload {
			t.Fatalf("exchange %d = (op=%#x %q), want text %q", i, op, got, payload)
		}
	}
}

// h2Server starts a TLS server with a real x/net/http2 transport whose
// handler upgrades every request and echoes each message. The accepted
// server conns are tracked so tests can force-close them: without that,
// a stalled tunnel (buffered output never flushed) pins the connection
// and the test process.
func h2Server(t *testing.T, upgrader *ws.Upgrader) (*httptest.Server, *trackedConns) {
	t.Helper()
	conns := &trackedConns{}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Logf("upgrade: %v", err)

			return
		}
		for {
			op, msg, readErr := s.ReadMessage()
			if readErr != nil {
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
	tracked := &trackedListener{conns: conns, Listener: ts.Listener}
	ts.Listener = tracked
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return ts, conns
}

// h2Transport builds the x/net/http2 client transport.
func h2Transport(t *testing.T) *http2.Transport {
	t.Helper()
	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	t.Cleanup(tr.CloseIdleConnections)

	return tr
}

// boundedRoundTrip runs the RoundTrip with a bound, so a server that never
// flushes the success headers fails the test instead of hanging the
// process. It returns nil when the deadline (or a transport error) fired.
func boundedRoundTrip(t *testing.T, tr *http2.Transport, req *http.Request, d time.Duration) *http.Response {
	t.Helper()
	type result struct {
		res *http.Response
		err error
	}
	ch := make(chan result, 1)
	go func() {
		res, err := tr.RoundTrip(req)
		ch <- result{res, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("RoundTrip: %v", r.err)
		}

		return r.res
	case <-time.After(d):
		t.Fatalf("did not receive the %s success headers within the bound — the "+
			"server never flushed them while the tunnel was open", d)

		return nil
	}
}

// readFrameWithTimeout reads one frame from the tunnel, bounding the wait
// so a stalled server-side write fails the test instead of hanging it.
func readFrameWithTimeout(r io.Reader, d time.Duration) (byte, []byte, error) {
	type result struct {
		op      byte
		payload []byte
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		op, p, e := readFrame(r)
		ch <- result{op: op, payload: p, err: e}
	}()
	select {
	case res := <-ch:
		return res.op, res.payload, res.err
	case <-time.After(d):
		return 0, nil, fmt.Errorf("timed out after %s waiting for the frame", d)
	}
}

// trackedListener records every accepted conn.
type trackedListener struct {
	net.Listener
	conns *trackedConns
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.conns.add(conn)

	return conn, nil
}

// trackedConns records the server conns a test may force-close at cleanup.
type trackedConns struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (c *trackedConns) add(conn net.Conn) {
	c.mu.Lock()
	c.conns = append(c.conns, conn)
	c.mu.Unlock()
}

// CloseAll force-closes every accepted conn: without it a stalled tunnel
// (buffered output never flushed) pins the connection and the test process.
func (c *trackedConns) CloseAll() {
	c.mu.Lock()
	snapshot := c.conns
	c.conns = nil
	c.mu.Unlock()
	for _, conn := range snapshot {
		_ = conn.Close()
	}
}
