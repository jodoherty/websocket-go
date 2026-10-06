// Audit reproductions for the HTTP/2 extended-CONNECT findings. Like the
// round-trip test they live in the h2 module and need the go1.26 toolchain
// plus GODEBUG=http2xconnect=1:
//
//	cd e2e/h2 && GOTOOLCHAIN=go1.26.0 GODEBUG=http2xconnect=1 go test -run TestAudit
//
// These tests assert the DESIRED behavior and FAIL against the audited
// revision: Finding 5 (the key must not be required) and Finding 10
// (headers and small frames must be flushed while the tunnel stays open).
package h2e2e

import (
	"crypto/tls"
	"encoding/base64"
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

// TestAuditExtendedConnectWithoutKey (Finding 5): RFC 8441 §5 — over
// extended CONNECT, Sec-WebSocket-Key/Accept processing is superseded by
// :protocol. A standards-shaped request that omits the HTTP/1-only key
// must be accepted, not rejected with 400.
func TestAuditExtendedConnectWithoutKey(t *testing.T) {
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

// TestAuditPersistentH2Exchange (Finding 10): with the tunnel open in both
// directions, the 200 headers must arrive promptly and each small echo
// frame must reach the client without any further server write, upload
// completion, or handler return. The existing round-trip test closes the
// upload after one message, which lets handler completion flush buffered
// output and masks the failure.
func TestAuditPersistentH2Exchange(t *testing.T) {
	upgrader := ws.NewUpgrader(ws.WithIdleTimeout(0), ws.WithWriteTimeout(0))
	ts, conns := h2Server(t, upgrader)
	defer conns.CloseAll()
	tr := h2Transport(t)

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, _ := http.NewRequest(http.MethodConnect, ts.URL, pr)
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")

	res := boundedRoundTrip(t, tr, req, 5*time.Second)
	if res == nil {
		return
	}
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != acceptKey(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, acceptKey(key))
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
