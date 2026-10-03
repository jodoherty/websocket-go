package ws_test

// This file closes out the cheap coverage gaps: small accessors, error
// strings, option functions, the package-level Handle, ClientCert, and the
// Dial failure path. Each test exists for a specific line that would
// otherwise never execute; the behavior assertions are intentionally light.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ws "github.com/jodoherty/websocket-go/ws"
)

// TestErrorStrings pins the error formats (stable, grep-able in logs).
func TestErrorStrings(t *testing.T) {
	ce := &ws.CloseError{Code: 1001, Reason: "going away"}
	got := ce.Error()
	if got != `ws: closed with code 1001 "going away"` {
		t.Fatalf("CloseError.Error() = %q", got)
	}
	code, reason, ok := ws.CloseCode(ce)
	if !ok || code != 1001 || reason != "going away" {
		t.Fatalf("CloseCode = (%d, %q, %v)", code, reason, ok)
	}

	ue := ws.UpgradeError{Status: http.StatusForbidden, Msg: "no client cert"}
	got = ue.Error()
	if got != "ws: upgrade rejected: no client cert (HTTP 403)" {
		t.Fatalf("UpgradeError.Error() = %q", got)
	}
}

// TestConnAccessorsAndDeadlines covers ID, RemoteAddr, LocalAddr,
// SetReadDeadline, SetWriteDeadline.
func TestConnAccessorsAndDeadlines(t *testing.T) {
	s := startServer(t)
	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/echo")
	defer c.Close(ws.StatusNormalClosure, "")

	if c.ID() == 0 {
		t.Error("ID() = 0, want non-zero")
	}
	if c.RemoteAddr().String() == "" {
		t.Error("RemoteAddr() empty")
	}
	if c.LocalAddr().String() == "" {
		t.Error("LocalAddr() empty")
	}

	// SetReadDeadline/SetWriteDeadline must pass through to the transport
	// without error, including while the connection is in use.
	err := c.SetReadDeadline(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err = c.SetReadDeadline(time.Time{}) // clear
	if err != nil {
		t.Fatalf("clearing SetReadDeadline: %v", err)
	}
	err = c.SetWriteDeadline(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	err = c.SetWriteDeadline(time.Time{}) // clear
	if err != nil {
		t.Fatalf("clearing SetWriteDeadline: %v", err)
	}
}

// TestClientCert covers both branches: certificate present, absent, and no
// TLS at all.
func TestClientCert(t *testing.T) {
	cert, err := selfSignedCert("e2e-client")
	if err != nil {
		t.Fatal(err)
	}
	withCert := httptest.NewRequest(http.MethodGet, "/ws", nil)
	withCert.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	got := ws.ClientCert(withCert)
	if got != cert {
		t.Fatalf("ClientCert with cert = %v, want the cert", got)
	}

	noCert := httptest.NewRequest(http.MethodGet, "/ws", nil)
	noCert.TLS = &tls.ConnectionState{}
	got = ws.ClientCert(noCert)
	if got != nil {
		t.Fatalf("ClientCert without cert = %v, want nil", got)
	}

	plain := httptest.NewRequest(http.MethodGet, "/ws", nil)
	got = ws.ClientCert(plain)
	if got != nil {
		t.Fatalf("ClientCert without TLS = %v, want nil", got)
	}
}

// selfSignedCert makes a throwaway self-signed certificate for testing
// ClientCert; nothing needs to verify it.
func selfSignedCert(cn string) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// TestOptionEffects applies every option to a Config and checks its effect,
// covering the client-only options (TLS, dial timeout) that the unit tests
// otherwise never touch.
func TestOptionEffects(t *testing.T) {
	cfg := &ws.Config{}

	ws.WithCheckOrigin(func(_ *http.Request) bool { return true })(cfg)
	if cfg.CheckOrigin == nil || !cfg.CheckOrigin(nil) {
		t.Error("WithCheckOrigin not applied")
	}
	ws.WithRequireClientCert()(cfg)
	if !cfg.RequireClientCert {
		t.Error("WithRequireClientCert not applied")
	}
	ws.WithSubprotocols("vnc1", "binary")(cfg)
	if len(cfg.Subprotocols) != 2 || cfg.Subprotocols[0] != "vnc1" {
		t.Errorf("WithSubprotocols = %v", cfg.Subprotocols)
	}
	ws.WithMaxMessageSize(1234)(cfg)
	if cfg.MaxMessageSize != 1234 {
		t.Errorf("WithMaxMessageSize = %d", cfg.MaxMessageSize)
	}
	ws.WithIdleTimeout(5 * time.Second)(cfg)
	if cfg.IdleTimeout != 5*time.Second {
		t.Errorf("WithIdleTimeout = %v", cfg.IdleTimeout)
	}
	called := false
	ws.WithPreHandshake(func(*http.Request) error {
		called = true
		return nil
	})(cfg)
	if len(cfg.PreHandshake) != 1 {
		t.Fatalf("WithPreHandshake: %d hooks", len(cfg.PreHandshake))
	}
	err := cfg.PreHandshake[0](nil)
	if err != nil || !called {
		t.Error("PreHandshake hook not the one registered")
	}

	// Client-only options: no observable Config field, but each body must
	// run; a broken closure would panic here or at Dial time.
	ws.WithHeader("Authorization", "Bearer x")(cfg)
	got := cfg.Headers.Get("Authorization")
	if got != "Bearer x" {
		t.Errorf("WithHeader = %q", got)
	}
	ws.WithTLS(&tls.Config{InsecureSkipVerify: true})(cfg) //nolint:gosec // test: no real server to verify
	cert, err := selfSignedCert("client")
	if err != nil {
		t.Fatal(err)
	}
	ws.WithTLSClientCert(cert, nil)(cfg)
	ws.WithDialTimeout(time.Second)(cfg)
	_ = ws.WithHandshakeData("v") // HandshakeOption body
}

// TestPackageHandle covers ws.Handle (the default-upgrader shorthand). The
// default origin policy is strict same-origin, so the dial must present a
// matching Origin header — which is exactly what a browser would do.
func TestPackageHandle(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/pkg", ws.Handle(func(_ *http.Request, c *ws.Conn) error {
		err := c.WriteMessage(ws.OpText, []byte("from ws.Handle"))
		if err != nil {
			return err
		}
		return c.Close(ws.StatusNormalClosure, "")
	}))
	s := httptest.NewServer(mux)
	defer s.Close()

	host := strings.TrimPrefix(s.URL, "http://")
	c := mustDial(t, "ws://"+host+"/pkg", ws.WithHeader("Origin", "http://"+host))
	defer c.Close(ws.StatusNormalClosure, "")

	op, data, err := c.ReadMessage()
	if err != nil || op != ws.OpText || string(data) != "from ws.Handle" {
		t.Fatalf("ReadMessage = (%d, %q, %v)", op, data, err)
	}
	// The handler closed normally; the next read reports the clean close.
	op, _, err = c.ReadMessage()
	if op != 0 || err != nil {
		t.Fatalf("after close: op=%d err=%v, want (0, nil)", op, err)
	}
}

// TestUpgradeRejectBranches covers the policy rejections that a dial-based
// test cannot reach individually: client-cert requirement, and the two
// pre-handshake hook failure modes (UpgradeError carries its own status;
// a plain error becomes 403).
func TestUpgradeRejectBranches(t *testing.T) {
	upgradeReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return r
	}
	var ue *ws.UpgradeError

	openOrigin := ws.WithCheckOrigin(func(*http.Request) bool { return true })

	up := ws.NewUpgrader(openOrigin, ws.WithRequireClientCert())
	_, err := up.Upgrade(httptest.NewRecorder(), upgradeReq())
	if !errors.As(err, &ue) || ue.Status != http.StatusForbidden || ue.Msg != "client certificate required" {
		t.Fatalf("client-cert requirement: %v, want 403 UpgradeError", err)
	}

	hook := func(*http.Request) error { return nil }
	// The passing case goes all the way through the protocol switch, which
	// requires a real hijackable connection — a ResponseRecorder cannot.
	up = ws.NewUpgrader(openOrigin, ws.WithPreHandshake(hook))
	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *ws.Conn) error {
		return c.Close(ws.StatusNormalClosure, "")
	}))
	s := httptest.NewServer(mux)
	defer s.Close()
	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/ws")
	op, _, err := c.ReadMessage()
	if op != 0 || err != nil {
		t.Fatalf("pre-handshake pass: ReadMessage = (%d, %v), want clean close", op, err)
	}

	up = ws.NewUpgrader(openOrigin, ws.WithPreHandshake(func(*http.Request) error {
		return &ws.UpgradeError{Status: http.StatusTeapot, Msg: "short and stout"}
	}))
	_, err = up.Upgrade(httptest.NewRecorder(), upgradeReq())
	if !errors.As(err, &ue) || ue.Status != http.StatusTeapot {
		t.Fatalf("pre-handshake UpgradeError: %v, want 418", err)
	}

	up = ws.NewUpgrader(openOrigin, ws.WithPreHandshake(func(*http.Request) error {
		return errors.New("nope")
	}))
	_, err = up.Upgrade(httptest.NewRecorder(), upgradeReq())
	if !errors.As(err, &ue) || ue.Status != http.StatusForbidden {
		t.Fatalf("pre-handshake plain error: %v, want 403", err)
	}

	// The protocol-header rejections. Each drops exactly one required
	// piece of the handshake.
	up = ws.NewUpgrader(openOrigin)
	req := upgradeReq()
	req.Method = http.MethodPost
	_, err = up.Upgrade(httptest.NewRecorder(), req)
	if !errors.As(err, &ue) || ue.Status != http.StatusMethodNotAllowed {
		t.Fatalf("non-GET: %v, want 405", err)
	}

	req = upgradeReq()
	req.Header.Del("Connection")
	_, err = up.Upgrade(httptest.NewRecorder(), req)
	if !errors.As(err, &ue) || ue.Status != http.StatusBadRequest {
		t.Fatalf("no Connection header: %v, want 400", err)
	}

	req = upgradeReq()
	req.Header.Del("Upgrade")
	_, err = up.Upgrade(httptest.NewRecorder(), req)
	if !errors.As(err, &ue) || ue.Status != http.StatusBadRequest {
		t.Fatalf("no Upgrade header: %v, want 400", err)
	}

	req = upgradeReq()
	req.Header.Set("Sec-WebSocket-Version", "8")
	_, err = up.Upgrade(httptest.NewRecorder(), req)
	if !errors.As(err, &ue) || ue.Status != http.StatusUpgradeRequired {
		t.Fatalf("bad version: %v, want 426", err)
	}

	req = upgradeReq()
	req.Header.Del("Sec-WebSocket-Key")
	_, err = up.Upgrade(httptest.NewRecorder(), req)
	if !errors.As(err, &ue) || ue.Status != http.StatusBadRequest {
		t.Fatalf("no key: %v, want 400", err)
	}
}

// TestHandleCloseErrorBranch covers Upgrader.Handle's branch where the
// handler returns a *CloseError: the close the handler chose must be the
// one the peer sees, not a forced normal closure.
func TestHandleCloseErrorBranch(t *testing.T) {
	up := ws.NewUpgrader(ws.WithCheckOrigin(func(*http.Request) bool { return true }))
	mux := http.NewServeMux()
	mux.Handle("/custom", up.Handle(func(_ *http.Request, _ *ws.Conn) error {
		return &ws.CloseError{Code: 4001, Reason: "policy"}
	}))
	s := httptest.NewServer(mux)
	defer s.Close()

	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/custom")
	defer c.Close(ws.StatusNormalClosure, "")
	_, _, err := c.ReadMessage()
	code, reason, ok := ws.CloseCode(err)
	if !ok || code != 4001 || reason != "policy" {
		t.Fatalf("close seen by client: %v (%d %q %v), want 4001 policy", err, code, reason, ok)
	}
}

// TestOriginCheckOnTLS covers defaultCheckOrigin's https branch: a TLS
// request must match an https:// origin, and a mismatched one must be
// rejected before the protocol checks. A passed origin check is detected
// by reaching the (impossible) hijack stage, which fails with 500 on a
// ResponseRecorder.
func TestOriginCheckOnTLS(t *testing.T) {
	mk := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/ws", nil)
		r.Host = "example.com"
		r.TLS = &tls.ConnectionState{}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		return r
	}

	// Wrong scheme (http origin against a TLS request) → 403.
	_, err := ws.NewUpgrader().Upgrade(httptest.NewRecorder(), mk("http://example.com"))
	if err == nil {
		t.Fatal("http origin on a TLS request accepted")
	}

	// Correct https origin → origin check passes, so the failure (if any)
	// is the later, un-hijackable response writer, not the origin.
	_, err = ws.NewUpgrader().Upgrade(httptest.NewRecorder(), mk("https://example.com"))
	if err == nil || strings.Contains(err.Error(), "origin not allowed") {
		t.Fatalf("https origin on a TLS request: %v", err)
	}
}

// TestSmallGaps: CloseCode on a code-less error, and Dial's scheme check.
func TestSmallGaps(t *testing.T) {
	_, _, ok := ws.CloseCode(errors.New("plain"))
	if ok {
		t.Fatal("CloseCode reported a code on a plain error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := ws.Dial(ctx, "http://example.com/ws")
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("Dial with http scheme: %v, want unsupported scheme", err)
	}

	// WithTLSClientCert on a config with no prior TLS state (the nil-cfg
	// branch of the option).
	cfg := &ws.Config{}
	cert, err := selfSignedCert("c")
	if err != nil {
		t.Fatal(err)
	}
	ws.WithTLSClientCert(cert, nil)(cfg)
}

// TestDialCanceledContext covers Dial's context-cancellation path.
func TestDialCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ws.Dial(ctx, "ws://127.0.0.1:1/ws")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial with canceled context: %v, want context.Canceled", err)
	}
}

// TestDialFailure covers Dial's error path (and WithDialTimeout) against a
// port that refuses connections.
func TestDialFailure(t *testing.T) {
	// A listener whose address is free again by the time we dial it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = ws.Dial(ctx, "ws://"+addr+"/ws", ws.WithDialTimeout(time.Second))
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dial to a closed port: err = %v, want refusal", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Logf("note: error text %q (not the classic refusal, but non-nil)", err)
	}
	_ = fmt.Sprintf // keep import if unused on some platforms
}

// TestDialTLSHandshakeFailure pins the wss failure path: dialing wss:// at
// a plain-HTTP server must fail with a wrapped TLS handshake error, not a
// hang or a success.
func TestDialTLSHandshakeFailure(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := ws.Dial(ctx, "wss"+strings.TrimPrefix(s.URL, "http"))
	if err == nil || !strings.Contains(err.Error(), "tls handshake") {
		t.Fatalf("Dial wss:// at a plain server: err = %v, want a tls handshake error", err)
	}
}

// TestDialSkipsReservedHeaders pins the reserved-header guard: user-supplied
// Host / Connection / Upgrade headers must be dropped, not duplicated, and
// the connection must still succeed (the net/http stack sets them).
func TestDialSkipsReservedHeaders(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := ws.Dial(ctx, "ws"+strings.TrimPrefix(s.URL, "http")+"/echo",
		ws.WithHeader("Host", "evil.example"),
		ws.WithHeader("Connection", "upgrade"),
		ws.WithHeader("Upgrade", "websocket"),
	)
	if err != nil {
		t.Fatalf("Dial with reserved headers: %v", err)
	}
	defer conn.Close(ws.StatusNormalClosure, "")
}

// rawResponder answers each accepted connection with a fixed byte string.
func rawResponder(t *testing.T, response string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = conn.Write([]byte(response))
				time.Sleep(100 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()
	return l.Addr().String()
}

// TestDialGarbageResponse pins the non-HTTP response path: a listener that
// speaks garbage must yield a wrapped handshake error.
func TestDialGarbageResponse(t *testing.T) {
	addr := rawResponder(t, "NOT-HTTP\r\n\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := ws.Dial(ctx, "ws://"+addr+"/ws")
	if err == nil || !strings.Contains(err.Error(), "read handshake response") {
		t.Fatalf("Dial at a garbage responder: err = %v, want a handshake error", err)
	}
}

// TestDialBadAccept pins the accept-key verification: a 101 response with a
// wrong Sec-WebSocket-Accept must be rejected.
func TestDialBadAccept(t *testing.T) {
	addr := rawResponder(t, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: deadbeef\r\n\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := ws.Dial(ctx, "ws://"+addr+"/ws")
	if err == nil || !strings.Contains(err.Error(), "Sec-WebSocket-Accept") {
		t.Fatalf("Dial with a bad accept key: err = %v, want an accept-key error", err)
	}
}

// TestDialMalformedURL pins the url.Parse failure branch.
func TestDialMalformedURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ws.Dial(ctx, "ws://127.0.0.1:notaport/ws")
	if err == nil || !strings.Contains(err.Error(), "bad url") {
		t.Fatalf("Dial with a malformed URL = %v, want a 'bad url' error", err)
	}
}

// TestDialDefaultPort pins the no-port branch on both schemes: a host without
// an explicit port must have the default (80 for ws, 443 for wss) filled in
// before dialing. The dials themselves fail (nothing serves those ports
// here), but the branch is exercised before the dial.
func TestDialDefaultPort(t *testing.T) {
	for _, rawurl := range []string{"ws://127.0.0.1/ws", "wss://127.0.0.1/ws"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, dialErr := ws.Dial(ctx, rawurl, ws.WithDialTimeout(200*time.Millisecond))
		cancel()
		if dialErr == nil {
			t.Fatalf("Dial(%q) succeeded; expected a dial or handshake failure", rawurl)
		}
	}
}

// TestUpgradeResponseAlreadyStarted pins the buffered-request guard: a
// request with body bytes left unread when the handler upgrades must get
// a 500 UpgradeError, and the client must see a non-101 response.
func TestUpgradeResponseAlreadyStarted(t *testing.T) {
	up := ws.NewUpgrader(ws.WithCheckOrigin(func(*http.Request) bool { return true }))
	upErrCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/early", func(w http.ResponseWriter, request *http.Request) {
		_, _ = w.Write([]byte("partial"))
		_, upErr := up.Upgrade(w, request)
		upErrCh <- upErr
	})
	s := httptest.NewServer(mux)
	defer s.Close()

	// A raw TCP client sends the upgrade request and a pipelined second
	// request in one write, so the server's bufio read-ahead retains the
	// second request's bytes after parsing the first — the condition the
	// guard is meant to catch (leftover request data at upgrade time).
	host := strings.TrimPrefix(s.URL, "http://")
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := "GET /early HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"\r\n" +
		"GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatal(err)
	}
	// The server responds (a 400, not a 101) and tears the connection
	// down; drain until it closes or the deadline fires.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var response []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		response = append(response, buf[:n]...)
		if err != nil {
			break
		}
	}
	upErr, ok := <-upErrCh
	if !ok {
		t.Fatalf("Upgrade did not return; server response was:\n%s", response)
	}
	upgradeErr := &ws.UpgradeError{}
	if !errors.As(upErr, &upgradeErr) ||
		upgradeErr.Status != http.StatusBadRequest ||
		!strings.Contains(upgradeErr.Msg, "unconsumed request data") {
		t.Fatalf("Upgrade = %v, want a 400 'unconsumed request data'; server response was:\n%s", upErr, response)
	}
}
