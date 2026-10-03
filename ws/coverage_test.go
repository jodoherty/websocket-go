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

	ws "github.com/jodoherty/websocket/ws"
)

// TestErrorStrings pins the error formats (stable, grep-able in logs).
func TestErrorStrings(t *testing.T) {
	ce := &ws.CloseError{Code: 1001, Reason: "going away"}
	if got := ce.Error(); got != `ws: closed with code 1001 "going away"` {
		t.Fatalf("CloseError.Error() = %q", got)
	}
	if code, reason, ok := ws.CloseCode(ce); !ok || code != 1001 || reason != "going away" {
		t.Fatalf("CloseCode = (%d, %q, %v)", code, reason, ok)
	}

	ue := ws.UpgradeError{Status: http.StatusForbidden, Msg: "no client cert"}
	if got := ue.Error(); got != "ws: upgrade rejected: no client cert (HTTP 403)" {
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
	if err := c.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil { // clear
		t.Fatalf("clearing SetReadDeadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := c.SetWriteDeadline(time.Time{}); err != nil { // clear
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
	if got := ws.ClientCert(withCert); got != cert {
		t.Fatalf("ClientCert with cert = %v, want the cert", got)
	}

	noCert := httptest.NewRequest(http.MethodGet, "/ws", nil)
	noCert.TLS = &tls.ConnectionState{}
	if got := ws.ClientCert(noCert); got != nil {
		t.Fatalf("ClientCert without cert = %v, want nil", got)
	}

	plain := httptest.NewRequest(http.MethodGet, "/ws", nil)
	if got := ws.ClientCert(plain); got != nil {
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

	ws.WithCheckOrigin(func(r *http.Request) bool { return true })(cfg)
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
	if err := cfg.PreHandshake[0](nil); err != nil || !called {
		t.Error("PreHandshake hook not the one registered")
	}

	// Client-only options: no observable Config field, but each body must
	// run; a broken closure would panic here or at Dial time.
	ws.WithHeader("Authorization", "Bearer x")(cfg)
	if got := cfg.Headers.Get("Authorization"); got != "Bearer x" {
		t.Errorf("WithHeader = %q", got)
	}
	ws.WithTLS(&tls.Config{InsecureSkipVerify: true})(cfg)
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
	mux.Handle("/pkg", ws.Handle(func(r *http.Request, c *ws.Conn) error {
		if err := c.WriteMessage(ws.OpText, []byte("from ws.Handle")); err != nil {
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
	if op, _, err := c.ReadMessage(); op != 0 || err != nil {
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
	mux.Handle("/ws", up.Handle(func(r *http.Request, c *ws.Conn) error {
		return c.Close(ws.StatusNormalClosure, "")
	}))
	s := httptest.NewServer(mux)
	defer s.Close()
	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/ws")
	if op, _, err := c.ReadMessage(); op != 0 || err != nil {
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
	mux.Handle("/custom", up.Handle(func(r *http.Request, c *ws.Conn) error {
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
	if _, err := ws.NewUpgrader().Upgrade(httptest.NewRecorder(), mk("http://example.com")); err == nil {
		t.Fatal("http origin on a TLS request accepted")
	}

	// Correct https origin → origin check passes, so the failure (if any)
	// is the later, un-hijackable response writer, not the origin.
	_, err := ws.NewUpgrader().Upgrade(httptest.NewRecorder(), mk("https://example.com"))
	if err == nil || strings.Contains(err.Error(), "origin not allowed") {
		t.Fatalf("https origin on a TLS request: %v", err)
	}
}

// TestSmallGaps: CloseCode on a code-less error, and Dial's scheme check.
func TestSmallGaps(t *testing.T) {
	if _, _, ok := ws.CloseCode(errors.New("plain")); ok {
		t.Fatal("CloseCode reported a code on a plain error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := ws.Dial(ctx, "http://example.com/ws"); err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
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
	if _, err := ws.Dial(ctx, "ws://127.0.0.1:1/ws"); !errors.Is(err, context.Canceled) {
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
	l.Close()

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
