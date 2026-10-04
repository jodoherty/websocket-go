// Package e2e contains a Go-based end-to-end test for the mTLS path of the
// demo server.
//
// Browsers (Chromium and Firefox alike) refuse to present client
// certificates on connections whose server certificate they do not trust,
// and the demo server deliberately uses a self-signed CA. So the *positive*
// mTLS case — client cert presented, session opened, identity greeter — is
// driven here by a real ws client against the real demo binary, with the
// same certificates the Playwright suite uses. The *negative* mTLS case
// (no client cert → 403 before the upgrade) is covered by the browser
// tests in tests/ws.spec.ts.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	ws "github.com/jodoherty/websocket-go/ws"
)

// demoEnv holds the demo server's resolved TLS address and the directory of
// its throwaway certificates, populated once by setup() into ephemeral
// allocations (no fixed ports or paths) so repeated or parallel runs cannot
// collide.
//
//nolint:gochecknoglobals // session-wide test state, set once in TestMain's setup
var demoEnv = struct {
	addr    string
	certDir string
}{}

func TestMain(m *testing.M) {
	demoCmd, cleanup, err := setup()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup failed:", err)
		os.Exit(1)
	}
	code := m.Run()
	if demoCmd != nil {
		_ = demoCmd.Process.Kill()
		_ = demoCmd.Wait()
	}
	cleanup()
	os.Exit(code)
}

// setup generates the throwaway CA/server/client certificates and a demo
// binary into a fresh temp directory, launches the demo on ephemeral ports,
// and learns the actual ports from the demo's port report (see cmd/demo's
// -report). It returns the demo command, a cleanup function, and any setup
// error. Setup is verified, not assumed: the demo must report two addresses,
// stay alive, and actually serve TLS before the tests run.
func setup() (*exec.Cmd, func(), error) {
	root, err := filepath.Abs("..")
	if err != nil {
		return nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "ws-e2e-")
	if err != nil {
		return nil, nil, fmt.Errorf("mkdtemp: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	// On any error below, remove the temp dir before returning; on success the
	// caller owns cleanup.
	ok := false
	defer func() {
		if !ok {
			cleanup()
		}
	}()

	certsDir := filepath.Join(tmp, "certs")
	err = run(root, "run", "./cmd/certgen", "-dir", certsDir)
	if err != nil {
		return nil, nil, fmt.Errorf("certgen: %w", err)
	}
	demoEnv.certDir = certsDir
	demoBin := filepath.Join(tmp, "demo.e2e")
	err = run(root, "build", "-o", demoBin, "./cmd/demo")
	if err != nil {
		return nil, nil, fmt.Errorf("build demo: %w", err)
	}

	// The callback listener is bound (and held) by us before the demo
	// launches, so its port is reserved: nothing else can take it. The demo
	// binds its own service listeners on ephemeral ports and reports the
	// actual addresses back over this reserved connection.
	callback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("reserve report listener: %w", err)
	}
	defer callback.Close()

	//nolint:gosec // the binary path is built from the repo root, not peer input.
	demoCmd := exec.Command(demoBin,
		"-addr", "127.0.0.1:0", "-health-addr", "127.0.0.1:0",
		"-certs", demoEnv.certDir, "-report", callback.Addr().String())
	demoCmd.Stdout = os.Stderr
	demoCmd.Stderr = os.Stderr
	err = demoCmd.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("start demo: %w", err)
	}

	addrs, err := readReport(callback, 20*time.Second)
	if err != nil {
		_ = demoCmd.Process.Kill()

		return nil, nil, fmt.Errorf("demo did not report its listeners: %w", err)
	}
	if len(addrs) != 2 {
		_ = demoCmd.Process.Kill()

		return nil, nil, fmt.Errorf("demo reported %d addresses, want 2", len(addrs))
	}
	demoEnv.addr = addrs[0]

	// Verify setup: the demo must still be alive and actually serving TLS on
	// the reported address, not merely bound.
	err = demoCmd.Process.Signal(syscall.Signal(0))
	if err != nil {
		return nil, nil, fmt.Errorf("demo exited during startup: %w", err)
	}
	err = waitTLSReady(demoEnv.addr)
	if err != nil {
		_ = demoCmd.Process.Kill()

		return nil, nil, err
	}

	ok = true

	return demoCmd, cleanup, nil
}

// readReport accepts one connection on the reserved callback listener and
// reads a single line of space-separated "host:port" addresses from it. The
// callback listener is bound before the child launches, so the child's
// connect completes in the kernel backlog and this accept returns whenever
// it is called — no fixed port, no readiness race.
func readReport(l net.Listener, timeout time.Duration) ([]string, error) {
	type report struct {
		addrs []string
		err   error
	}
	ch := make(chan report, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			ch <- report{err: err}

			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			ch <- report{err: err}

			return
		}
		ch <- report{addrs: strings.Fields(line)}
	}()
	select {
	case r := <-ch:
		return r.addrs, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out after %s", timeout)
	}
}

// waitTLSReady dials addr and completes a TLS handshake (accepting any
// certificate — the demo uses a throwaway self-signed CA), retrying until the
// demo is actually serving. This is the setup verification that the reported
// port is a live TLS server, not just a bound socket.
func waitTLSReady(addr string) error {
	//nolint:gosec // e2e: the demo's self-signed certificate is deliberately untrusted.
	cfg := &tls.Config{InsecureSkipVerify: true}
	var lastErr error
	for range 50 {
		conn, err := tls.Dial("tcp", addr, cfg)
		if err == nil {
			_ = conn.Close()

			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("demo TLS listener never became ready: %w", lastErr)
}

func run(dir string, args ...string) error {
	//nolint:gosec // "go" is a fixed binary; args are literal test commands.
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func tlsConfigWithClientCert(t *testing.T) *tls.Config {
	t.Helper()
	caPEM := read(t, filepath.Join(demoEnv.certDir, "ca.pem"))
	clientPEM := read(t, filepath.Join(demoEnv.certDir, "client.pem"))
	clientKey := read(t, filepath.Join(demoEnv.certDir, "client.key"))
	cert, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("bad CA pem")
	}
	return &tls.Config{
		ServerName:   "localhost",
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
	}
}

// tlsDialer is a ws.WithDialer function that wraps the fresh TCP
// connection in the given TLS configuration: the application owns the
// transport policy (root store, client certificates), and the library
// performs only the WebSocket handshake.
func tlsDialer(cfg *tls.Config) func(context.Context, *url.URL) (net.Conn, error) {
	return func(_ context.Context, target *url.URL) (net.Conn, error) {
		conn, err := net.Dial("tcp", target.Host)
		if err != nil {
			return nil, err
		}
		tconn := tls.Client(conn, cfg)
		handshakeErr := tconn.Handshake()
		if handshakeErr != nil {
			_ = conn.Close()

			return nil, handshakeErr
		}

		return tconn, nil
	}
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	//nolint:gosec // paths are literal e2e/certs locations, not peer input.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// lockedBuffer is a bytes.Buffer guarded by a mutex. os/exec fills it from a
// copier goroutine, and the test may read it at any point — including on
// failure paths that fire before cmd.Wait() stops the copier — so
// unsynchronized access would be a data race under -race.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.String()
}

func TestMTLSClientCertOpensSession(t *testing.T) {
	cfg := tlsConfigWithClientCert(t)

	c, err := ws.Dial(context.Background(), "wss://"+demoEnv.addr+"/ws/mtls",
		ws.WithDialer(tlsDialer(cfg)), ws.WithIdleTimeout(0), ws.WithSubprotocols("vnc1"),
		ws.WithHeader("Origin", "https://"+demoEnv.addr))
	if err != nil {
		t.Fatalf("dial /ws/mtls with client cert: %v", err)
	}
	defer c.Close(ws.StatusNormalClosure, "")

	// The server greets us with the identity from the client certificate.
	op, data, err := c.ReadMessage()
	if err != nil || op != ws.OpText || string(data) != "hello, e2e-client" {
		t.Fatalf("greeting = (op=%d data=%q err=%v), want (1 \"hello, e2e-client\" nil)", op, data, err)
	}

	// And the session behaves like any other websocket session.
	writeErr := c.WriteMessage(ws.OpBinary, []byte("through the gate"))
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	op, data, err = c.ReadMessage()
	if err != nil || op != ws.OpBinary || string(data) != "through the gate" {
		t.Fatalf("echo = (op=%d data=%q err=%v)", op, data, err)
	}
}

func TestMTLSWithoutClientCertIsRefused(t *testing.T) {
	caPEM := read(t, filepath.Join(demoEnv.certDir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	_, err := ws.Dial(context.Background(), "wss://"+demoEnv.addr+"/ws/mtls",
		ws.WithDialer(tlsDialer(&tls.Config{ServerName: "localhost", RootCAs: pool})),
		ws.WithIdleTimeout(0), ws.WithHeader("Origin", "https://"+demoEnv.addr))
	if err == nil {
		t.Fatal("dial /ws/mtls without client cert succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("dial error = %v, want 403 refusal", err)
	}
}

// --- Cross-implementation interop (Node's `ws` library <-> this library) ---
//
// Our own client talking to our own server proves internal consistency;
// interop with an independent implementation proves conformance. Both
// directions are covered: Node client -> Go server, and Go client ->
// Node server.

func TestInteropNodeClientAgainstGoServer(t *testing.T) {
	//nolint:gosec // the base URL is the demo address we just started, not peer input.
	cmd := exec.Command("node", "interop-node-client.mjs", "wss://"+demoEnv.addr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node ws client failed against Go server:\n%s (%v)", out, err)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

func TestInteropGoClientAgainstNodeServer(t *testing.T) {
	// The node server binds its own ephemeral ws listener and reports the
	// actual address over a reserved callback listener — the same pattern as
	// the demo's -report — so the Go client learns the port without any
	// fixed value.
	callback, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Close()

	//nolint:gosec // the callback address is the listener we just reserved, not peer input.
	cmd := exec.Command("node", "interop-node-server.mjs", callback.Addr().String())
	var serverOut lockedBuffer
	cmd.Stderr = &serverOut
	startErr := cmd.Start()
	if startErr != nil {
		t.Fatalf("start node server: %v", startErr)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if stderr := serverOut.String(); stderr != "" {
			t.Logf("node server stderr:\n%s", stderr)
		}
	}()

	// Readiness is the report itself: the node server reports its address
	// from the "listening" event, by which point the listener is bound and
	// accepting, so the Go client can dial it directly.
	addrs, err := readReport(callback, 10*time.Second)
	if err != nil {
		t.Fatalf("node server did not report its port: %v (stderr: %s)", err, serverOut.String())
	}
	if len(addrs) != 1 {
		t.Fatalf("node server reported %d addresses, want 1", len(addrs))
	}
	nodeAddr := addrs[0]
	t.Logf("node server listening on %s", nodeAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := ws.Dial(ctx, "ws://"+nodeAddr, ws.WithIdleTimeout(0))
	if err != nil {
		t.Fatalf("Go client dial node ws server: %v", err)
	}
	defer c.Close(ws.StatusNormalClosure, "")

	// permessage-deflate must be negotiated (the Node server accepts the
	// Go client's offer), and a large compressible message must survive the
	// round trip through Node's decompressor.
	if !c.Compressed() {
		t.Fatal("Compressed() = false, want true: permessage-deflate should be negotiated with the Node server")
	}
	big := make([]byte, 1<<19) // 512 KiB of repetitive data
	for i := range big {
		big[i] = byte(i * 13)
	}
	wrErr := c.WriteMessage(ws.OpBinary, big)
	if wrErr != nil {
		t.Fatal(wrErr)
	}
	op, data, err := c.ReadMessage()
	if err != nil || op != ws.OpBinary || len(data) != len(big) || !bytes.Equal(data, big) {
		t.Fatalf("compressed binary echo via node = (op=%d len=%d err=%v)", op, len(data), err)
	}

	// Text and binary round-trips through the Node server.
	writeErr := c.WriteMessage(ws.OpText, []byte("hello from go"))
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	op, data, err = c.ReadMessage()
	if err != nil || op != ws.OpText || string(data) != "hello from go" {
		t.Fatalf("text echo via node = (%d, %q, %v)", op, data, err)
	}
	bin := []byte{0x00, 0x01, 0xfe, 0xff}
	writeErr = c.WriteMessage(ws.OpBinary, bin)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	op, data, err = c.ReadMessage()
	if err != nil || op != ws.OpBinary || string(data) != string(bin) {
		t.Fatalf("binary echo via node = (%d, %q, %v)", op, data, err)
	}

	// Node closes with a custom code; the Go client must report it.
	writeErr = c.WriteMessage(ws.OpText, []byte("close-me"))
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	_, _, err = c.ReadMessage()
	code, reason, ok := ws.CloseCode(err)
	if !ok || code != 4001 || reason != "bye from node" {
		t.Fatalf("close from node = (code=%d reason=%q ok=%v err=%v), want 4001/bye from node", code, reason, ok, err)
	}
}
