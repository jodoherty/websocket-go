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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ws "github.com/jodoherty/websocket/ws"
)

const (
	wsAddr    = "127.0.0.1:18443"
	healthURL = "http://127.0.0.1:18444/health"
)

var demoCmd *exec.Cmd

func TestMain(m *testing.M) {
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e setup failed:", err)
		os.Exit(1)
	}
	code := m.Run()
	if demoCmd != nil {
		_ = demoCmd.Process.Kill()
		_ = demoCmd.Wait()
	}
	os.Exit(code)
}

func setup() error {
	root, err := filepath.Abs("..")
	if err != nil {
		return err
	}
	if err := run(root, "run", "./cmd/certgen", "-dir", filepath.Join(root, "e2e/certs")); err != nil {
		return fmt.Errorf("certgen: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "e2e/.bin"), 0o755); err != nil {
		return err
	}
	if err := run(root, "build", "-o", filepath.Join(root, "e2e/.bin/demo.e2e"), "./cmd/demo"); err != nil {
		return fmt.Errorf("build demo: %w", err)
	}
	demoCmd = exec.Command(filepath.Join(root, "e2e/.bin/demo.e2e"),
		"-addr", wsAddr, "-certs", filepath.Join(root, "e2e/certs"), "-health-addr", "127.0.0.1:18444")
	demoCmd.Stdout = os.Stderr
	demoCmd.Stderr = os.Stderr
	if err := demoCmd.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("demo server did not become ready")
}

func run(dir string, args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func tlsConfigWithClientCert(t *testing.T, root string) *tls.Config {
	t.Helper()
	caPEM := read(t, filepath.Join(root, "e2e/certs/ca.pem"))
	clientPEM := read(t, filepath.Join(root, "e2e/certs/client.pem"))
	clientKey := read(t, filepath.Join(root, "e2e/certs/client.key"))
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

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func TestMTLSClientCertOpensSession(t *testing.T) {
	root, _ := filepath.Abs("..")
	cfg := tlsConfigWithClientCert(t, root)

	c, err := ws.Dial(context.Background(), "wss://"+wsAddr+"/ws/mtls",
		ws.WithTLS(cfg), ws.WithIdleTimeout(0), ws.WithSubprotocols("vnc1"),
		ws.WithHeader("Origin", "https://"+wsAddr))
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
	if err := c.WriteMessage(ws.OpBinary, []byte("through the gate")); err != nil {
		t.Fatal(err)
	}
	op, data, err = c.ReadMessage()
	if err != nil || op != ws.OpBinary || string(data) != "through the gate" {
		t.Fatalf("echo = (op=%d data=%q err=%v)", op, data, err)
	}
}

func TestMTLSWithoutClientCertIsRefused(t *testing.T) {
	root, _ := filepath.Abs("..")
	caPEM := read(t, filepath.Join(root, "e2e/certs/ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	_, err := ws.Dial(context.Background(), "wss://"+wsAddr+"/ws/mtls",
		ws.WithTLS(&tls.Config{ServerName: "localhost", RootCAs: pool}),
		ws.WithIdleTimeout(0), ws.WithHeader("Origin", "https://"+wsAddr))
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
	cmd := exec.Command("node", "interop-node-client.mjs", "wss://"+wsAddr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node ws client failed against Go server:\n%s (%v)", out, err)
	}
	t.Logf("%s", strings.TrimSpace(string(out)))
}

func TestInteropGoClientAgainstNodeServer(t *testing.T) {
	const nodeAddr = "127.0.0.1:18543"
	cmd := exec.Command("node", "interop-node-server.mjs", "18543")
	var serverOut bytes.Buffer
	cmd.Stderr = &serverOut
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if serverOut.Len() > 0 {
			t.Logf("node server stderr:\n%s", serverOut.String())
		}
	}()

	// Wait for the node server to report readiness, then for the port to
	// actually be reachable — the former is the process's claim, the latter
	// is the precondition we depend on.
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		t.Fatalf("node server did not report ready (stderr: %s)", serverOut.String())
	}
	for i := 0; ; i++ {
		nc, err := net.DialTimeout("tcp", nodeAddr, time.Second)
		if err == nil {
			nc.Close()
			break
		}
		if i == 50 {
			t.Fatalf("node server port never became reachable: %v (stderr: %s)", err, serverOut.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := ws.Dial(ctx, "ws://"+nodeAddr, ws.WithIdleTimeout(0))
	if err != nil {
		t.Fatalf("Go client dial node ws server: %v", err)
	}
	defer c.Close(ws.StatusNormalClosure, "")

	// Text and binary round-trips through the Node server.
	if err := c.WriteMessage(ws.OpText, []byte("hello from go")); err != nil {
		t.Fatal(err)
	}
	op, data, err := c.ReadMessage()
	if err != nil || op != ws.OpText || string(data) != "hello from go" {
		t.Fatalf("text echo via node = (%d, %q, %v)", op, data, err)
	}
	bin := []byte{0x00, 0x01, 0xfe, 0xff}
	if err := c.WriteMessage(ws.OpBinary, bin); err != nil {
		t.Fatal(err)
	}
	op, data, err = c.ReadMessage()
	if err != nil || op != ws.OpBinary || string(data) != string(bin) {
		t.Fatalf("binary echo via node = (%d, %q, %v)", op, data, err)
	}

	// Node closes with a custom code; the Go client must report it.
	if err := c.WriteMessage(ws.OpText, []byte("close-me")); err != nil {
		t.Fatal(err)
	}
	_, _, err = c.ReadMessage()
	code, reason, ok := ws.CloseCode(err)
	if !ok || code != 4001 || reason != "bye from node" {
		t.Fatalf("close from node = (code=%d reason=%q ok=%v err=%v), want 4001/bye from node", code, reason, ok, err)
	}
}
