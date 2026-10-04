// Command demo runs a TLS server exercising the ws package: bearer-token
// auth, mTLS client-cert auth, subprotocol negotiation, and a controlled
// close — the same surfaces the e2e Playwright suite drives from real
// Firefox and Chromium.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jodoherty/websocket-go/ws"
)

const (
	page = `<!doctype html>
<html>
<head><title>ws demo</title></head>
<body>
  <h1>websocket demo</h1>
  <p>Open the browser console. The page auto-tests the echo endpoint.</p>
  <script>
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = proto + "//" + location.host + "/ws/echo";
    const log = (m) => document.body.insertAdjacentText("beforeend", m + "\n", "pre");
    log("connecting " + url + " …");
    const ws = new WebSocket(url, "vnc1");
    ws.onopen = () => { log("open (subprotocol " + ws.protocol + ")"); ws.send("hello, server"); };
    ws.onmessage = (e) => { log("echo: " + e.data); ws.close(1000, "done"); };
    ws.onclose = (e) => log("closed " + e.code + " " + e.reason);
    ws.onerror = () => log("error — check that the page was served from this host");
  </script>
</body>
</html>`

	// demoMaxMessageSize caps each message at 1 MiB.
	demoMaxMessageSize = 1 << 20
	// readHeaderTimeout bounds the TLS server's header read;
	// healthReadHeaderTimeout does the same for the health endpoint.
	readHeaderTimeout       = 10 * time.Second
	healthReadHeaderTimeout = 5 * time.Second
	// goodbyeDelay spaces the "hello" and the close on /ws/goodbye.
	goodbyeDelay = 50 * time.Millisecond
)

func main() {
	addr := flag.String("addr", ":8443", "TLS listen address (:0 for an ephemeral port)")
	certs := flag.String("certs", "e2e/certs", "directory containing ca.pem, server.pem, server.key")
	healthAddr := flag.String("health-addr", "127.0.0.1:8444",
		"plain-HTTP health-check listen address (:0 = ephemeral)")
	report := flag.String("report", "", "host:port of a harness-owned callback listener to report the bound addresses to")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           buildMux(),
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig:         tlsConfig(*certs),
	}
	health := &http.Server{
		Addr:              *healthAddr,
		ReadHeaderTimeout: healthReadHeaderTimeout,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/health" {
				writer.WriteHeader(http.StatusOK)

				return
			}
			http.NotFound(writer, request)
		}),
	}

	// Bind the listeners before serving so an ephemeral address (:0) resolves
	// to a real port we can report to the harness, and so a port conflict
	// fails before we ever claim readiness. A fresh ListenConfig keeps the
	// dials context-bounded (noctx).
	lc := net.ListenConfig{}
	tlsL, err := lc.Listen(context.Background(), "tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	healthL, err := lc.Listen(context.Background(), "tcp", *healthAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *healthAddr, err)
	}

	// -report turns this into a harness-discoverable server: the callback
	// listener is created and reserved by the harness before it launches us,
	// so this connection is the "here are my (ephemeral) ports" handshake.
	// Without it the demo just serves on the configured address.
	if *report != "" {
		go reportBound(*report, tlsL.Addr(), healthL.Addr())
	}
	log.Printf("demo server on %s (bearer token via DEMO_TOKEN, default %q)",
		tlsL.Addr(), token())

	go func() {
		log.Printf("health check on %s", healthL.Addr())
		_ = health.Serve(healthL)
	}()
	serveErr := srv.ServeTLS(tlsL, *certs+"/server.pem", *certs+"/server.key")
	if serveErr != nil {
		log.Fatal(serveErr)
	}
}

// reportBound dials the harness-owned callback listener given by -report and
// writes the actual bound addresses of the demo's listeners, one line of
// space-separated "host:port" strings, then closes. The callback listener is
// bound and reserved by the harness before it launches this process, so the
// connection is the handshake that lets the harness learn ephemeral (:0)
// listeners without any fixed port.
func reportBound(callback string, addrs ...net.Addr) {
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", callback)
	if err != nil {
		log.Printf("report: dial %s: %v", callback, err)

		return
	}
	defer func() { _ = conn.Close() }()
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	_, _ = fmt.Fprintf(conn, "%s\n", strings.Join(parts, " "))
}

// buildMux assembles the demo's routes: echo (plain upgrader sugar),
// bearer-gated echo (self-upgrading handler), mTLS-gated echo, and a
// controlled-close endpoint.
func buildMux() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/certinfo", certinfoHandler)
	mux.HandleFunc("/", rootHandler)

	echoUp := ws.NewUpgrader(
		ws.WithSubprotocols("vnc1", "binary"),
		ws.WithMaxMessageSize(demoMaxMessageSize),
	)
	mtlsUp := ws.NewUpgrader(
		ws.WithRequireClientCert(),
		ws.WithSubprotocols("vnc1"),
	)

	// Plain upgrader sugar: the handler itself is the session.
	mux.Handle("/ws/echo", echoUp.Handle(func(_ *http.Request, conn *ws.Conn) error {
		log.Printf("echo session %d from %s (subprotocol %q, compressed=%v)",
			conn.ID(), conn.RemoteAddr(), conn.Subprotocol(), conn.Compressed())

		return echo(conn)
	}))

	// Connection report: the browser WebSocket API exposes no negotiated
	// extensions, so the Playwright permessage-deflate assertion reads the
	// server-side view here.
	mux.Handle("/ws/info", echoUp.Handle(func(_ *http.Request, conn *ws.Conn) error {
		info := fmt.Sprintf(`{"compressed":%v,"subprotocol":%q}`,
			conn.Compressed(), conn.Subprotocol())
		writeErr := conn.WriteMessage(ws.OpText, []byte(info))
		if writeErr != nil {
			return fmt.Errorf("demo: write connection report: %w", writeErr)
		}

		return nil
	}))

	// Self-upgrading handler: ordinary HTTP auth first, then the upgrade.
	mux.Handle("/ws/bearer", bearerHandler(echoUp))

	// mTLS: the TLS layer verifies the client cert; RequireClientCert
	// rejects any request that arrived without one.
	mux.Handle("/ws/mtls", mtlsUp.Handle(func(request *http.Request, conn *ws.Conn) error {
		if cert := ws.ClientCert(request); cert != nil {
			greeting := "hello, " + cert.Subject.CommonName
			_ = conn.WriteMessage(ws.OpText, []byte(greeting))
		}

		return echo(conn)
	}))

	// Controlled close: one message, then 1001 "going away".
	mux.Handle("/ws/goodbye", echoUp.Handle(func(_ *http.Request, conn *ws.Conn) error {
		_ = conn.WriteMessage(ws.OpText, []byte("hello"))
		time.Sleep(goodbyeDelay)
		_ = conn.Close(ws.StatusGoingAway, "going away")

		return nil
	}))

	return mux
}

// certinfoHandler echoes the client certificate's common name, if the
// request was presented with one.
func certinfoHandler(writer http.ResponseWriter, request *http.Request) {
	//nolint:gosec // demo: the cert CN is echoed back verbatim; the demo is
	// not a production endpoint.
	if cert := ws.ClientCert(request); cert != nil {
		_, _ = writer.Write([]byte(cert.Subject.CommonName))

		return
	}
	writer.WriteHeader(http.StatusForbidden)
	_, _ = writer.Write([]byte("no client certificate"))
}

func rootHandler(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)

		return
	}
	writer.Header().Set("Content-Type", "text/html")
	_, _ = writer.Write([]byte(page))
}

// bearerHandler returns the /ws/bearer self-upgrading handler: it runs
// ordinary HTTP bearer-token auth before switching protocols.
func bearerHandler(upgrader *ws.Upgrader) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !validToken(request, token()) {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)

			return
		}
		conn, err := upgrader.Upgrade(writer, request, ws.WithHandshakeData("bearer-user"))
		if err != nil {
			return // response already written
		}
		defer func() {
			_ = conn.Close(ws.StatusNormalClosure, "")
		}()
		//nolint:gosec // demo logging: address comes from the peer's socket.
		log.Printf("bearer session %d from %s", conn.ID(), conn.RemoteAddr())
		echoErr := echo(conn)
		if echoErr != nil {
			//nolint:gosec // demo logging: error text is ours, not the peer's.
			log.Printf("bearer session %d ended: %v", conn.ID(), echoErr)
		}
	}
}

// tlsConfig builds the server's TLS configuration: server verification
// against the e2e CA and optional client-cert verification (the mTLS
// gate itself is per-endpoint, via ws.WithRequireClientCert).
func tlsConfig(certsDir string) *tls.Config {
	//nolint:gosec // certsDir is an operator-supplied flag, not peer input.
	caPEM, err := os.ReadFile(certsDir + "/ca.pem")
	if err != nil {
		panic(fmt.Sprintf("read ca: %v (run go run ./cmd/certgen first)", err))
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
}

func token() string {
	if envToken := os.Getenv("DEMO_TOKEN"); envToken != "" {
		return envToken
	}

	return "demo-secret"
}

// validToken accepts the bearer token in the Authorization header or, for
// browser clients (which cannot set headers), the ?token= query parameter.
func validToken(request *http.Request, token string) bool {
	tokenValue, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	if !ok {
		tokenValue = request.URL.Query().Get("token")
	}

	return tokenValue != "" && subtle.ConstantTimeCompare([]byte(tokenValue), []byte(token)) == 1
}

// echo runs the read loop: every message is written back until the
// connection closes (a 1000 close reads as io.EOF).
func echo(conn *ws.Conn) error {
	for {
		opcode, data, err := conn.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}

			return fmt.Errorf("demo: read: %w", err)
		}
		writeErr := conn.WriteMessage(opcode, data)
		if writeErr != nil {
			return fmt.Errorf("demo: write: %w", writeErr)
		}
	}
}
