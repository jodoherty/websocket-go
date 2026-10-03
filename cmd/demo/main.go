// Command demo runs a TLS server exercising the ws package: bearer-token
// auth, mTLS client-cert auth, subprotocol negotiation, and a controlled
// close — the same surfaces the e2e Playwright suite drives from real
// Firefox and Chromium.
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jodoherty/websocket/ws"
)

const page = `<!doctype html>
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

func main() {
	addr := flag.String("addr", ":8443", "TLS listen address")
	certs := flag.String("certs", "e2e/certs", "directory containing ca.pem, server.pem, server.key")
	healthAddr := flag.String("health-addr", "127.0.0.1:8444", "plain-HTTP health-check listen address")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           BuildMux(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         TLSConfig(*certs),
	}
	log.Printf("demo server on %s (bearer token via DEMO_TOKEN, default %q)", *addr, token())
	health := &http.Server{
		Addr:              *healthAddr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
		}),
	}
	go func() {
		log.Printf("health check on %s", *healthAddr)
		_ = health.ListenAndServe()
	}()
	if err := srv.ListenAndServeTLS(*certs+"/server.pem", *certs+"/server.key"); err != nil {
		log.Fatal(err)
	}
}

// BuildMux assembles the demo's routes: echo (plain upgrader sugar),
// bearer-gated echo (self-upgrading handler), mTLS-gated echo, and a
// controlled-close endpoint.
func BuildMux() http.Handler {
	echoUp := ws.NewUpgrader(
		ws.WithSubprotocols("vnc1", "binary"),
		ws.WithMaxMessageSize(1<<20),
	)
	mtlsUp := ws.NewUpgrader(
		ws.WithRequireClientCert(),
		ws.WithSubprotocols("vnc1"),
	)

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/certinfo", func(w http.ResponseWriter, r *http.Request) {
		if c := ws.ClientCert(r); c != nil {
			_, _ = w.Write([]byte(c.Subject.CommonName))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("no client certificate"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(page))
	})

	// Plain upgrader sugar: the handler itself is the session.
	mux.Handle("/ws/echo", echoUp.Handle(func(r *http.Request, c *ws.Conn) error {
		log.Printf("echo session %d from %s (subprotocol %q)", c.ID(), c.RemoteAddr(), c.Subprotocol())
		return echo(c)
	}))

	// Self-upgrading handler: ordinary HTTP auth first, then the upgrade.
	mux.Handle("/ws/bearer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validToken(r, token()) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := echoUp.Upgrade(w, r, ws.WithHandshakeData("bearer-user"))
		if err != nil {
			return // response already written
		}
		defer c.Close(ws.StatusNormalClosure, "")
		log.Printf("bearer session %d from %s", c.ID(), c.RemoteAddr())
		if err := echo(c); err != nil {
			log.Printf("bearer session %d ended: %v", c.ID(), err)
		}
	}))

	// mTLS: the TLS layer verifies the client cert; RequireClientCert
	// rejects any request that arrived without one.
	mux.Handle("/ws/mtls", mtlsUp.Handle(func(r *http.Request, c *ws.Conn) error {
		if cert := ws.ClientCert(r); cert != nil {
			greeting := "hello, " + cert.Subject.CommonName
			_ = c.WriteMessage(ws.OpText, []byte(greeting))
		}
		return echo(c)
	}))

	// Controlled close: one message, then 1001 "going away".
	mux.Handle("/ws/goodbye", echoUp.Handle(func(r *http.Request, c *ws.Conn) error {
		_ = c.WriteMessage(ws.OpText, []byte("hello"))
		time.Sleep(50 * time.Millisecond)
		_ = c.Close(ws.StatusGoingAway, "going away")
		return nil
	}))

	return mux
}

// TLSConfig builds the server's TLS configuration: server verification
// against the e2e CA and optional client-cert verification (the mTLS
// gate itself is per-endpoint, via ws.WithRequireClientCert).
func TLSConfig(certsDir string) *tls.Config {
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
	if t := os.Getenv("DEMO_TOKEN"); t != "" {
		return t
	}
	return "demo-secret"
}

// validToken accepts the bearer token in the Authorization header or, for
// browser clients (which cannot set headers), the ?token= query parameter.
func validToken(r *http.Request, token string) bool {
	t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		t = r.URL.Query().Get("token")
	}
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1
}

func echo(c *ws.Conn) error {
	for {
		op, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		if op == 0 {
			return nil
		}
		if err := c.WriteMessage(op, data); err != nil {
			return err
		}
	}
}
