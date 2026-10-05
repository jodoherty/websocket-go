package ws

// This file holds the package's Example functions. They are rendered by
// `go doc` and pkg.go.dev, and — unlike plain doc-comment code blocks,
// which are never compiled or run — they are real tests: each one is built
// and executed on every `go test` (and under -race), with its output pinned
// by a golden // Output: line. The documentation is therefore executable,
// and each example doubles as an integration test of one entry point:
//
//   - Example:         ws.Handle + Dial — an echo round trip
//   - ExampleUpgrader:  auth middleware + the request context + Upgrade
//   - ExampleDial:      programmatic client, bearer token via WithHeader
//   - ExampleWithDialer: the custom-transport seam (WithDialer)
//   - ExampleWithDialer_mtls:    the standard-library mTLS dial — WithDialer with
//                         a custom root store and a client certificate,
//                         against a server whose mTLS gate is ordinary
//                         middleware
//   - ExampleDialRaw:   the raw face — events, answering pings, a two-frame
//                       write, and the peer's close as an OpClose event
//   - ExampleCloseCode: application close codes, end to end
//   - ExampleWithCheckOrigin: origin allowlist, per-endpoint size cap, and
//                             per-action authorization (1008)
//   - ExampleSession_WriteText: the text-frame UTF-8 rule — a refused write
//                             leaves the connection open
//
// Note the // Output: block sits inside each function body: since Go 1.27
// the golden-output comment is only recognized there; in the old
// after-the-closing-brace position it is silently ignored and the example
// is never run at all.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

// wsURL converts an httptest http:// URL to its ws:// equivalent.
func wsURL(httpURL string) string {
	u, err := url.Parse(httpURL)
	if err != nil {
		panic(err)
	}
	return "ws://" + u.Host
}

// Example is the whole trip: a session on a plain http.ServeMux, and a
// client that connects, sends a message, and receives the echo.
//
// The upgrader runs its default origin policy: requests without an Origin
// header (programmatic clients) are allowed, and a browser presenting an
// Origin that is not the page's own origin is rejected. Use
// [WithCheckOrigin] to customize.
func Example() {
	up := NewUpgrader()

	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Session) error {
		for {
			op, data, err := c.ReadMessage()
			if err != nil {
				if errors.Is(err, io.EOF) { // normal close (1000)
					return nil
				}

				return err
			}
			fmt.Println("server:", string(data))
			err = c.WriteMessage(op, data)
			if err != nil {
				return err
			}
		}
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := Dial(context.Background(), wsURL(srv.URL)+"/ws")
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	err = c.WriteMessage(OpText, []byte("hello"))
	if err != nil {
		panic(err)
	}
	op, data, err := c.ReadMessage()
	if err != nil || op != OpText {
		panic(fmt.Sprintf("round trip failed: %v", err))
	}
	fmt.Println("client:", string(data))
	// Output:
	// server: hello
	// client: hello
}

// ExampleUpgrader shows the pattern the package is built around:
// authentication is ordinary middleware that runs before the upgrade, and
// its result rides on the request context into the message handler instead
// of globals. Browsers cannot set headers on the upgrade, so the token
// comes in a query parameter here — demo-grade, not a pattern to copy:
// a token in the URL rides in access logs, browser history, and Referer
// headers; production prefers the Authorization header (ExampleDial) or
// mTLS. The upgrader keeps its default origin policy: the programmatic
// client below sends no Origin, and a cross-origin browser would still be
// rejected.
func ExampleUpgrader() {
	up := NewUpgrader(WithSubprotocols("chat.v1"))

	// auth is a plain http.Handler wrapper: nothing about it is
	// websocket-specific.
	type principalKey struct{}
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if subtle.ConstantTimeCompare([]byte(token), []byte("secret")) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)

				return
			}
			r = r.WithContext(context.WithValue(r.Context(), principalKey{}, token))
			next.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", auth(up.Handle(func(r *http.Request, c *Session) error {
		principal, _ := r.Context().Value(principalKey{}).(string)
		op, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		fmt.Println(c.Subprotocol(), principal, "says", string(data))
		return c.WriteMessage(op, data)
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := Dial(context.Background(), wsURL(srv.URL)+"/ws?token=secret", WithSubprotocols("chat.v1"))
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	err = c.WriteMessage(OpText, []byte("hi"))
	if err != nil {
		panic(err)
	}
	op, data, err := c.ReadMessage()
	if err != nil || op != OpText {
		panic(fmt.Sprintf("round trip failed: %v", err))
	}
	fmt.Println("client:", c.Subprotocol(), string(data))
	// Output:
	// chat.v1 secret says hi
	// client: chat.v1 hi
}

// ExampleDial shows a programmatic client authenticating with a bearer
// token. The token check is ordinary middleware in front of the upgrader —
// nothing about it is websocket-specific — while the client sets the header
// on the upgrade request with WithHeader, which browsers cannot do. The
// upgrader keeps its default origin policy: the client below sends no
// Origin header, and a browser presenting one must match the page's own
// origin.
func ExampleDial() {
	up := NewUpgrader()

	bearer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")),
				[]byte("Bearer demo-secret")) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)

				return
			}
			next.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", bearer(up.Handle(func(_ *http.Request, c *Session) error {
		_, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		fmt.Println("server:", string(data))
		return nil // the handler returns: Handle closes with 1000
	})))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := Dial(context.Background(), wsURL(srv.URL)+"/ws", WithHeader("Authorization", "Bearer demo-secret"))
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	err = c.WriteMessage(OpText, []byte("hi"))
	if err != nil {
		panic(err)
	}
	op, _, err := c.ReadMessage()
	if !errors.Is(err, io.EOF) {
		panic(err)
	}
	if op != 0 {
		panic("expected normal close")
	}
	fmt.Println("client: closed normally")
	// Output:
	// server: hi
	// client: closed normally
}

// ExampleWithDialer shows the custom-transport seam: the application owns
// the connection policy — here TLS is deliberately omitted, so a wss://
// URL runs over plain TCP — and the library performs only the WebSocket
// handshake over whatever connection the dialer returns.
func ExampleWithDialer() {
	up := NewUpgrader()

	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Session) error {
		_, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		fmt.Println("server:", string(data))
		return nil
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := Dial(context.Background(), "wss://"+srv.Listener.Addr().String()+"/ws",
		WithDialer(func(_ context.Context, target *url.URL) (net.Conn, error) {
			return net.Dial("tcp", target.Host) // the app's policy: no TLS
		}))
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	err = c.WriteMessage(OpText, []byte("hi"))
	if err != nil {
		panic(err)
	}
	_, _, err = c.ReadMessage()
	if !errors.Is(err, io.EOF) {
		panic(err)
	}
	fmt.Println("client: closed normally")
	// Output:
	// server: hi
	// client: closed normally
}

// mTLS fixture: a throwaway CA and the two certificates it signs, so the
// example is self-contained (nothing trusted by the system, nothing on
// disk). The server certificate is valid for localhost and the loopback
// address; the client certificate carries the CN the server's handler
// will read back.
func mtlsExampleCerts() (caPool *x509.CertPool, server, client tls.Certificate) {
	caKey, caTmpl := exampleKey(), &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ws-example CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}

	leaf := func(serial int64, commonName string, extKeyUsage x509.ExtKeyUsage) tls.Certificate {
		key := exampleKey()
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extKeyUsage},
		}
		if extKeyUsage == x509.ExtKeyUsageServerAuth {
			// The example dials the httptest listener's own address.
			tmpl.DNSNames = []string{"localhost"}
			tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
		if err != nil {
			panic(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	caPool = x509.NewCertPool()
	caPool.AddCert(ca)
	return caPool, leaf(2, "ws.example", x509.ExtKeyUsageServerAuth),
		leaf(3, "mtls-client", x509.ExtKeyUsageClientAuth)
}

// exampleKey is a throwaway P-256 key for the certificate fixtures above.
func exampleKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

// ExampleWithDialer_mtls is the standard-library way to dial a wss:// endpoint
// with application-owned TLS policy: WithDialer replaces the transport, so
// the app builds the TLS connection itself — here with a custom root
// store that trusts a specific CA (RootCAs) and a client certificate the
// server verifies (mTLS) — and hands the library the ready connection,
// over which only the WebSocket handshake runs.
//
// The server runs the mTLS gate the same way the demo's /ws/mtls does:
// the TLS layer verifies any presented chain (VerifyClientCertIfGiven),
// ordinary middleware refuses requests that arrived without a verified
// certificate, and the handler reads the client identity off
// r.TLS.PeerCertificates.
func ExampleWithDialer_mtls() {
	caPool, serverCert, clientCert := mtlsExampleCerts()

	// The mTLS gate as ordinary middleware, in front of the upgrader.
	mtlsGate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client certificate required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	up := NewUpgrader()
	mux := http.NewServeMux()
	mux.Handle("/ws", mtlsGate(up.Handle(func(r *http.Request, c *Session) error {
		identity := r.TLS.PeerCertificates[0].Subject.CommonName
		_, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		fmt.Println("server:", identity, "sent", string(data))
		return c.WriteMessage(OpText, data) // echo; the handler returns after
	})))

	// VerifyClientCertIfGiven: the TLS layer verifies a presented chain
	// against caPool; the middleware above decides that one was required.
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	srv.StartTLS()
	defer srv.Close()

	// The app's transport: plain TCP, then TLS with the app's policy —
	// the custom root store and the client certificate — then the
	// handshake, then the ready connection to the library.
	c, err := Dial(context.Background(), "wss://"+srv.Listener.Addr().String()+"/ws",
		WithDialer(func(_ context.Context, u *url.URL) (net.Conn, error) {
			conn, err := net.Dial("tcp", u.Host)
			if err != nil {
				return nil, err
			}
			tconn := tls.Client(conn, &tls.Config{
				ServerName:   u.Hostname(),
				RootCAs:      caPool,
				Certificates: []tls.Certificate{clientCert},
			})
			handshakeErr := tconn.Handshake()
			if handshakeErr != nil {
				_ = conn.Close()

				return nil, handshakeErr
			}
			return tconn, nil
		}))
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	err = c.WriteMessage(OpText, []byte("hi"))
	if err != nil {
		panic(err)
	}
	op, data, err := c.ReadMessage() // the echo
	if err != nil || op != OpText {
		panic(err)
	}
	fmt.Println("client:", string(data))
	_, _, err = c.ReadMessage() // the server's 1000 close, as EOF
	if !errors.Is(err, io.EOF) {
		panic(err)
	}
	fmt.Println("client: closed normally")
	// Output:
	// server: mtls-client sent hi
	// client: hi
	// client: closed normally
}

// ExampleWithCheckOrigin shows the application-side protections the OWASP
// WebSocket Security Cheat Sheet assigns to the application, at the seams
// this package provides: an explicit origin allowlist (the CSWSH defense;
// browsers always send Origin, so the no-Origin branch decides only for
// programmatic clients), a per-endpoint message-size cap, and per-action
// authorization that ends the session with 1008.
func ExampleWithCheckOrigin() {
	up := NewUpgrader(
		WithCheckOrigin(func(r *http.Request) bool {
			if origin := r.Header.Get("Origin"); origin != "" {
				return origin == "https://app.example.com" // explicit allowlist
			}
			return r.Header.Get("Authorization") != "" // programmatic clients
		}),
		WithMaxMessageSize(64<<10), // the cheat sheet's guidance for chat traffic
	)

	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Session) error {
		_, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		if string(data) == "delete_user" { // no admin session on this connection
			return &CloseError{Code: StatusPolicyViolation, Reason: "forbidden"}
		}
		_ = c.WriteMessage(OpText, []byte("ok"))
		return nil
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. A cross-site browser presents a non-allowlisted Origin and no
	//    token: rejected with 403 before the protocol switch (CSWSH).
	_, err := Dial(context.Background(), wsURL(srv.URL)+"/ws")
	fmt.Println("no token:", err != nil)

	// 2. A programmatic client with a token gets in; the unauthorized
	//    action ends the session with 1008, not a silent drop.
	c, err := Dial(context.Background(), wsURL(srv.URL)+"/ws",
		WithHeader("Authorization", "Bearer t"))
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")
	err = c.WriteMessage(OpText, []byte("delete_user"))
	if err != nil {
		panic(err)
	}
	_, _, err = c.ReadMessage()
	code, reason, _ := CloseCode(err)
	fmt.Println(code, reason)
	// Output:
	// no token: true
	// 1008 forbidden
}

// ExampleDialRaw shows the raw face: the protocol as an event stream, with
// the application as the responder. The server answers the client's ping
// with Pong, reassembles the client's two-frame message, echoes it, and
// closes with 1001; the client sees the pong, the echoed text, and the
// peer's close as an OpClose event carrying the resolved code, followed by
// the terminal error.
func ExampleDialRaw() {
	up := NewUpgrader()

	mux := http.NewServeMux()
	mux.Handle("/ws", up.HandleRaw(func(_ *http.Request, c *RawConn) error {
		for {
			event, readErr := c.ReadEvent()
			if readErr != nil {
				return readErr
			}
			// This example reacts only to pings and text; any other event is ignored.
			switch event.Op {
			case OpPing:
				// The application is the responder: no auto-pong in raw mode.
				pingErr := c.Pong(event.Payload)
				if pingErr != nil {
					return pingErr
				}
			case OpText:
				writeErr := c.WriteFrame(OpText, event.Payload, false)
				if writeErr != nil {
					return writeErr
				}
				return c.Close(StatusGoingAway, "done")
			default:
			}
		}
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := DialRaw(context.Background(), wsURL(srv.URL)+"/ws")
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	pingErr := c.Ping([]byte("hi"))
	if pingErr != nil {
		panic(pingErr)
	}
	// One message, two frames: a start frame with more=true, then the
	// continuation that ends the message (RFC 6455 §5.4).
	startErr := c.WriteFrame(OpText, []byte("frag-"), true)
	if startErr != nil {
		panic(startErr)
	}
	contErr := c.WriteFrame(OpContinuation, []byte("ed"), false)
	if contErr != nil {
		panic(contErr)
	}
	for {
		event, readErr := c.ReadEvent()
		if readErr != nil {
			code, reason, ok := CloseCode(readErr)
			fmt.Println("terminal:", code, reason, ok)
			break
		}
		// This example prints pongs, text, and the close; any other event is
		// ignored.
		switch event.Op {
		case OpPong:
			fmt.Println("pong:", string(event.Payload))
		case OpText:
			fmt.Println("text:", string(event.Payload))
		case OpClose:
			fmt.Println("close event:", event.Code, event.Reason)
		default:
		}
	}
	// Output:
	// pong: hi
	// text: frag-ed
	// close event: 1001 done
	// terminal: 1001 done true
}

// ExampleCloseCode shows application-level close codes end to end: the
// handler returns a *CloseError, Handle closes the connection with its
// code, and the peer extracts the code with CloseCode.
func ExampleCloseCode() {
	// Default origin policy: the client below sends no Origin header.
	up := NewUpgrader()

	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Session) error {
		_, _, _ = c.ReadMessage() // consume the client's message
		return &CloseError{Code: StatusPolicyViolation, Reason: "token expired"}
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := Dial(context.Background(), wsURL(srv.URL)+"/ws")
	if err != nil {
		panic(err)
	}
	defer c.Close(StatusNormalClosure, "")

	err = c.WriteMessage(OpText, []byte("hi"))
	if err != nil {
		panic(err)
	}
	_, _, err = c.ReadMessage()
	code, reason, ok := CloseCode(err)
	fmt.Println(code, reason, ok)
	// Output:
	// 1008 token expired true
}

// ExampleSession_WriteText demonstrates the text-frame rule (RFC 6455 §5.6):
// an OpText payload that is not valid UTF-8 is refused before anything
// reaches the wire, the refusal does not close the connection, and a valid
// message immediately after is delivered. Applications that move raw byte
// sequences should use OpBinary — it passes through with no validation.
func ExampleSession_WriteText() {
	sr, cr := net.Pipe()
	server := newSession(newRawConn(sr, sr, false, 1<<20, 0, 0), nil)
	client := newSession(newRawConn(cr, cr, true, 1<<20, 0, 0), nil)
	// net.Pipe is bidirectional, so both ends need readers; without them
	// the teardown close frames would wait out the close-write deadline.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			_, _, err := server.ReadMessage()
			if err != nil {
				return
			}
		}
	}()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		for {
			_, _, err := client.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	err := client.WriteText("héllo wörld")
	fmt.Println(err)
	err = client.WriteMessage(OpText, []byte{0xff, 0xfe})
	fmt.Println(err)
	err = client.WriteText("delivered")
	fmt.Println(err)
	_ = client.Close(StatusNormalClosure, "")
	<-serverDone
	<-clientDone
	// Output:
	// <nil>
	// ws: text message is not valid UTF-8: 2 bytes
	// <nil>
}
