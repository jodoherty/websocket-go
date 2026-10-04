package ws

// This file holds the package's Example functions. They are rendered by
// `go doc` and pkg.go.dev, and — unlike plain doc-comment code blocks,
// which are never compiled or run — they are real tests: each one is built
// and executed on every `go test` (and under -race), with its output pinned
// by a golden // Output: line. The documentation is therefore executable,
// and each example doubles as an integration test of one entry point:
//
//   - Example:         ws.Handle + Dial — an echo round trip
//   - ExampleUpgrader:  auth middleware + WithHandshakeData + Upgrade
//   - ExampleDial:      programmatic client, bearer token via WithHeader
//   - ExampleCloseCode: application close codes, end to end
//   - ExampleWithCheckOrigin: origin allowlist, per-endpoint size cap, and
//                             per-action authorization (1008)
//   - ExampleConn_WriteText: the text-frame UTF-8 rule — a refused write
//                             leaves the connection open
//
// Note the // Output: block sits inside each function body: since Go 1.27
// the golden-output comment is only recognized there; in the old
// after-the-closing-brace position it is silently ignored and the example
// is never run at all.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Conn) error {
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
// authentication and authorization are ordinary middleware that runs before
// the upgrade, and its result rides on the connection via WithHandshakeData
// instead of globals. Browsers cannot set headers on the upgrade, so the
// token comes in a query parameter here.
func ExampleUpgrader() {
	up := NewUpgrader(
		WithCheckOrigin(func(*http.Request) bool { return true }),
		WithSubprotocols("chat.v1"),
	)

	mux := http.NewServeMux()
	mux.Handle("/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, WithHandshakeData(token))
		if err != nil {
			return // an HTTP error response was already written
		}
		defer c.Close(StatusNormalClosure, "")

		op, data, err := c.ReadMessage()
		if err != nil {
			return
		}
		fmt.Println(c.Subprotocol(), c.HandshakeData(), "says", string(data))
		_ = c.WriteMessage(op, data)
	}))
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
// token. Unlike browsers, programmatic clients can set headers on the
// upgrade request; the server checks the token in a WithPreHandshake hook,
// before the protocol switch.
func ExampleDial() {
	up := NewUpgrader(
		WithCheckOrigin(func(*http.Request) bool { return true }),
		WithPreHandshake(func(r *http.Request) error {
			if r.Header.Get("Authorization") != "Bearer demo-secret" {
				return errors.New("unauthorized")
			}
			return nil
		}),
	)

	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Conn) error {
		_, data, err := c.ReadMessage()
		if err != nil {
			return err
		}
		fmt.Println("server:", string(data))
		return nil // the handler returns: Handle closes with 1000
	}))
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
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Conn) error {
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

// ExampleCloseCode shows application-level close codes end to end: the
// handler returns a *CloseError, Handle closes the connection with its
// code, and the peer extracts the code with CloseCode.
func ExampleCloseCode() {
	up := NewUpgrader(WithCheckOrigin(func(*http.Request) bool { return true }))

	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Conn) error {
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

// ExampleConn_WriteText demonstrates the text-frame rule (RFC 6455 §5.6):
// an OpText payload that is not valid UTF-8 is refused before anything
// reaches the wire, the refusal does not close the connection, and a valid
// message immediately after is delivered. Applications that move raw byte
// sequences should use OpBinary — it passes through with no validation.
func ExampleConn_WriteText() {
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
