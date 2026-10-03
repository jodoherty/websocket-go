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
//
// Note the // Output: block sits inside each function body: since Go 1.27
// the golden-output comment is only recognized there; in the old
// after-the-closing-brace position it is silently ignored and the example
// is never run at all.

import (
	"context"
	"errors"
	"fmt"
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
				return err
			}
			if op == 0 { // normal close (1000)
				return nil
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
		if err != nil || op == 0 {
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
		op, data, err := c.ReadMessage()
		if err != nil || op == 0 {
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
	if err != nil {
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
