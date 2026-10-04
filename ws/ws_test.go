package ws_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ws "github.com/jodoherty/websocket-go/ws"
)

const goodToken = "good-token"

func echo(c *ws.Conn) error {
	for {
		op, data, err := c.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) { // clean close
				return nil
			}

			return err
		}
		err = c.WriteMessage(op, data)
		if err != nil {
			return err
		}
	}
}

func startServer(t *testing.T) *httptest.Server {
	t.Helper()
	up := ws.NewUpgrader(
		ws.WithCheckOrigin(func(*http.Request) bool { return true }), // tests dial without Origin
		ws.WithSubprotocols("vnc1", "binary"),
		ws.WithIdleTimeout(time.Hour), // keepalive is covered separately
	)

	mux := http.NewServeMux()
	mux.Handle("/echo", up.Handle(func(_ *http.Request, c *ws.Conn) error {
		return echo(c)
	}))
	mux.Handle("/bye", up.Handle(func(_ *http.Request, c *ws.Conn) error {
		_ = c.WriteMessage(ws.OpText, []byte("farewell"))
		_ = c.Close(ws.StatusGoingAway, "later")
		return nil
	}))
	mux.Handle("/data", up.Handle(func(_ *http.Request, c *ws.Conn) error {
		if c.HandshakeData() != "principal" {
			return errors.New("handshake data missing")
		}
		return echo(c)
	}))
	mux.Handle("/strict", ws.NewUpgrader().Handle(func(_ *http.Request, c *ws.Conn) error { // default origin policy
		return echo(c)
	}))
	mux.Handle("/auth", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok != goodToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, ws.WithHandshakeData("authed"))
		if err != nil {
			return
		}
		defer c.Close(ws.StatusNormalClosure, "")
		err = echo(c)
		if err != nil {
			t.Logf("auth echo ended: %v", err)
		}
	}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return httptest.NewServer(mux)
}

func mustDial(t *testing.T, url string, opts ...ws.Option) *ws.Conn {
	t.Helper()
	c, err := ws.Dial(context.Background(), url, opts...)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	return c
}

// TestAppPingPongRoundTrip pins the application-level ping/pong pair on
// both sides: a client Ping is answered by the server's automatic pong
// that the client's WithPongHandler (dial-side wiring) observes, and a
// server Ping's pong is observed by the upgrader's WithPongHandler
// (server-side wiring) in the server's pumping goroutine.
func TestAppPingPongRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("client observes the pong", func(t *testing.T) {
		t.Parallel()
		srv := startServer(t)
		defer srv.Close()
		pong := make(chan []byte, 1)
		c := mustDial(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/echo",
			ws.WithPongHandler(func(payload []byte) {
				pong <- append([]byte(nil), payload...)
			}))
		defer c.Close(ws.StatusNormalClosure, "")
		done := make(chan error, 1)
		go func() { _, _, err := c.ReadMessage(); done <- err }()

		err := c.Ping([]byte("rtt-probe"))
		if err != nil {
			t.Fatalf("Ping: %v", err)
		}
		select {
		case payload := <-pong:
			if string(payload) != "rtt-probe" {
				t.Fatalf("pong payload %q, want the ping's payload", payload)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pong handler never fired")
		}
		_ = c.Close(ws.StatusNormalClosure, "")
		err = <-done
		if !errors.Is(err, io.EOF) {
			t.Fatalf("pump after close: %v, want io.EOF", err)
		}
	})

	t.Run("server observes the pong", func(t *testing.T) {
		t.Parallel()
		// The session pings the client before its read loop starts; the
		// client's automatic pong is consumed by the pump, which invokes
		// the upgrader's handler inline.
		pong := make(chan []byte, 1)
		up := ws.NewUpgrader(
			ws.WithCheckOrigin(func(*http.Request) bool { return true }),
			ws.WithPongHandler(func(payload []byte) { pong <- append([]byte(nil), payload...) }),
		)
		srv := httptest.NewServer(up.Handle(func(_ *http.Request, c *ws.Conn) error {
			_ = c.Ping([]byte("srv-probe"))
			return echo(c)
		}))
		defer srv.Close()
		c := mustDial(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/")
		// The client's pump is what auto-pongs the server's probe.
		clientDone := make(chan struct{})
		go func() {
			defer close(clientDone)
			for {
				_, _, err := c.ReadMessage()
				if err != nil {
					return
				}
			}
		}()

		select {
		case payload := <-pong:
			if string(payload) != "srv-probe" {
				t.Fatalf("server pong payload %q, want the ping's payload", payload)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("server pong handler never fired")
		}
		_ = c.Close(ws.StatusNormalClosure, "")
		<-clientDone
	})
}

// TestAppPingValidation pins Ping's local rejections: an over-limit
// control payload is refused before the wire and leaves the connection
// open, the 125-byte limit is accepted, and a closed connection reports
// the close, never a silent success.
func TestAppPingValidation(t *testing.T) {
	t.Parallel()
	srv := startServer(t)
	defer srv.Close()
	c := mustDial(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/echo")

	err := c.Ping(make([]byte, 126))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("126-byte ping: %v, want a size refusal", err)
	}
	err = c.Ping(make([]byte, 125))
	if err != nil {
		t.Fatalf("125-byte ping: %v, want success", err)
	}
	// The connection is still open after the refusal: a normal write goes
	// through.
	err = c.WriteText("still here")
	if err != nil {
		t.Fatalf("write after a refused ping: %v", err)
	}
	_ = c.Close(ws.StatusNormalClosure, "")
	err = c.Ping(nil)
	if !errors.Is(err, ws.ErrClosed) {
		t.Fatalf("ping on a closed connection: %v, want ErrClosed", err)
	}
}

func TestEchoTextAndBinary(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/echo", ws.WithSubprotocols("binary"))
	defer c.Close(ws.StatusNormalClosure, "")
	got := c.Subprotocol()
	if got != "binary" {
		t.Fatalf("negotiated subprotocol = %q, want %q", got, "binary")
	}

	err := c.WriteMessage(ws.OpText, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	op, data, err := c.ReadMessage()
	if err != nil || op != ws.OpText || string(data) != "hello" {
		t.Fatalf("text echo = (%d, %q, %v), want (1, hello, nil)", op, data, err)
	}

	bin := []byte{0x00, 0x01, 0xfe, 0xff, 0x7f}
	err = c.WriteMessage(ws.OpBinary, bin)
	if err != nil {
		t.Fatal(err)
	}
	op, data, err = c.ReadMessage()
	if err != nil || op != ws.OpBinary || string(data) != string(bin) {
		t.Fatalf("binary echo = (%d, %q, %v)", op, data, err)
	}
}

func TestSubprotocolNotAdvertised(t *testing.T) {
	s := startServer(t) // advertises "vnc1" and "binary"
	defer s.Close()

	// The client offers only a subprotocol the server does not advertise:
	// the handshake succeeds and selects none (the server is lenient by
	// design — requiring a subprotocol is an application decision), and the
	// client's §1.9 check accepts the empty selection.
	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/echo", ws.WithSubprotocols("nope"))
	defer c.Close(ws.StatusNormalClosure, "")
	if got := c.Subprotocol(); got != "" {
		t.Fatalf("negotiated subprotocol = %q, want empty", got)
	}
}

func TestLargeMessage(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/echo")
	defer c.Close(ws.StatusNormalClosure, "")

	big := make([]byte, 1<<20) // 1 MiB
	for i := range big {
		big[i] = byte(i * 7)
	}
	err := c.WriteMessage(ws.OpBinary, big)
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := c.ReadMessage()
	if err != nil || len(data) != len(big) || string(data) != string(big) {
		t.Fatalf("large echo: len=%d err=%v", len(data), err)
	}
}

func TestServerInitiatedClose(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/bye")
	defer c.Close(ws.StatusNormalClosure, "")

	_, data, err := c.ReadMessage()
	if err != nil || string(data) != "farewell" {
		t.Fatalf("got (%q, %v), want (farewell, nil)", data, err)
	}
	_, _, err = c.ReadMessage()
	code, reason, ok := ws.CloseCode(err)
	if !ok || code != ws.StatusGoingAway || reason != "later" {
		t.Fatalf("close = (code=%d reason=%q ok=%v err=%v), want 1001/later", code, reason, ok, err)
	}
}

func TestCleanCloseIsEOF(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/echo")
	_ = c.Close(ws.StatusNormalClosure, "done")
	_, _, err := c.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("clean close should yield io.EOF, got %v", err)
	}
}

func TestHandshakeData(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	// /data requires the HandshakeData that only the /auth upgrade sets.
	// Dialing it directly leaves the data nil, so the handler's policy
	// failure reaches the peer as a 1011 close — not a misreported normal
	// closure.
	c := mustDial(t, "ws"+strings.TrimPrefix(s.URL, "http")+"/data")
	defer c.Close(ws.StatusNormalClosure, "")
	err := c.WriteMessage(ws.OpText, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.ReadMessage()
	code, reason, ok := ws.CloseCode(err)
	if !ok || code != ws.StatusUnexpectedCondition || reason != "handler failure" {
		t.Fatalf("close = (code=%d reason=%q ok=%v err=%v), want 1011/handler failure", code, reason, ok, err)
	}
}

// TestOriginEnforced pins the default origin policy: requests without an
// Origin header (programmatic clients) are allowed, and requests with an
// Origin are enforced against the request's own scheme and Host.
func TestOriginEnforced(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	// No Origin at all: programmatic clients are allowed by default.
	_, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http")+"/strict")
	if err != nil {
		t.Fatalf("dial without Origin failed, want allowed: %v", err)
	}
	// Wrong origin.
	_, err = ws.Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http")+"/strict",
		ws.WithHeader("Origin", "https://evil.example"))
	if err == nil {
		t.Fatal("dial with foreign Origin succeeded, want 403 rejection")
	}
	// Correct same-origin (httptest is plain http).
	_, err = ws.Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http")+"/strict",
		ws.WithHeader("Origin", s.URL))
	if err != nil {
		t.Fatalf("dial with matching Origin failed: %v", err)
	}
}

func TestAuthBearer(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	base := strings.TrimPrefix(s.URL, "http")
	// Plain HTTP without a token: 401 before any websocket business.
	resp, err := http.Get(s.URL + "/auth")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// Bad token: also 401.
	req, _ := http.NewRequest(http.MethodGet, s.URL+"/auth", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	// Good token upgrades and echoes.
	c, err := ws.Dial(context.Background(), "ws"+base+"/auth", ws.WithHeader("Authorization", "Bearer "+goodToken))
	if err != nil {
		t.Fatalf("dial with bearer: %v", err)
	}
	defer c.Close(ws.StatusNormalClosure, "")
	err = c.WriteMessage(ws.OpText, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = c.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRequiredHeaders(t *testing.T) {
	s := startServer(t)
	defer s.Close()

	// A plain GET must not upgrade.
	resp, err := http.Get(s.URL + "/echo")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("plain GET upgraded, want rejection")
	}
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 400 (missing upgrade headers)", resp.StatusCode)
	}
}

func TestKeepaliveDetectsDeadPeer(t *testing.T) {
	// A "server" that accepts a websocket, echoes nothing, and then goes
	// silent. With a short keepalive window the client probes with a ping
	// after one window, and its next ReadMessage must fail with a timeout
	// after the second window (~2x the window) rather than block forever.
	up := ws.NewUpgrader(
		ws.WithCheckOrigin(func(*http.Request) bool { return true }),
		ws.WithIdleTimeout(300*time.Millisecond),
	)
	mux := http.NewServeMux()
	mux.Handle("/quiet", up.Handle(func(_ *http.Request, _ *ws.Conn) error {
		time.Sleep(30 * time.Second) // never read, never write
		return nil
	}))
	s := httptest.NewServer(mux)
	defer s.Close()

	c, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(s.URL, "http")+"/quiet",
		ws.WithIdleTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ws.StatusAbnormalClosure, "")
	_ = c.WriteMessage(ws.OpText, []byte("start")) // one exchange resets the clock

	start := time.Now()
	_, _, err = c.ReadMessage()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("ReadMessage returned nil from a silent peer")
	}
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("err = %v, want a timeout net.Error", err)
	}
	if elapsed < 500*time.Millisecond || elapsed > 10*time.Second {
		t.Fatalf("silent peer detected after %v, want ~600ms (300ms probe + 300ms grace)", elapsed)
	}
}
