package ws

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestWithDialerOption pins the option's plumbing: the dial function lands
// in the config, and the server side ignores it (an upgrader's transport is
// the hijacked connection, never a dialer).
func TestWithDialerOption(t *testing.T) {
	t.Parallel()
	// The recorded dial function is the one the option carried: invoking it
	// yields its sentinel error.
	dialErrSentinel := errors.New("marked")
	dial := func(context.Context, *url.URL) (net.Conn, error) {
		return nil, dialErrSentinel
	}
	cfg := &Config{}
	WithDialer(dial)(cfg)
	if cfg.dialer == nil {
		t.Fatal("WithDialer did not record the dial function")
	}
	_, dialErr := cfg.dialer(context.Background(), nil)
	if dialErr == nil || !errors.Is(dialErr, dialErrSentinel) {
		t.Fatal("WithDialer recorded the wrong dial function")
	}
	NewUpgrader(WithDialer(dial)) // the server side must ignore it

	// The option is symmetric in name only: applying it on the server
	// leaves the server options untouched.
	serverCfg := &Config{CheckOrigin: defaultCheckOrigin}
	WithDialer(dial)(serverCfg)
	if serverCfg.CheckOrigin == nil {
		t.Fatal("WithDialer disturbed the server options")
	}
}

// TestDialWithCustomDialer pins WithDialer end to end: the dialer receives
// the parsed URL, and its connection is used for the handshake as-is — no
// TLS is applied by the library, even for a wss:// URL, so the app owns the
// transport policy.
func TestDialWithCustomDialer(t *testing.T) {
	t.Parallel()
	up := NewUpgrader()
	mux := http.NewServeMux()
	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *Session) error {
		op, data, err := c.ReadMessage()
		if err != nil {
			return err
		}

		return c.WriteMessage(op, data)
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var gotURL *url.URL
	c, err := Dial(context.Background(), "wss://"+srv.Listener.Addr().String()+"/ws",
		WithDialer(func(_ context.Context, u *url.URL) (net.Conn, error) {
			gotURL = u

			return net.Dial("tcp", u.Host) // no TLS: the app owns the transport
		}))
	if err != nil {
		t.Fatalf("dial with custom dialer: %v", err)
	}
	defer c.Close(StatusNormalClosure, "")
	if gotURL == nil || gotURL.Scheme != "wss" || gotURL.Path != "/ws" {
		t.Fatalf("dialer saw %v, want the parsed wss URL with path /ws", gotURL)
	}
	writeErr := c.WriteText("hi")
	if writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	op, data, readErr := c.ReadMessage()
	if readErr != nil || op != OpText || string(data) != "hi" {
		t.Fatalf("round trip = (%d, %q, %v), want the echo", op, data, readErr)
	}
}

// TestDialerFailure pins the error path: a dialer failure fails the dial
// with the dialer's error.
func TestDialerFailure(t *testing.T) {
	t.Parallel()
	want := netError{msg: "proxy down"}
	_, err := Dial(context.Background(), "ws://example.com/ws",
		WithDialer(func(context.Context, *url.URL) (net.Conn, error) {
			return nil, want
		}))
	if err == nil || !errors.Is(err, want) {
		t.Fatalf("dial error = %v, want the dialer's error", err)
	}
}

type netError struct{ msg string }

func (e netError) Error() string { return e.msg }

// TestDialTarget pins the URL → dial-target resolution: a plain host gets
// the scheme's default port, an explicit port is preserved, and a
// bracketed IPv6 literal without a port gets the default port too — the
// literal carries colons, so port detection must go through url.URL.Port,
// not a colon search.
func TestDialTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw      string
		wantHost string
		wantTLS  bool
	}{
		{"ws://example.com/path?x=1", "example.com:80", false},
		{"wss://example.com/", "example.com:443", true},
		{"ws://example.com:8443/x", "example.com:8443", false},
		{"ws://127.0.0.1/ws", "127.0.0.1:80", false},
		{"ws://[::1]/ws", "[::1]:80", false},
		{"wss://[::1]/ws", "[::1]:443", true},
		{"ws://[2001:db8::1]:9000/ws", "[2001:db8::1]:9000", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			host, _, isTLS, _, err := dialTarget(tc.raw)
			if err != nil {
				t.Fatalf("dialTarget(%q) error = %v", tc.raw, err)
			}
			if host != tc.wantHost || isTLS != tc.wantTLS {
				t.Fatalf("dialTarget(%q) = (%q, %v), want (%q, %v)",
					tc.raw, host, isTLS, tc.wantHost, tc.wantTLS)
			}
		})
	}
}
