package ws

import "testing"

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
			host, _, isTLS, err := dialTarget(tc.raw)
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
