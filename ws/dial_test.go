package ws

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// TestWithTLSClientChainOption pins the mTLS chain option's plumbing: the
// leaf and its intermediates land in the tls.Config as one chain, leaf
// first, and composing the option after WithTLS adds the chain to the
// existing configuration instead of replacing it.
func TestWithTLSClientChainOption(t *testing.T) {
	t.Parallel()
	// Raw-only certificates suffice: this test checks what the option
	// places in the tls.Config, not what x509 verifies.
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	intermediates := []*x509.Certificate{
		{Raw: []byte("intermediate-1")},
		{Raw: []byte("intermediate-2")},
	}
	key := "private-key"

	cfg := &Config{}
	WithTLSClientChain(leaf, intermediates, key)(cfg)
	if len(cfg.tlsConfigClient.Certificates) != 1 {
		t.Fatalf("chain option: %d certificates, want exactly one", len(cfg.tlsConfigClient.Certificates))
	}
	cert := cfg.tlsConfigClient.Certificates[0]
	// The entry is the whole chain, leaf first.
	if len(cert.Certificate) != 3 ||
		!bytes.Equal(cert.Certificate[0], leaf.Raw) ||
		!bytes.Equal(cert.Certificate[1], intermediates[0].Raw) ||
		!bytes.Equal(cert.Certificate[2], intermediates[1].Raw) {
		t.Fatalf("certificate chain % x, want leaf then the intermediates in order", cert.Certificate)
	}
	if cert.PrivateKey != key {
		t.Fatal("private key not carried into the certificate entry")
	}

	// Composed after WithTLS, the chain is installed on the existing
	// configuration without disturbing its other settings.
	cfg = &Config{}
	base := &tls.Config{ServerName: "example.com"}
	WithTLS(base)(cfg)
	WithTLSClientChain(leaf, nil, key)(cfg)
	if cfg.tlsConfigClient != base {
		t.Fatal("chain option replaced the WithTLS configuration")
	}
	if base.ServerName != "example.com" || len(base.Certificates) != 1 {
		t.Fatalf("WithTLS settings or chain lost: serverName=%q certs=%d", base.ServerName, len(base.Certificates))
	}
}

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
