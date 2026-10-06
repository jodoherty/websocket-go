// Package h3e2e is an out-of-module integration test: it drives a real
// github.com/quic-go/quic-go HTTP/3 server with an extended CONNECT and
// proves a WebSocket is served over that QUIC stream end-to-end. It lives in
// its own module (not the root) so the root go.mod — and the multiver gate,
// which must still build on go1.25.0 — never pulls in quic-go.
//
// The h3 path uses ws.SessionOnStream, not ws.Upgrader.Upgrade: quic-go
// surfaces the negotiated protocol in the request's Proto (not the :protocol
// header) and its response writer does not implement
// http.ResponseController.EnableFullDuplex, so the handler runs the RFC 6455
// handshake itself and hands the open tunnel to SessionOnStream. Run with:
//
//	cd e2e/h3 && go test
package h3e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	http3 "github.com/quic-go/quic-go/http3"

	ws "github.com/jodoherty/websocket-go/ws"
)

func TestExtendedConnectH3RoundTrip(t *testing.T) {
	cert := selfSignedCert(t)
	// ConfigureTLSConfig clones the config and sets the ALPN to h3.
	serverTLS := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}})

	upgrader := ws.NewUpgrader(
		// The tunnel wrapper reports no address and no-op deadlines, so it
		// cannot enforce the deadline options; they are waived and liveness
		// rests on the transport's own idle timeout. With either option
		// nonzero SessionOnStream returns ws.ErrNoDeadlineSupport.
		ws.WithIdleTimeout(0), ws.WithWriteTimeout(0),
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// quic-go surfaces the :protocol pseudo-header in r.Proto.
		if r.Method != http.MethodConnect || r.Proto != "websocket" {
			http.Error(w, "not a websocket CONNECT", http.StatusNotImplemented)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		if key == "" {
			http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
			return
		}
		w.Header().Set("Sec-WebSocket-Accept", acceptKey(key))
		w.WriteHeader(http.StatusOK)

		session, sessionErr := upgrader.SessionOnStream(tunnel{read: r.Body, write: w}, "", "")
		if sessionErr != nil {
			http.Error(w, sessionErr.Error(), http.StatusNotImplemented)
			return
		}
		for {
			op, msg, err := session.ReadMessage()
			if err != nil {
				return
			}
			if err := session.WriteMessage(op, msg); err != nil {
				return
			}
		}
	})

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	quicLn, err := quic.Listen(udpConn, serverTLS, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
	srv := &http3.Server{Handler: mux}
	go func() { _ = srv.ServeListener(quicLn) }()
	t.Cleanup(func() {
		_ = quicLn.Close()
		_ = udpConn.Close()
	})

	clientTLS := &tls.Config{
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}
	tr := &http3.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(func() { _ = tr.Close() })

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	req, _ := http.NewRequest(http.MethodConnect, "https://127.0.0.1:"+itoa(port)+"/ws", pr)
	req.Proto = "websocket"
	req.Header.Set("Sec-WebSocket-Key", key)
	req.Header.Set("Sec-WebSocket-Version", "13")

	// The client writes one masked frame to the tunnel (client-to-server) and
	// closes the body; the server echoes it back on the response.
	go func() {
		_, _ = pw.Write(maskedTextFrame("hello"))
		_ = pw.Close()
	}()

	res, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Sec-WebSocket-Accept"); got != acceptKey(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, acceptKey(key))
	}

	op, payload, err := readFrame(res.Body)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if op != 0x1 || !bytes.Equal(payload, []byte("hello")) {
		t.Fatalf("echo = (op=%#x %q), want text hello", op, payload)
	}
}

// tunnel is the minimal io.ReadWriteCloser over a quic-go response: reads come
// from the request body and writes go to the response writer, which after the
// 200 is the extended-CONNECT tunnel.
type tunnel struct {
	read  io.Reader
	write io.Writer
}

func (t tunnel) Read(p []byte) (int, error)  { return t.read.Read(p) }
func (t tunnel) Write(p []byte) (int, error) { return t.write.Write(p) }
func (tunnel) Close() error                  { return nil }

// acceptKey computes the RFC 6455 §1.3 accept value: base64(sha1(key+GUID)).
func acceptKey(key string) string {
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	_, _ = h.Write([]byte(key))
	_, _ = h.Write([]byte(guid))

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// maskedTextFrame builds a masked client-to-server text frame with a fixed
// mask, for payloads of at most 125 bytes.
func maskedTextFrame(payload string) []byte {
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	b := []byte{0x81, 0x80 | byte(len(payload))}
	b = append(b, mask[:]...)
	for i, c := range []byte(payload) {
		b = append(b, c^mask[i%4])
	}

	return b
}

// readFrame reads one (unmasked) frame and returns its opcode and payload.
func readFrame(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	op := hdr[0] & 0x0f
	payload := make([]byte, int(hdr[1]&0x7f))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}

	return op, payload, nil
}

// itoa is a port-free integer-to-string for the test URL (avoids importing
// strconv for one call).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	return string(buf[i:])
}

// selfSignedCert makes a throwaway ECDSA server certificate good for
// 127.0.0.1, for the duration of the test.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
