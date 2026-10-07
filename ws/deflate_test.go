package ws

// permessage-deflate (RFC 7692) tests: extension negotiation (server
// offer parsing, client response verification), the RSV1 state machine,
// compressed message round trips, decompression error branches, and the
// allocation budget of the compressed paths.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// deflateStream compresses data into a complete raw DEFLATE stream, the
// exact wire form this implementation sends (RFC 7692 §7.2.1).
func deflateStream(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	_, err = w.Write(data)
	if err != nil {
		t.Fatalf("flate write: %v", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("flate close: %v", err)
	}

	return buf.Bytes()
}

// deflateTestConn builds a raw Conn served from data with permessage-deflate
// pre-negotiated, so frame-level tests skip the handshake. It returns the
// pump-level connection: tests that read messages wrap it in newSession.
func deflateTestConn(data []byte, isClient bool) *RawConn {
	c := newTestRawConn(data, isClient)
	c.fc.deflate = true

	return c
}

// TestWriteCompressedMessageOverLimitIsRefused pins the write-side size
// guarantee under compression: an incompressible message exactly at
// maxMessageSize expands under deflate, so the compressed frame exceeds the
// limit even though the raw message fit. The write must be refused with
// errMessageTooBig (a peer with the same limit would 1002 such a frame) and
// the connection must stay open for a later, smaller write.
func TestWriteCompressedMessageOverLimitIsRefused(t *testing.T) {
	fc := &fakeConn{}
	c := newRawConn(fc, fc, true, 100, 0, 0)
	c.fc.deflate = true
	c.deflateNegotiated = true
	c.compressLevel = flate.DefaultCompression

	// 100 incompressible bytes: the raw message is exactly at the limit, but
	// compressing it yields ~106 bytes (see the compress() block overhead).
	// Byte-space arithmetic (no int->byte conversion) keeps the buffer
	// deterministic and lint-clean.
	data := make([]byte, 100)
	var v byte = 1
	for i := range data {
		v = v*131 + 17 // wraps mod 256: varied, non-repetitive bytes
		data[i] = v
	}
	err := c.WriteMessage(OpBinary, data)
	if !errors.Is(err, errMessageTooBig) {
		t.Fatalf("WriteMessage(compressed over limit) = %v, want errMessageTooBig", err)
	}
	if c.Closed() {
		t.Fatal("connection closed after refusing an oversized compressed write")
	}

	// A small write still succeeds: the refusal was per-write, not terminal.
	err = c.WriteMessage(OpBinary, []byte("ok"))
	if err != nil {
		t.Fatalf("write after refusal: %v", err)
	}
}

// TestWriteCompressedMessageAtLimitSucceeds is the mirror: a compressible
// message at the limit stays under it once compressed and is accepted.
func TestWriteCompressedMessageAtLimitSucceeds(t *testing.T) {
	fc := &fakeConn{}
	c := newRawConn(fc, fc, true, 100, 0, 0)
	c.fc.deflate = true
	c.deflateNegotiated = true
	c.compressLevel = flate.DefaultCompression

	err := c.WriteMessage(OpBinary, bytes.Repeat([]byte("a"), 100))
	if err != nil {
		t.Fatalf("compressible message at the limit: %v", err)
	}
}

// offerHeader builds an http.Header carrying the given
// Sec-WebSocket-Extension value ("" = no header at all).
func offerHeader(offer string) http.Header {
	if offer == "" {
		return http.Header{}
	}

	return http.Header{http.CanonicalHeaderKey("Sec-WebSocket-Extension"): []string{offer}}
}

// echo runs a read/echo loop until the connection ends. It mirrors the
// helper in the external ws_test package, which this internal test file
// cannot import.
func echo(c *Session) error {
	for {
		op, data, err := c.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) { // clean close
				return nil
			}

			return err
		}
		writeErr := c.WriteMessage(op, data)
		if writeErr != nil {
			return writeErr
		}
	}
}

// startCompressedEchoServer starts an echo server with the given upgrader
// options (compression on by default) and returns it.
func startCompressedEchoServer(t *testing.T, upOpts ...Option) *httptest.Server {
	t.Helper()
	allOpts := append([]Option{
		WithCheckOrigin(func(*http.Request) bool { return true }),
		WithIdleTimeout(time.Hour),
	}, upOpts...)
	up := NewUpgrader(allOpts...)
	mux := http.NewServeMux()
	mux.Handle("/echo", up.Handle(func(_ *http.Request, c *Session) error {
		return echo(c)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { srv.Close() })

	return srv
}

// serverExtensionReply performs a raw handshake against a default upgrader
// with the given Sec-WebSocket-Extension offer value ("" = no header) and
// returns the handshake response's status code and the value of its
// Sec-WebSocket-Extension header ("" when absent).
func serverExtensionReply(t *testing.T, offer string) (int, string) {
	t.Helper()
	up := NewUpgrader(WithCheckOrigin(func(*http.Request) bool { return true }))
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r)
		if err != nil {
			return // the 400 was already written by Upgrade
		}
		_, _, _ = conn.ReadMessage()
		_ = conn.Close(StatusNormalClosure, "")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := "GET /ws HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n"
	if offer != "" {
		req += "Sec-WebSocket-Extension: " + offer + "\r\n"
	}
	req += "\r\n"
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	defer resp.Body.Close()

	ext := resp.Header.Get("Sec-WebSocket-Extensions")

	return resp.StatusCode, ext
}

// dialWithServerExtension dials a server whose 101 response carries the
// given Sec-WebSocket-Extension value ("" = no header) and returns the
// Dial outcome. The server ignores the client's offer and answers with
// whatever ext says, so client-side response verification is exercised
// against arbitrary (even non-conforming) responses.
func dialWithServerExtension(t *testing.T, ext string, opts ...Option) (*Session, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)

			return
		}
		raw, _, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			http.Error(w, hijackErr.Error(), http.StatusInternalServerError)

			return
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey(r.Header.Get("Sec-WebSocket-Key")) + "\r\n"
		if ext != "" {
			resp += "Sec-WebSocket-Extension: " + ext + "\r\n"
		}
		resp += "\r\n"
		_, _ = raw.Write([]byte(resp))
		time.Sleep(time.Second) // hold the transport until the dial side is done
		_ = raw.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	allOpts := append([]Option{WithIdleTimeout(0)}, opts...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return Dial(ctx, "ws"+srv.URL[len("http"):]+"/ws", allOpts...)
}

// TestDeflateServerNegotiation pins the server's answer to a client
// extension offer. Accepted offers yield the fixed response header; a
// window-bit demand the compressor cannot honor is declined (the response
// carries no extension, the session runs uncompressed); a malformed offer
// is an error that Upgrade maps to a 400. The decision is exercised here
// directly; the wiring of the chosen header into the 101 response is
// integration-tested by TestDeflateServerExtensionHeader and
// TestDeflateRoundTrip.
func TestDeflateServerNegotiation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		offer   string
		wantExt string // "" = the response carries no extension
		wantErr bool   // the negotiation is rejected (a 400 in Upgrade)
	}{
		{offer: "", wantExt: ""},
		{offer: "permessage-deflate", wantExt: deflateResponseHeader},
		// Empty groups (extra commas) are dropped, not a parse error.
		{offer: "permessage-deflate,,", wantExt: deflateResponseHeader},
		{offer: ",,", wantExt: ""},
		{offer: "permessage-deflate; client_max_window_bits", wantExt: deflateResponseHeader},
		{offer: "permessage-deflate; client_max_window_bits=15", wantExt: deflateResponseHeader},
		{offer: "permessage-deflate; server_max_window_bits=15", wantExt: deflateResponseHeader},
		{offer: "permessage-deflate; server_no_context_takeover", wantExt: deflateResponseHeader},
		{offer: "permessage-deflate; client_no_context_takeover", wantExt: deflateResponseHeader},
		// The compressor always uses the full 32 KiB window, so a smaller
		// demand is declined: no extension in the response.
		{offer: "permessage-deflate; server_max_window_bits=10", wantExt: ""},
		// Malformed offers fail the negotiation.
		{offer: "permessage-deflate; server_max_window_bits", wantErr: true},
		{offer: "permessage-deflate; client_max_window_bits=7", wantErr: true},
		{offer: "permessage-deflate; client_max_window_bits=16", wantErr: true},
		{offer: "permessage-deflate; client_max_window_bits=010", wantErr: true},
		{offer: "permessage-deflate; client_max_window_bits=abc", wantErr: true},
		{offer: "permessage-deflate; client_max_window_bits=+10", wantErr: true},
		{offer: "permessage-deflate; client_no_context_takeover=1", wantErr: true},
		{offer: "permessage-deflate; bogus", wantErr: true},
		{offer: "permessage-deflate; bogus, permessage-deflate", wantErr: true},
		// Multiple permessage-deflate groups are alternative configurations
		// (RFC 7692 §5.1); the first honorable one wins — including two
		// identical alternatives, which simply select the first.
		{offer: "permessage-deflate, permessage-deflate", wantExt: deflateResponseHeader},
		{offer: "permessage-deflate; client_max_window_bits; client_max_window_bits", wantErr: true},
		{offer: "x-deflate", wantErr: true},
		{offer: "permessage-deflate;", wantErr: true},
	}
	for _, tc := range cases {
		t.Run("offer="+tc.offer, func(t *testing.T) {
			t.Parallel()
			ext, err := negotiateCompression(splitExtensionGroups(offerHeader(tc.offer)))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("offer %q: negotiated %q, want rejection", tc.offer, ext)
				}

				return
			}
			if err != nil {
				t.Fatalf("offer %q: %v", tc.offer, err)
			}
			if ext != tc.wantExt {
				t.Fatalf("offer %q: ext %q, want %q", tc.offer, ext, tc.wantExt)
			}
		})
	}
}

// TestDeflateServerExtensionHeader pins the wiring: a real handshake whose
// client offers permessage-deflate gets a 101 carrying the fixed extension
// header, and one that demands a smaller window gets a 101 with no
// extension (the declined, uncompressed path).
func TestDeflateServerExtensionHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		offer string
		ext   string // expected Sec-WebSocket-Extension in the 101
	}{
		{offer: "", ext: ""},
		{offer: "permessage-deflate", ext: deflateResponseHeader},
		{offer: "permessage-deflate; server_max_window_bits=10", ext: ""},
	}
	for _, tc := range cases {
		t.Run("offer="+tc.offer, func(t *testing.T) {
			t.Parallel()
			status, ext := serverExtensionReply(t, tc.offer)
			if status != http.StatusSwitchingProtocols || ext != tc.ext {
				t.Fatalf("offer %q: status=%d ext=%q, want 101 %q",
					tc.offer, status, ext, tc.ext)
			}
		})
	}
}

// TestDeflateClientVerification pins the client's validation of the 101
// response: the server may decline, may accept with its own constraints,
// but must not select an unoffered extension, must not select it twice, and
// must not cap the client window below what this compressor can honor.
func TestDeflateClientVerification(t *testing.T) {
	t.Parallel()
	snct := "permessage-deflate; server_no_context_takeover"
	cases := []struct {
		name     string
		ext      string
		wantErr  bool
		compress bool // expected Compressed() when the dial succeeds
	}{
		{name: "declined", ext: "", compress: false},
		// RFC 7692 §7.1.1.1: the offer carries server_no_context_takeover,
		// so an accepting response must too — absence means the server may
		// use context takeover, which this decompressor cannot follow.
		{name: "accepted bare", ext: "permessage-deflate", wantErr: true},
		{name: "client no context takeover only", ext: "permessage-deflate; client_no_context_takeover", wantErr: true},
		{name: "server no context takeover", ext: snct, compress: true},
		{name: "both no context takeover", ext: snct + "; client_no_context_takeover", compress: true},
		// §7.1.2.2: the offer carries no client_max_window_bits, so the
		// response must not either — valued or value-less.
		{name: "client window full", ext: snct + "; client_max_window_bits=15", wantErr: true},
		{name: "client window value-less", ext: snct + "; client_max_window_bits", wantErr: true},
		// §7.1.2.1: the server MAY add server_max_window_bits even
		// unoffered. The value configures the server's compressor window;
		// this client decodes with the full window unconditionally (RFC
		// 7692 §7), so any supported value (8–15) is accepted without
		// restricting this client.
		{name: "server window below full", ext: snct + "; server_max_window_bits=10", compress: true},
		{name: "server window min", ext: snct + "; server_max_window_bits=8", compress: true},
		{name: "server window full", ext: snct + "; server_max_window_bits=15", compress: true},
		// server_max_window_bits without the required
		// server_no_context_takeover still fails: the §7.1.1.1 check is
		// independent of the window value.
		{name: "server window alone", ext: "permessage-deflate; server_max_window_bits=10", wantErr: true},
		{name: "smaller client window", ext: snct + "; client_max_window_bits=10", wantErr: true},
		{name: "unknown extension", ext: "x-deflate", wantErr: true},
		// The guards that run before the §7.1 checks must still fail the
		// dial on their own: a second extension alongside a fully compliant
		// first one, not be ignored.
		{name: "duplicated extension", ext: snct + ", " + snct, wantErr: true},
		{name: "unknown parameter", ext: "permessage-deflate; bogus", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn, err := dialWithServerExtension(t, tc.ext)
			if tc.wantErr {
				if err == nil {
					_ = conn.Close(StatusNormalClosure, "")
					t.Fatalf("ext %q: dial succeeded, want failure", tc.ext)
				}

				return
			}
			if err != nil {
				t.Fatalf("ext %q: %v", tc.ext, err)
			}
			t.Cleanup(func() { _ = conn.Close(StatusNormalClosure, "") })
			if got := conn.Compressed(); got != tc.compress {
				t.Fatalf("ext %q: Compressed() = %v, want %v", tc.ext, got, tc.compress)
			}
		})
	}

	// An extension the client never offered fails the dial even when the
	// client disabled compression — with or without the §7.1 parameters,
	// so the unoffered check itself (not the no-takeover echo check) is
	// what is proven.
	t.Run("unoffered with compression disabled", func(t *testing.T) {
		t.Parallel()
		_, err := dialWithServerExtension(t, "permessage-deflate", WithCompression(false))
		if err == nil {
			t.Fatal("dial succeeded, want failure for an unoffered extension")
		}
		_, err = dialWithServerExtension(t, snct, WithCompression(false))
		if err == nil {
			t.Fatal("dial succeeded, want failure for an unoffered extension with parameters")
		}
	})
}

// TestDeflateFrameRSVRules pins the RSV state machine: RSV1 is the
// compressed marker on the first frame of a data message when negotiated;
// RSV2/RSV3 are always protocol errors; RSV1 on control frames and
// continuation frames is a protocol error even when negotiated.
func TestDeflateFrameRSVRules(t *testing.T) {
	t.Parallel()
	stream := deflateStream(t, []byte("Hello"))

	t.Run("rsv1 data frame accepted when negotiated", func(t *testing.T) {
		t.Parallel()
		frm := append([]byte{0xC1, byte(len(stream))}, stream...) //nolint:gosec // small test stream, 7-bit length
		c := newSession(deflateTestConn(frm, true), nil)
		op, data, err := c.ReadMessage()
		if err != nil || op != OpText || string(data) != "Hello" {
			t.Fatalf("compressed text = (%d, %q, %v), want text \"Hello\"", op, data, err)
		}
	})

	t.Run("rsv1 data frame rejected without negotiation", func(t *testing.T) {
		t.Parallel()
		frm := append([]byte{0xC1, byte(len(stream))}, stream...) //nolint:gosec // small test stream, 7-bit length
		c := newTestConn(frm, true)
		_, _, err := c.ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "RSV1 set without permessage-deflate") {
			t.Fatalf("RSV1 without negotiation: %v, want RSV1 protocol error", err)
		}
	})

	t.Run("rsv1 on ping rejected", func(t *testing.T) {
		t.Parallel()
		c := newSession(deflateTestConn([]byte{0xC9, 0x01, 'x'}, true), nil)
		_, _, err := c.ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "control frame") {
			t.Fatalf("RSV1 ping: %v, want control-frame protocol error", err)
		}
	})

	t.Run("rsv1 on continuation rejected", func(t *testing.T) {
		t.Parallel()
		c := newSession(deflateTestConn([]byte{0x01, 0x01, 'a', 0x40, 0x01, 'b'}, true), nil)
		_, _, err := c.ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "continuation frame") {
			t.Fatalf("RSV1 continuation: %v, want continuation-frame protocol error", err)
		}
	})

	t.Run("rsv2 rejected even when negotiated", func(t *testing.T) {
		t.Parallel()
		c := newSession(deflateTestConn([]byte{0xA1, 0x00}, true), nil)
		_, _, err := c.ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "reserved bits 2 or 3") {
			t.Fatalf("RSV2: %v, want reserved-bits protocol error", err)
		}
	})

	t.Run("rsv3 rejected even when negotiated", func(t *testing.T) {
		t.Parallel()
		c := newSession(deflateTestConn([]byte{0x91, 0x00}, true), nil)
		_, _, err := c.ReadMessage()
		if err == nil || !strings.Contains(err.Error(), "reserved bits 2 or 3") {
			t.Fatalf("RSV3: %v, want reserved-bits protocol error", err)
		}
	})
}

// TestDeflateFragmentedCompressedMessage pins the fragmentation rule: the
// whole message is one DEFLATE stream split across frames, RSV1 set on the
// first frame only.
func TestDeflateFragmentedCompressedMessage(t *testing.T) {
	t.Parallel()
	stream := deflateStream(t, []byte("Hello fragmented world"))
	mid := len(stream) / 2
	frm := []byte{0x41, byte(mid)} //nolint:gosec // mid = len/2 of a tiny test stream
	frm = append(frm, stream[:mid]...)
	frm = append(frm, 0x80, byte(len(stream)-mid)) //nolint:gosec // tiny test stream
	frm = append(frm, stream[mid:]...)
	c := newSession(deflateTestConn(frm, true), nil)
	op, data, err := c.ReadMessage()
	if err != nil || op != OpText || string(data) != "Hello fragmented world" {
		t.Fatalf("fragmented compressed = (%d, %q, %v), want the full text", op, data, err)
	}
}

// TestDeflateRoundTrip drives real dials: compressed echo in both
// directions, and the opt-out paths that leave the session uncompressed.
// checkEmptyEcho verifies that an empty message of each given opcode
// round-trips through the (compressed) connection: an empty compressed
// payload must decompress to zero bytes, and an empty message is legal.
func checkEmptyEcho(t *testing.T, conn *Session, ops ...Op) {
	t.Helper()
	for _, op := range ops {
		writeErr := conn.WriteMessage(op, []byte{})
		if writeErr != nil {
			t.Fatalf("write empty op=%d: %v", op, writeErr)
		}
		got, payload, err := conn.ReadMessage()
		if err != nil || got != op || len(payload) != 0 {
			t.Fatalf("empty op=%d echo: (%d, %d bytes, %v), want (%d, 0, nil)",
				op, got, len(payload), err, op)
		}
	}
}

func TestDeflateRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("compressed echo both directions", func(t *testing.T) {
		t.Parallel()
		srv := startCompressedEchoServer(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := Dial(ctx, "ws"+srv.URL[len("http"):]+"/echo", WithIdleTimeout(0))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close(StatusNormalClosure, "")
		if !conn.Compressed() {
			t.Fatal("Compressed() = false, want true for a default dial")
		}
		// 1 MiB of repetitive data compresses well; a binary incompressible
		// payload exercises the other end of the spectrum.
		big := make([]byte, 1<<20)
		for i := range big {
			big[i] = byte(i*31 + 7)
		}
		writeErr := conn.WriteMessage(OpBinary, big)
		if writeErr != nil {
			t.Fatalf("write: %v", writeErr)
		}
		op, data, err := conn.ReadMessage()
		if err != nil || op != OpBinary || !bytes.Equal(data, big) {
			t.Fatalf("binary echo = (%d, %d bytes, %v), want the same %d bytes",
				op, len(data), err, len(big))
		}
		textErr := conn.WriteMessage(OpText, []byte("hello compressed"))
		if textErr != nil {
			t.Fatalf("write text: %v", textErr)
		}
		op, data, err = conn.ReadMessage()
		if err != nil || op != OpText || string(data) != "hello compressed" {
			t.Fatalf("text echo = (%d, %q, %v)", op, data, err)
		}
		// Empty messages are legal and must round-trip compressed: a
		// compressed empty payload decompresses to zero bytes.
		checkEmptyEcho(t, conn, OpText, OpBinary)
	})

	t.Run("best speed level", func(t *testing.T) {
		t.Parallel()
		srv := startCompressedEchoServer(t, WithCompressionLevel(flate.BestSpeed))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := Dial(ctx, "ws"+srv.URL[len("http"):]+"/echo", WithIdleTimeout(0))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close(StatusNormalClosure, "")
		if !conn.Compressed() {
			t.Fatal("Compressed() = false, want true")
		}
		writeErr := conn.WriteMessage(OpText, []byte("level check"))
		if writeErr != nil {
			t.Fatalf("write: %v", writeErr)
		}
		_, data, err := conn.ReadMessage()
		if err != nil || string(data) != "level check" {
			t.Fatalf("echo = (%q, %v)", data, err)
		}
	})

	t.Run("server disabled", func(t *testing.T) {
		t.Parallel()
		srv := startCompressedEchoServer(t, WithCompression(false))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := Dial(ctx, "ws"+srv.URL[len("http"):]+"/echo", WithIdleTimeout(0))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close(StatusNormalClosure, "")
		if conn.Compressed() {
			t.Fatal("Compressed() = true, want false for a server with WithCompression(false)")
		}
		writeErr := conn.WriteMessage(OpText, []byte("plain"))
		if writeErr != nil {
			t.Fatalf("write: %v", writeErr)
		}
		_, data, err := conn.ReadMessage()
		if err != nil || string(data) != "plain" {
			t.Fatalf("echo = (%q, %v)", data, err)
		}
	})

	t.Run("client disabled", func(t *testing.T) {
		t.Parallel()
		srv := startCompressedEchoServer(t)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := Dial(ctx, "ws"+srv.URL[len("http"):]+"/echo",
			WithIdleTimeout(0), WithCompression(false))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close(StatusNormalClosure, "")
		if conn.Compressed() {
			t.Fatal("Compressed() = true, want false for a client with WithCompression(false)")
		}
		writeErr := conn.WriteMessage(OpText, []byte("plain from client"))
		if writeErr != nil {
			t.Fatalf("write: %v", writeErr)
		}
		_, data, err := conn.ReadMessage()
		if err != nil || string(data) != "plain from client" {
			t.Fatalf("echo = (%q, %v)", data, err)
		}
	})
}

// TestDeflateDecompressionErrors pins the decompression failure branches:
// a truncated or corrupt stream, and an expanded payload that exceeds the
// message size limit (enforced while decompressing, so a decompression bomb
// cannot grow unboundedly). A stream that decompresses to zero bytes is a
// legal empty message, so it is covered by the round-trip tests instead.
func TestDeflateDecompressionErrors(t *testing.T) {
	t.Parallel()

	t.Run("truncated stream", func(t *testing.T) {
		t.Parallel()
		// A payload with enough structure that the final block carries real
		// codes: cutting three bytes off the tail truncates the last
		// huffman block mid-code.
		payload := bytes.Repeat([]byte("truncation probe "), 64)
		stream := deflateStream(t, payload)
		c := deflateTestConn(nil, true)
		_, err := c.decompress(stream[:len(stream)-3])
		if err == nil || !errors.Is(err, errProtocol) {
			t.Fatalf("truncated stream: %v, want protocol error", err)
		}
	})

	t.Run("empty stream is a legal empty message", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.NoCompression)
		if err != nil {
			t.Fatal(err)
		}
		err = w.Close()
		if err != nil {
			t.Fatal(err)
		}
		c := deflateTestConn(nil, true)
		out, err := c.decompress(buf.Bytes())
		if err != nil {
			t.Fatalf("empty stream: %v, want a legal empty payload", err)
		}
		if len(out) != 0 {
			t.Fatalf("empty stream: %d bytes, want 0", len(out))
		}
	})

	t.Run("expanded payload exceeds limit", func(t *testing.T) {
		t.Parallel()
		payload := bytes.Repeat([]byte("a"), 100)
		c := deflateTestConn(nil, true)
		c.fc.maxMsg = 10
		_, err := c.decompress(deflateStream(t, payload))
		if err == nil || !errors.Is(err, errMessageTooBig) {
			t.Fatalf("expanded over limit: %v, want errMessageTooBig", err)
		}
	})

	t.Run("decompression bomb is bounded", func(t *testing.T) {
		t.Parallel()
		zeros := make([]byte, 100_000) // compresses to ~100 bytes
		c := deflateTestConn(nil, true)
		c.fc.maxMsg = 1 << 10
		_, err := c.decompress(deflateStream(t, zeros))
		if err == nil || !errors.Is(err, errMessageTooBig) {
			t.Fatalf("bomb: %v, want errMessageTooBig", err)
		}
	})

	t.Run("corrupt stream", func(t *testing.T) {
		t.Parallel()
		c := deflateTestConn(nil, true)
		_, err := c.decompress([]byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff})
		if err == nil || !errors.Is(err, errProtocol) {
			t.Fatalf("corrupt stream: %v, want protocol error", err)
		}
	})
}

// TestCompressedAllocationBudget pins the steady-state allocation cost of
// the compressed paths, mirroring the uncompressed budgets in
// memory_test.go: compress + writeFrame allocate nothing per message
// (the compressor and its buffer are per-connection scratch), and
// decompress allocates exactly one thing — the fresh payload slice the
// caller owns.
func TestCompressedAllocationBudget(t *testing.T) {
	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}

	t.Run("compress and write", func(t *testing.T) {
		c := newTestRawConn(nil, false) // server side: unmasked frames
		c.deflateNegotiated = true
		c.compressLevel = flate.DefaultCompression
		for range 3 { // warm up the compressor and grow the scratch
			err := c.compress(payload)
			if err != nil {
				t.Fatal(err)
			}
			err = c.fc.writeFrame(OpBinary, c.compressBuf.Bytes(), true, true)
			if err != nil {
				t.Fatal(err)
			}
		}
		if n := testing.AllocsPerRun(100, func() {
			err := c.compress(payload)
			if err != nil {
				t.Fatal(err)
			}
			err = c.fc.writeFrame(OpBinary, c.compressBuf.Bytes(), true, true)
			if err != nil {
				t.Fatal(err)
			}
		}); n != 0 {
			t.Fatalf("compress+writeFrame: %v allocs/op, want 0", n)
		}
	})

	t.Run("decompress", func(t *testing.T) {
		if raceDetectorOn() {
			t.Skip("flate alloc count is inflated under the race detector; pinned on the non-race run")
		}
		c := deflateTestConn(nil, true)
		compressed := deflateStream(t, payload)
		for range 3 { // warm up the decompressor and grow the scratch
			out, err := c.decompress(compressed)
			if err != nil || !bytes.Equal(out, payload) {
				t.Fatalf("warm-up decompress: %v", err)
			}
		}
		if n := testing.AllocsPerRun(100, func() {
			out, err := c.decompress(compressed)
			if err != nil || !bytes.Equal(out, payload) {
				t.Fatal(err)
			}
		}); n != 1 {
			t.Fatalf("decompress: %v allocs/op, want 1 (the payload)", n)
		}
	})
}

// TestCompressTailCheck pins the compressor's tail validation: the flushed
// stream must end with the RFC 7692 §7.2.1 empty-block octets, and an
// undersized or mismatched stream — a stdlib encoder regression — is
// reported as errCompressTail, never an index panic. The undersized inputs
// are the regression: the pre-guard code sliced b[len(b)-4:] without a
// length check, which panics for len(b) < 4.
func TestCompressTailCheck(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("compressTailCheck panicked: %v", r)
		}
	}()

	// The wire form compress() actually emits, restored to the full flushed
	// stream: the body plus the trailing four octets it trims off.
	c := newTestRawConn(nil, false)
	err := c.compress([]byte("hello, world"))
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	full := append(append([]byte{}, c.compressBuf.Bytes()...), deflateTailBytes[:truncateOctets]...)

	cases := []struct {
		name    string
		in      []byte
		wantErr bool
		wantOut []byte
	}{
		{
			name:    "real flushed stream trims the RFC tail",
			in:      full,
			wantOut: c.compressBuf.Bytes(),
		},
		{
			name:    "exactly the tail yields an empty payload",
			in:      append([]byte(nil), deflateTailBytes[:truncateOctets]...),
			wantOut: nil,
		},
		{name: "empty stream is too short", in: nil, wantErr: true},
		{name: "one byte is too short", in: []byte{0x00}, wantErr: true},
		{
			name:    "three bytes are too short",
			in:      deflateTailBytes[:truncateOctets-1],
			wantErr: true,
		},
		{
			name:    "wrong tail octets are rejected",
			in:      append([]byte{0x00, 0x01}, 0x00, 0x00, 0xfe, 0xff),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := compressTailCheck(tc.in)
			if tc.wantErr {
				if !errors.Is(err, errCompressTail) {
					t.Fatalf("compressTailCheck = (%q, %v), want errCompressTail", out, err)
				}

				return
			}
			if err != nil {
				t.Fatalf("compressTailCheck: %v", err)
			}
			if !bytes.Equal(out, tc.wantOut) {
				t.Fatalf("compressTailCheck = % x, want % x", out, tc.wantOut)
			}
		})
	}
}

// TestDecompressedMessageAtLimitSucceeds pins the decompression bound's
// inclusivity: a compressed message whose expanded form is exactly
// MaxMessageSize is legal and must be delivered; only a larger expansion
// fails the connection (TestDeflateDecompressionErrors covers that side).
// A boundary that rejected exactly-at-limit output would drop legal
// messages.
func TestDecompressedMessageAtLimitSucceeds(t *testing.T) {
	t.Parallel()
	const limit = 100
	srv := startCompressedEchoServer(t, WithMaxMessageSize(limit))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, "ws"+srv.URL[len("http"):]+"/echo",
		WithMaxMessageSize(limit), WithIdleTimeout(0))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close(StatusNormalClosure, "")
	if !conn.Compressed() {
		t.Fatal("Compressed() = false, want true for a default dial")
	}
	// Exactly limit bytes of one rune compress to a frame far under the
	// limit, and inflate back to exactly the limit on both sides.
	payload := bytes.Repeat([]byte("a"), limit)
	writeErr := conn.WriteMessage(OpBinary, payload)
	if writeErr != nil {
		t.Fatalf("write at the decompressed limit: %v", writeErr)
	}
	op, data, err := conn.ReadMessage()
	if err != nil || op != OpBinary || !bytes.Equal(data, payload) {
		t.Fatalf("read at the decompressed limit = (%d, %d bytes, %v), want %d bytes, nil",
			op, len(data), err, limit)
	}
}

// TestUnquoteExtensionValue pins the RFC 6455 §9.1 quoted-string
// handling: a quoted parameter value is unescaped (\" and \\), tab is
// the only control character permitted, and any other control or high
// byte — bare or after a backslash — is a malformed extension.
func TestUnquoteExtensionValue(t *testing.T) {
	t.Parallel()
	check := func(value, want string) {
		got, err := unquoteExtensionValue(value)
		if err != nil {
			t.Fatalf("unquoteExtensionValue(%q) = (%q, %v), want %q", value, got, err, want)
		}
		if got != want {
			t.Fatalf("unquoteExtensionValue(%q) = %q, want %q", value, got, want)
		}
	}
	checkErr := func(value, sub string) {
		_, unquoteErr := unquoteExtensionValue(value)
		if unquoteErr == nil || !strings.Contains(unquoteErr.Error(), sub) {
			t.Fatalf("unquoteExtensionValue(%q) = %v, want an error containing %q", value, unquoteErr, sub)
		}
	}
	// Structural cases: valid values and the rejections the MC/DC matrix
	// does not trace (truncated escapes, unterminated strings, trailing
	// characters).
	plain := []struct {
		subtest string
		value   string
		want    string
	}{
		{"quoted-digits", `"15"`, "15"},
		{"escape-printable", `"a\Zb"`, "aZb"},
	}
	for _, pc := range plain {
		t.Run(pc.subtest, func(t *testing.T) {
			t.Parallel()
			check(pc.value, pc.want)
		})
	}
	// The not-quoted / empty short-circuit (value == "" || value[0] != '"'): each
	// is passed through untouched.
	t.Run("empty-string", func(t *testing.T) {
		t.Parallel()
		// (value==""=T, value[0]!="'"=F) vs (F, F): an empty value short-circuits.
		check("", "")
	})
	t.Run("plain-token", func(t *testing.T) {
		t.Parallel()
		// (value[0]!="'"=T) vs (F): an unquoted token is returned as-is; a
		// quoted value is unescaped (the quote condition flips the guard).
		check("15", "15")
		check(`"15"`, "15")
	})
	structural := []struct {
		subtest string
		value   string
		want    string
	}{
		{"dangling-escape", `"a\`, "dangling escape"},
		{"unterminated", `"ab`, "unterminated"},
		{"trailing", `"a"b`, "trailing characters"},
	}
	for _, pc := range structural {
		t.Run(pc.subtest, func(t *testing.T) {
			t.Parallel()
			checkErr(pc.value, pc.want)
		})
	}
	// MC/DC matrix: each subtest asserts the observable outcome of one
	// condition flip in the escape / character checks.
	t.Run("escape-quote", func(t *testing.T) {
		t.Parallel()
		// A \" escape is legal; a control-char escape is rejected. The quote
		// condition (the escaped byte is a DQUOTE) flips the invalid-escape
		// check off then on.
		check(`"a\"b"`, "a\"b")
		checkErr("\"a\\\x01\"", "invalid escape")
	})
	t.Run("escape-backslash", func(t *testing.T) {
		t.Parallel()
		// (next!=\\=F, ...) vs (T, ...): a \\\\ escape is legal, a
		// control-char escape is rejected — the backslash condition flips
		// the invalid-escape check.
		check(`"a\\b"`, "a\\b")
		checkErr("\"a\\\x01\"", "invalid escape")
	})
	t.Run("escape-control", func(t *testing.T) {
		t.Parallel()
		// (next<0x20=T) vs (F): a control char after a backslash is
		// rejected, a printable char after a backslash is legal — the low
		// condition flips the check.
		checkErr("\"a\\\x01b\"", "invalid escape")
		check(`"a\Zb"`, "aZb")
	})
	t.Run("escape-high", func(t *testing.T) {
		t.Parallel()
		// (next>0x7e=T) vs (F): a high char after a backslash is rejected,
		// a printable char after a backslash is legal — the high condition
		// flips the check.
		checkErr("\"a\\\x7fb\"", "invalid escape")
		check(`"a\Zb"`, "aZb")
	})
	t.Run("tab-char", func(t *testing.T) {
		t.Parallel()
		// (ch!=0x09=F, ch<0x20=T, ch>0x7e=F) vs (T, T, F): tab is the one
		// permitted control char, a NUL is rejected — the tab condition
		// flips the invalid-character check.
		check("\"a\tb\"", "a\tb")
		checkErr("\"a\x00\"", "invalid character")
	})
	t.Run("control-char", func(t *testing.T) {
		t.Parallel()
		// (ch<0x20=T) vs (F): a NUL is rejected, a printable char is legal
		// — the low condition flips the check.
		checkErr("\"a\x00\"", "invalid character")
		check("\"aZ\"", "aZ")
	})
	t.Run("high-char", func(t *testing.T) {
		t.Parallel()
		// (ch>0x7e=T) vs (F): a high char is rejected, a printable char is
		// legal — the high condition flips the check.
		checkErr("\"a\x7f\"", "invalid character")
		check("\"aZ\"", "aZ")
	})
}
