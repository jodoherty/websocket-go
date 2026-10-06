package ws

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// connectWriter stands in for the HTTP/2 full-duplex response on an extended
// CONNECT: it records the status and headers, flags EnableFullDuplex, and
// captures the bytes the server writes as frames.
type connectWriter struct {
	header     http.Header
	code       int
	fullDuplex bool
	closed     bool
	body       *bytes.Buffer
}

func (w *connectWriter) Header() http.Header         { return w.header }
func (w *connectWriter) WriteHeader(code int)        { w.code = code }
func (w *connectWriter) Write(p []byte) (int, error) { return w.body.Write(p) }
func (w *connectWriter) EnableFullDuplex() error     { w.fullDuplex = true; return nil }
func (w *connectWriter) Close() error                { w.closed = true; return nil }

// failDuplexWriter wraps a ResponseWriter whose EnableFullDuplex always fails.
type failDuplexWriter struct{ inner *connectWriter }

func (w failDuplexWriter) Header() http.Header         { return w.inner.Header() }
func (w failDuplexWriter) WriteHeader(code int)        { w.inner.WriteHeader(code) }
func (w failDuplexWriter) Write(p []byte) (int, error) { return w.inner.Write(p) }
func (w failDuplexWriter) EnableFullDuplex() error     { return errors.New("full-duplex unavailable") }
func (w failDuplexWriter) Close() error                { return w.inner.Close() }

// maskedTextFrame builds a masked client-to-server text frame with the given
// payload, using the fixed mask 01 02 03 04.
func maskedTextFrame(payload string) []byte {
	mask := [4]byte{0x01, 0x02, 0x03, 0x04}
	length := byte(len(payload)) //nolint:gosec // test frames are always well under 126 bytes
	out := []byte{0x81, 0x80 | length}
	out = append(out, mask[:]...)
	for i := range payload {
		out = append(out, payload[i]^mask[i%4])
	}

	return out
}

// readTextFrame reads one unmasked server-to-client text frame from r and
// returns its payload.
func readTextFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var hdr [2]byte
	_, err := io.ReadFull(r, hdr[:])
	if err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	if hdr[0] != 0x81 {
		t.Fatalf("expected a text frame, got 0x%02x", hdr[0])
	}
	payload := make([]byte, int(hdr[1]&0x7f))
	_, err = io.ReadFull(r, payload)
	if err != nil {
		t.Fatalf("read frame payload: %v", err)
	}

	return payload
}

// connectRequest builds an RFC 8441 / RFC 9220 extended-CONNECT WebSocket
// request, mirroring what the net/http h2 and h3 servers deliver to a handler.
func connectRequest(key string) *http.Request {
	request := httptest.NewRequest(http.MethodConnect, "ws://host/ws", new(bytes.Buffer))
	request.Proto = "HTTP/2.0"
	request.ProtoMajor = 2
	request.Header.Set(":protocol", "websocket")
	request.Header.Set("Sec-WebSocket-Key", key)
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.RemoteAddr = "203.0.113.7:54321"

	return request
}

func testKey() string { return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")) }

func newConnectWriter() *connectWriter {
	return &connectWriter{header: make(http.Header), body: new(bytes.Buffer)}
}

func runConnect(t *testing.T, request *http.Request, opts ...Option) (*Session, *connectWriter) {
	t.Helper()
	w := newConnectWriter()
	// The extended-CONNECT stream exposes no per-stream deadline, so the
	// default deadline options are waived here; the stream is trusted to be
	// idle-bounded by the transport.
	opts = append([]Option{WithIdleTimeout(0), WithWriteTimeout(0)}, opts...)
	session, err := NewUpgrader(opts...).Upgrade(w, request)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	return session, w
}

// upgradeStatus returns the HTTP status of a failed extended-CONNECT upgrade.
func upgradeStatus(t *testing.T, err error) int {
	t.Helper()
	var ue *UpgradeError
	if !errors.As(err, &ue) {
		t.Fatalf("error = %v, want *UpgradeError", err)
	}

	return ue.Status
}

func TestExtendedConnectUpgradesAndEchoes(t *testing.T) {
	key := testKey()
	body := new(bytes.Buffer)
	request := connectRequest(key)
	request.Header.Set("Sec-WebSocket-Protocol", "chat, rpc")
	request.Body = io.NopCloser(body)
	body.Write(maskedTextFrame("hello"))

	session, w := runConnect(t, request, WithSubprotocols("chat", "rpc"))

	if !w.fullDuplex {
		t.Fatal("EnableFullDuplex was not called")
	}
	if w.code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.code)
	}
	if got := w.header.Get("Sec-WebSocket-Accept"); got != acceptKey(key) {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, acceptKey(key))
	}
	if got := w.header.Get("Sec-WebSocket-Protocol"); got != "chat" {
		t.Fatalf("Sec-WebSocket-Protocol = %q, want chat", got)
	}
	if session.Subprotocol() != "chat" {
		t.Fatalf("session subprotocol = %q, want chat", session.Subprotocol())
	}

	// Client-to-server: the server session reads the client's frame from the
	// request body.
	op, msg, err := session.ReadMessage()
	if err != nil || op != OpText || string(msg) != "hello" {
		t.Fatalf("ReadMessage = %v %q %v, want text hello", op, msg, err)
	}

	// Server-to-client: the session writes to the response tunnel.
	writeErr := session.WriteText("world")
	if writeErr != nil {
		t.Fatalf("WriteText: %v", writeErr)
	}
	if got := readTextFrame(t, w.body); string(got) != "world" {
		t.Fatalf("tunnel frame = %q, want world", got)
	}
}

func TestExtendedConnectRejectsOtherProtocol(t *testing.T) {
	request := connectRequest(testKey())
	request.Header.Set(":protocol", "quic")
	_, err := NewUpgrader().Upgrade(newConnectWriter(), request)
	if status := upgradeStatus(t, err); status != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", status, http.StatusNotImplemented)
	}
}

func TestExtendedConnectRejectsMissingKey(t *testing.T) {
	request := connectRequest(testKey())
	request.Header.Del("Sec-WebSocket-Key")
	_, err := NewUpgrader().Upgrade(newConnectWriter(), request)
	if status := upgradeStatus(t, err); status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestExtendedConnectRejectsMalformedKey(t *testing.T) {
	request := connectRequest("!!!not-base64!!!")
	_, err := NewUpgrader().Upgrade(newConnectWriter(), request)
	if status := upgradeStatus(t, err); status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
	}
}

func TestExtendedConnectOriginPolicy(t *testing.T) {
	request := connectRequest(testKey())
	request.Header.Set("Origin", "https://evil.example")
	up := NewUpgrader()
	up.checkOrigin = func(*http.Request) bool { return false }
	_, err := up.Upgrade(newConnectWriter(), request)
	if status := upgradeStatus(t, err); status != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", status, http.StatusForbidden)
	}
}

func TestExtendedConnectRequiresFullDuplex(t *testing.T) {
	request := connectRequest(testKey())
	request.Body = io.NopCloser(new(bytes.Buffer))
	// Waive the deadline options so the failure under test is the
	// full-duplex one, not the deadline refusal.
	_, err := NewUpgrader(WithIdleTimeout(0), WithWriteTimeout(0)).Upgrade(failDuplexWriter{newConnectWriter()}, request)
	if err == nil {
		t.Fatal("expected Upgrade to fail when full-duplex is unsupported")
	}
	if status := upgradeStatus(t, err); status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", status, http.StatusInternalServerError)
	}
}

func TestExtendedConnectRejectsDeadlineOptions(t *testing.T) {
	request := connectRequest(testKey())
	request.Body = io.NopCloser(new(bytes.Buffer))
	// The stream cannot enforce the configured window; the upgrade is
	// refused before the tunnel opens, 501.
	up := NewUpgrader(WithIdleTimeout(time.Second))
	_, err := up.Upgrade(newConnectWriter(), request)
	if status := upgradeStatus(t, err); status != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", status, http.StatusNotImplemented)
	}
}

func TestExtendedConnectDeadlineWaiver(t *testing.T) {
	request := connectRequest(testKey())
	request.Body = io.NopCloser(new(bytes.Buffer))
	// With the options waived the same stream upgrades: liveness is the
	// transport's job, and the session reports the windows it actually
	// enforces.
	session, err := NewUpgrader(WithIdleTimeout(0), WithWriteTimeout(0)).Upgrade(newConnectWriter(), request)
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if got := session.EffectiveIdleTimeout(); got != 0 {
		t.Fatalf("EffectiveIdleTimeout = %v, want 0", got)
	}
	if got := session.EffectiveWriteTimeout(); got != 0 {
		t.Fatalf("EffectiveWriteTimeout = %v, want 0", got)
	}
}

func TestSessionOnStreamNetPipe(t *testing.T) {
	a, b := net.Pipe()
	session, err := NewUpgrader().SessionOnStream(a, "chat", "")
	if err != nil {
		t.Fatalf("SessionOnStream: %v", err)
	}

	// A server-side session reads masked client frames, so the peer must send
	// one.
	go func() {
		_, _ = b.Write(maskedTextFrame("hello"))
	}()

	op, msg, err := session.ReadMessage()
	if err != nil || op != OpText || string(msg) != "hello" {
		t.Fatalf("ReadMessage = %v %q %v, want text hello", op, msg, err)
	}

	reply := make(chan []byte, 1)
	go func() {
		reply <- readTextFrame(t, b)
	}()
	writeErr := session.WriteText("hi")
	if writeErr != nil {
		t.Fatalf("WriteText: %v", writeErr)
	}
	if got := <-reply; string(got) != "hi" {
		t.Fatalf("peer frame = %q, want hi", got)
	}

	// Closing the peer end ends the stream: the next read fails.
	_ = b.Close()
	_, _, readErr := session.ReadMessage()
	if readErr == nil {
		t.Fatal("expected the read to fail after the peer closed")
	}
}

// bareRWC is an io.ReadWriteCloser with no transport methods, to exercise the
// streamTransport wrap path in SessionOnStream.
type bareRWC struct {
	r io.Reader
	w io.Writer
}

func (b bareRWC) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b bareRWC) Write(p []byte) (int, error) { return b.w.Write(p) }
func (bareRWC) Close() error                  { return nil }

// deadlineOnlyRWC is a stream with deadline methods but no address methods,
// to exercise the deadlineStream pass-through path in SessionOnStream.
type deadlineOnlyRWC struct{ conn net.Conn }

func (d deadlineOnlyRWC) Read(p []byte) (int, error) {
	return d.conn.Read(p)
}

func (d deadlineOnlyRWC) Write(p []byte) (int, error) { return d.conn.Write(p) }
func (d deadlineOnlyRWC) Close() error                { return d.conn.Close() }
func (d deadlineOnlyRWC) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

func (d deadlineOnlyRWC) SetWriteDeadline(t time.Time) error {
	return d.conn.SetWriteDeadline(t)
}

func TestSessionOnStreamWrap(t *testing.T) {
	rwc := bareRWC{r: bytes.NewReader(maskedTextFrame("pong")), w: new(bytes.Buffer)}
	session, err := NewUpgrader(WithIdleTimeout(0), WithWriteTimeout(0)).SessionOnStream(rwc, "", "")
	if err != nil {
		t.Fatalf("SessionOnStream: %v", err)
	}

	op, msg, err := session.ReadMessage()
	if err != nil || op != OpText || string(msg) != "pong" {
		t.Fatalf("ReadMessage = %v %q %v, want text pong", op, msg, err)
	}
}

// TestSessionOnStreamRefusesDeadlineOptions pins the stream-side half of the
// deadline gate: a bare stream with no deadline methods must not be
// promised windows it cannot enforce.
func TestSessionOnStreamRefusesDeadlineOptions(t *testing.T) {
	rwc := bareRWC{r: bytes.NewReader(nil), w: new(bytes.Buffer)}

	t.Run("idle", func(t *testing.T) {
		_, err := NewUpgrader(WithIdleTimeout(time.Second)).SessionOnStream(rwc, "", "")
		if !errors.Is(err, ErrNoDeadlineSupport) {
			t.Fatalf("err = %v, want ErrNoDeadlineSupport", err)
		}
	})

	t.Run("write", func(t *testing.T) {
		_, err := NewUpgrader(WithWriteTimeout(time.Second)).SessionOnStream(rwc, "", "")
		if !errors.Is(err, ErrNoDeadlineSupport) {
			t.Fatalf("err = %v, want ErrNoDeadlineSupport", err)
		}
	})

	t.Run("waived", func(t *testing.T) {
		session, err := NewUpgrader(WithIdleTimeout(0), WithWriteTimeout(0)).SessionOnStream(rwc, "", "")
		if err != nil {
			t.Fatalf("SessionOnStream: %v", err)
		}
		if got := session.EffectiveIdleTimeout(); got != 0 {
			t.Fatalf("EffectiveIdleTimeout = %v, want 0", got)
		}
		if got := session.EffectiveWriteTimeout(); got != 0 {
			t.Fatalf("EffectiveWriteTimeout = %v, want 0", got)
		}
	})

	t.Run("capable-stream", func(t *testing.T) {
		// A stream that implements DeadlineStream keeps its deadlines in
		// force over a nonzero window.
		a, _ := net.Pipe()
		defer a.Close()
		_, err := NewUpgrader().SessionOnStream(a, "", "")
		if err != nil {
			t.Fatalf("SessionOnStream: %v", err)
		}
	})

	t.Run("deadline-stream-without-addresses", func(t *testing.T) {
		// A stream with deadlines but no address methods is adapted so its
		// deadlines pass through, and the window is enforced.
		a, _ := net.Pipe()
		defer a.Close()
		session, err := NewUpgrader(WithIdleTimeout(time.Second)).SessionOnStream(deadlineOnlyRWC{a}, "", "")
		if err != nil {
			t.Fatalf("SessionOnStream: %v", err)
		}
		if got := session.EffectiveIdleTimeout(); got != time.Second {
			t.Fatalf("EffectiveIdleTimeout = %v, want 1s", got)
		}
	})
}
