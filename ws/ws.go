// Package ws is a WebSocket (RFC 6455) implementation for Go that uses only
// the standard library.
//
// # Design
//
// A WebSocket session starts as an ordinary HTTP request, so this package is
// built to compose with net/http rather than replace it:
//
//  1. The entry point is an [http.Handler]. [Upgrader.Upgrade] converts the
//     request to a websocket connection, and [Handle] converts a message
//     handler into an [http.Handler] that drops straight into a
//     [http.ServeMux].
//
//  2. Authentication and authorization are ordinary middleware. Bearer
//     tokens, sessions, and anything else run before the upgrade, in plain
//     http.Handler code. Client certificates presented via mTLS are available
//     through [ClientCert] (which reads r.TLS.PeerCertificates).
//
//  3. There are no callbacks and no pump goroutine. The goroutine that calls
//     [Conn.ReadMessage] is the connection's goroutine. Your handler does its
//     setup, upgrades, runs its read loop, and returns when the connection
//     dies — cleanup is a plain deferred call.
//
//     c, err := up.Upgrade(w, r)
//     if err != nil {
//         return // an appropriate 4xx/5xx response was already written
//     }
//     defer c.Close(ws.StatusNormalClosure, "")
//
//     for {
//         op, data, err := c.ReadMessage()
//         if err != nil {
//             // abnormal end: transport error, protocol violation, or an
//             // application close code. See CloseCode for details.
//             break
//         }
//         if op == 0 {
//             // normal close (1000): ReadMessage returns (0, nil, nil)
//             break
//         }
//         // op is OpText or OpBinary
//         _ = c.WriteMessage(op, data)
//     }
//
//  4. Close detection covers all four classes of death, funneled into the
//     single ReadMessage return: a close frame from the peer, a transport
//     error, a keepalive timeout (a silent peer is detected after
//     Upgrader.idleTimeout via a ping sent inline in the read path — no
//     background goroutines), and a local [Conn.Close] call.
//
// # Concurrency
//
//  1. [Conn.WriteMessage] and [Conn.Close] are safe to call from any
//     goroutine.
//  2. [Conn.ReadMessage] is not: read state is owned by the goroutine that
//     pumps the connection. Never call ReadMessage from two goroutines.
//  3. Between sequential ReadMessage calls in the same goroutine there are no
//     visibility concerns: handler-local state modified in one iteration is
//     plainly visible in the next.
package ws

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 mandates SHA-1 in the handshake
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Close status codes (RFC 6455 §7.4).
const (
	StatusNormalClosure       = 1000
	StatusGoingAway           = 1001
	StatusProtocolError       = 1002
	StatusUnsupportedData     = 1003
	StatusNoStatusReceived    = 1005 // never transmitted on the wire
	StatusAbnormalClosure     = 1006
	StatusInvalidDataType     = 1007
	StatusPolicyViolation     = 1008
	StatusMessageTooBig       = 1009
	StatusUnexpectedCondition = 1011
	StatusServiceRestart      = 1012
	StatusTryAgainLater       = 1013
)

// CloseError is returned by [Conn.ReadMessage] when the connection is closed
// with a status code other than a normal closure (1000, or a close frame
// with no status). A normal closure returns (0, nil, nil) from
// ReadMessage instead; expected notices such as 1001 "going away" arrive
// here so the application can react to them.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("ws: closed with code %d %q", e.Code, e.Reason)
}

// CloseCode extracts the close code and reason from an error returned by
// [Conn.ReadMessage] or stored on a connection. ok is false if the error
// does not carry a close code.
func CloseCode(err error) (code int, reason string, ok bool) {
	var ce *CloseError
	if errors.As(err, &ce) {
		return ce.Code, ce.Reason, true
	}
	return 0, "", false
}

// closeErrFor maps a close code to the terminal error recorded on the
// connection: a normal closure (1000, or an absent status) yields nil,
// everything else yields a *CloseError so callers can see the code and
// reason (e.g. 1001 "going away").
func closeErrFor(code int, reason string) error {
	switch code {
	case StatusNormalClosure, StatusNoStatusReceived:
		return nil
	default:
		return &CloseError{Code: code, Reason: reason}
	}
}

// ClientCert returns the client's first verified certificate from an
// mTLS-terminated request, or nil if no client certificate was presented.
// Chain verification has already been performed by the TLS layer; this is a
// convenience for reading identity out of the handshake.
func ClientCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil {
		return nil
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// Frame opcodes (RFC 6455 §5.2).
const (
	OpContinuation = 0
	OpText         = 1
	OpBinary       = 2
	OpClose        = 8
	OpPing         = 9
	OpPong         = 10
)

// errProtocol marks a protocol violation that terminates the connection.
var errProtocol = errors.New("ws: protocol violation")

type frame struct {
	fin     bool
	opcode  int
	payload []byte
}

// frameCodec is the byte-level half of a [Conn]: it reads and writes RFC
// 6455 frames on a buffered stream pair. Masking enforcement depends on
// which side we are on; everything else is independent of connection state,
// so it lives in its own struct — frame encoding and decoding can be
// benchmarked, fuzzed, and tested with plain buffers, no live connection.
type frameCodec struct {
	br       *bufio.Reader
	bw       *bufio.Writer
	isClient bool
	maxMsg   int64
}

func (f frame) isControl() bool { return f.opcode >= 8 }

// readFrame reads one frame from the connection. A client must mask its
// frames and a server must not, so the peer's frames are masked exactly
// when we are the server.
func (fc *frameCodec) readFrame() (frame, error) {
	var b [2]byte
	if _, err := io.ReadFull(fc.br, b[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: b[0]&0x80 != 0, opcode: int(b[0] & 0x0f)}
	if b[0]&0x70 != 0 {
		return frame{}, fmt.Errorf("%w: reserved bits set", errProtocol)
	}
	masked := b[1]&0x80 != 0
	if masked == fc.isClient {
		return frame{}, fmt.Errorf("%w: frame masking violation", errProtocol)
	}
	var n int64
	switch l := b[1] & 0x7f; l {
	case 126:
		var x [2]byte
		if _, err := io.ReadFull(fc.br, x[:]); err != nil {
			return frame{}, err
		}
		n = int64(binary.BigEndian.Uint16(x[:]))
	case 127:
		var x [8]byte
		if _, err := io.ReadFull(fc.br, x[:]); err != nil {
			return frame{}, err
		}
		if x[0] != 0 {
			return frame{}, fmt.Errorf("%w: frame too large", errProtocol)
		}
		n = int64(binary.BigEndian.Uint64(x[:]))
	default:
		n = int64(l)
	}
	if f.isControl() && (!f.fin || n > 125) {
		return frame{}, fmt.Errorf("%w: invalid control frame", errProtocol)
	}
	if n > fc.maxMsg {
		return frame{}, fmt.Errorf("%w: frame of %d bytes exceeds the %d byte limit", errProtocol, n, fc.maxMsg)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(fc.br, mask[:]); err != nil {
			return frame{}, err
		}
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(fc.br, f.payload); err != nil {
		return frame{}, err
	}
	if masked {
		for i := range f.payload {
			f.payload[i] ^= mask[i&3]
		}
	}
	return f, nil
}

// writeFrame writes one complete (FIN set) frame. It does not take any
// lock; a [Conn] serializes calls via its write mutex.
func (fc *frameCodec) writeFrame(op int, payload []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | byte(op)
	l := len(payload)
	hdrLen := 2
	switch {
	case l <= 125:
		hdr[1] = byte(l)
	case l <= 0xffff:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(l))
		hdrLen = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(l))
		hdrLen = 10
	}
	if fc.isClient {
		if _, err := rand.Read(hdr[hdrLen : hdrLen+4]); err != nil {
			return err
		}
		hdr[1] |= 0x80
		hdrLen += 4
	}
	if _, err := fc.bw.Write(hdr[:hdrLen]); err != nil {
		return err
	}
	if fc.isClient {
		// Masking must not modify the caller's buffer.
		buf := make([]byte, l)
		copy(buf, payload)
		mask := hdr[hdrLen-4 : hdrLen]
		for i := range buf {
			buf[i] ^= mask[i&3]
		}
		if _, err := fc.bw.Write(buf); err != nil {
			return err
		}
	} else if _, err := fc.bw.Write(payload); err != nil {
		return err
	}
	return fc.bw.Flush()
}

const (
	stOpen int32 = iota
	stClosed
)

var errMessageTooBig = errors.New("ws: message exceeds size limit")

// ErrClosed is returned by [Conn.WriteMessage] when the connection has been
// closed with a normal closure (1000). A normal closure records a nil
// terminal error, so without a sentinel a write after such a close would
// report success for a frame that is never sent.
var ErrClosed = errors.New("ws: connection closed")

// closedWriteErr is the error a write path returns for a closed
// connection: the recorded close error when there is one, ErrClosed for a
// normal closure.
func (c *Conn) closedWriteErr() error {
	if c.closeErr != nil {
		return c.closeErr
	}
	return ErrClosed
}

// closeWriteTimeout bounds how long the close-frame write in [Conn.Close]
// may take. The peer of a closing connection is often silent by
// definition; an unbounded write would hang the closing goroutine (and
// every goroutine waiting on the close) forever.
const closeWriteTimeout = 5 * time.Second

var connSeq uint64

// Conn is an open WebSocket connection.
//
// A Conn is tied to exactly one pumping goroutine: the goroutine that calls
// [Conn.ReadMessage]. [Conn.WriteMessage] and [Conn.Close] may be called
// from any goroutine.
//
// Conn is not safe for concurrent use of ReadMessage from multiple
// goroutines.
type Conn struct {
	nc net.Conn
	fc frameCodec
	mu sync.Mutex // serializes the write path

	id          uint64
	subprotocol string

	state         int32 // stOpen or stClosed (atomic)
	closeErr      error // valid once state == stClosed; guarded by c.mu
	handshakeData any

	idleTimeout    time.Duration
	lastActivity   time.Time

	inFrag  bool
	fragOp  int
	fragBuf []byte
}

func newConn(nc net.Conn, r io.Reader, isClient bool, maxMessageSize int64, idleTimeout time.Duration) *Conn {
	var br *bufio.Reader
	if existing, ok := r.(*bufio.Reader); ok {
		br = existing
	} else {
		br = bufio.NewReaderSize(r, 16<<10)
	}
	return &Conn{
		nc: nc,
		fc: frameCodec{
			br:       br,
			bw:       bufio.NewWriterSize(nc, 16<<10),
			isClient: isClient,
			maxMsg:   maxMessageSize,
		},
		id:             atomic.AddUint64(&connSeq, 1),
		idleTimeout:    idleTimeout,
		lastActivity:   time.Now(),
	}
}

// ID returns a unique identifier for the connection, useful as a key in
// session registries.
func (c *Conn) ID() uint64 { return c.id }

// Subprotocol returns the negotiated subprotocol, or "" if none.
func (c *Conn) Subprotocol() string { return c.subprotocol }

// HandshakeData returns the value passed to the upgrade via
// WithHandshakeData, or nil if none was provided.
func (c *Conn) HandshakeData() any { return c.handshakeData }

// RemoteAddr returns the peer's network address.
func (c *Conn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// LocalAddr returns this endpoint's network address.
func (c *Conn) LocalAddr() net.Addr { return c.nc.LocalAddr() }

// SetReadDeadline sets the underlying connection's read deadline. When the
// idle timeout keepalive is enabled it is overridden by the keepalive for
// the duration of each blocking read; use WithIdleTimeout(0) to manage
// deadlines yourself.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.nc.SetReadDeadline(t) }

// SetWriteDeadline sets the underlying connection's write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }

// finish records a terminal state. It is safe to call concurrently: the
// first caller's error wins, and the returned error is the one recorded at
// close time. A nil return means the connection closed normally (1000).
//
// The state transition and the closeErr write happen under c.mu so that no
// reader — which also reads closeErr under c.mu — can ever observe the
// closed state without the recorded error.
func (c *Conn) finish(err error) error {
	c.mu.Lock()
	if atomic.LoadInt32(&c.state) == stOpen {
		atomic.StoreInt32(&c.state, stClosed)
		c.closeErr = err
	}
	err = c.closeErr
	c.mu.Unlock()
	_ = c.nc.Close()
	return err
}

// ReadMessage reads the next complete message from the connection.
//
// It returns (op, data, nil) for a complete text or binary message, where op
// is OpText or OpBinary. It returns (0, nil, nil) when the connection has
// been closed with a normal closure (code 1000, in either direction).
// Any other close — including expected ones like 1001 "going away" — is
// reported as a [*CloseError] carrying the code and reason, so the
// distinction between a clean end and a notification is visible to the
// application.
//
// Pings and pongs are handled transparently: incoming pings are answered
// automatically and pongs are consumed, so neither appears in the return
// values. When the idle timeout is enabled and no frame has been received
// within the window, a ping is sent inline before the blocking read, which
// bounds detection of a silently dead peer to the idle timeout without any
// background goroutine.
//
// ReadMessage must only be called from one goroutine at a time.
func (c *Conn) ReadMessage() (opcode int, data []byte, err error) {
	if atomic.LoadInt32(&c.state) == stClosed {
		c.mu.Lock()
		err = c.closeErr
		c.mu.Unlock()
		return 0, nil, err
	}
	for {
		if err := c.armIdle(); err != nil {
			return 0, nil, c.finish(err)
		}
		var f frame
		if f, err = c.fc.readFrame(); err != nil {
			return 0, nil, c.finish(err)
		}
		_ = c.nc.SetReadDeadline(time.Time{}) // clear the keepalive deadline
		c.lastActivity = time.Now()

		switch f.opcode {
		case OpPing:
			if err := c.writeFrame(OpPong, f.payload); err != nil {
				return 0, nil, c.finish(err)
			}
			continue
		case OpPong:
			continue
		case OpClose:
			return c.peerClose(f.payload)
		case OpText, OpBinary:
			if c.inFrag {
				return 0, nil, c.finish(fmt.Errorf("%w: data frame while message is in progress", errProtocol))
			}
			if f.fin {
				return f.opcode, f.payload, nil
			}
			c.inFrag, c.fragOp, c.fragBuf = true, f.opcode, f.payload
			continue
		case OpContinuation:
			if !c.inFrag {
				return 0, nil, c.finish(fmt.Errorf("%w: continuation frame without start", errProtocol))
			}
			if int64(len(c.fragBuf)+len(f.payload)) > c.fc.maxMsg {
				c.inFrag, c.fragBuf = false, nil
				return 0, nil, c.finish(fmt.Errorf("%w: %w", errProtocol, errMessageTooBig))
			}
			c.fragBuf = append(c.fragBuf, f.payload...)
			if f.fin {
				op, buf := c.fragOp, c.fragBuf
				c.inFrag, c.fragBuf = false, nil
				return op, buf, nil
			}
		default:
			return 0, nil, c.finish(fmt.Errorf("%w: unknown opcode %d", errProtocol, f.opcode))
		}
	}
}

// peerClose handles a close frame received from the peer: reply with the same
// code, tear down, and report the outcome.
func (c *Conn) peerClose(payload []byte) (int, []byte, error) {
	code, reason := StatusNoStatusReceived, ""
	if len(payload) >= 2 {
		code = int(binary.BigEndian.Uint16(payload[:2]))
		reason = string(payload[2:])
	}
	_ = c.Close(code, reason)
	return 0, nil, c.finish(closeErrFor(code, reason))
}

// keepaliveDecision decides, before a blocking read, whether the connection
// has been quiet long enough to warrant a ping first, and which read
// deadline to set. It is pure in its inputs so the timing boundary can be
// tested exactly, without a clock or a socket.
func keepaliveDecision(lastActivity, now time.Time, idle time.Duration) (ping bool, deadline time.Time) {
	deadline = lastActivity.Add(idle)
	if now.After(deadline) {
		ping = true
		deadline = now.Add(idle)
	}
	return ping, deadline
}

// armIdle bounds the next blocking read. Every blocking read is therefore
// bounded when the idle timeout is set; see [keepaliveDecision].
func (c *Conn) armIdle() error {
	if c.idleTimeout <= 0 {
		return nil
	}
	ping, deadline := keepaliveDecision(c.lastActivity, time.Now(), c.idleTimeout)
	if ping {
		if err := c.writeFrame(OpPing, nil); err != nil {
			return err
		}
	}
	return c.nc.SetReadDeadline(deadline)
}

// writeFrame writes a frame, taking the write lock. Control frames are
// rejected here; use [Close] to send a close frame. A closed connection
// yields [Conn.closedWriteErr], never a silent success.
func (c *Conn) writeFrame(op int, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.LoadInt32(&c.state) == stClosed {
		return c.closedWriteErr()
	}
	return c.fc.writeFrame(op, payload)
}

// WriteMessage writes a complete text or binary message. It is safe to call
// from any goroutine. Writes do not fragment: the message is sent in a
// single frame, so messages must fit within maxMessageSize.
//
// On a closed connection WriteMessage always fails: with the recorded close
// error, or [ErrClosed] after a normal closure (1000) — never a silent
// success for a frame that will not be sent.
func (c *Conn) WriteMessage(op int, data []byte) error {
	if op != OpText && op != OpBinary {
		return fmt.Errorf("%w: WriteMessage requires OpText or OpBinary", errProtocol)
	}
	if int64(len(data)) > c.fc.maxMsg {
		return fmt.Errorf("%w: message of %d bytes exceeds the %d byte limit", errMessageTooBig, len(data), c.fc.maxMsg)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.LoadInt32(&c.state) == stClosed {
		return c.closedWriteErr()
	}
	return c.fc.writeFrame(op, data)
}

// Close closes the connection, sending a close frame with the given code and
// reason before tearing down the transport. It is idempotent and safe to
// call from any goroutine, including the pumping goroutine.
//
// Close codes must be in the range 1000-4999. The return value is the
// terminal error recorded on the connection — nil for a normal closure
// (1000), a [*CloseError] otherwise — not the status of the close-frame
// write, which is best effort: the kernel delivers queued data before the
// FIN, so the frame reaches the peer in order when the transport allows.
// Concurrent Close callers all observe the same recorded error, from the
// first one to close.
func (c *Conn) Close(code int, reason string) error {
	if code < 1000 || code > 4999 {
		return fmt.Errorf("ws: invalid close code %d", code)
	}
	var payload []byte
	if code != StatusNoStatusReceived && code != StatusAbnormalClosure {
		reason = reason[:min(len(reason), 123)] // close frame payloads max out at 125 bytes
		payload = make([]byte, 2+len(reason))
		binary.BigEndian.PutUint16(payload, uint16(code))
		copy(payload[2:], reason)
	}
	c.mu.Lock()
	if atomic.LoadInt32(&c.state) == stClosed {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	atomic.StoreInt32(&c.state, stClosed)
	c.closeErr = closeErrFor(code, reason)
	// The close frame is sent best-effort: the kernel delivers queued data
	// before the FIN, so it reaches the peer in order when the transport
	// allows. The write is bounded — a silent or half-dead peer must not be
	// able to hold the close open forever.
	_ = c.nc.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	_ = c.fc.writeFrame(OpClose, payload)
	_ = c.nc.SetWriteDeadline(time.Time{})
	c.mu.Unlock()
	_ = c.nc.Close()
	return c.closeErr
}

// Option configures a [Upgrader] (via [NewUpgrader]) or a client connection
// (via [Dial]). The same option names work on both sides where the setting
// is symmetric (subprotocols, message size, idle timeout); client-only
// options (headers, TLS, dial timeout) are ignored on the server side.
type Option func(*Config)

// Config holds the resolved options described by [Option].
type Config struct {
	CheckOrigin       func(r *http.Request) bool
	RequireClientCert bool
	Subprotocols      []string
	MaxMessageSize    int64
	IdleTimeout       time.Duration
	PreHandshake      []func(r *http.Request) error

	// Client-only fields, settable through the corresponding Options.
	Headers http.Header

	// Unexported client-only state.
	tlsConfigClient *tls.Config
	dialTimeout     time.Duration
}

// wsGUID is the magic GUID from RFC 6455 §1.3.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Upgrader validates the HTTP portion of a WebSocket handshake and performs
// the protocol switch to [Conn].
type Upgrader struct {
	checkOrigin       func(r *http.Request) bool
	requireClientCert bool
	subprotocols      []string
	maxMessageSize    int64
	idleTimeout       time.Duration
	preHandshake      []func(r *http.Request) error
}

// NewUpgrader creates an Upgrader with sensible defaults: same-origin origin
// checking, a 16 MiB message size limit, and a 60 second idle timeout for
// keepalive detection of silently dead peers.
func NewUpgrader(opts ...Option) *Upgrader {
	c := &Config{
		CheckOrigin:    defaultCheckOrigin,
		MaxMessageSize: 16 << 20,
		IdleTimeout:    60 * time.Second,
	}
	for _, o := range opts {
		o(c)
	}
	return &Upgrader{
		checkOrigin:       c.CheckOrigin,
		requireClientCert: c.RequireClientCert,
		subprotocols:      c.Subprotocols,
		maxMessageSize:    c.MaxMessageSize,
		idleTimeout:       c.IdleTimeout,
		preHandshake:      c.PreHandshake,
	}
}

type handshakeOpts struct {
	data any
}

// HandshakeOption configures a single upgrade.
type HandshakeOption func(*handshakeOpts)

// WithHandshakeData attaches a value to the connection produced by the
// upgrade, retrievable with [Conn.HandshakeData]. Use it to pass the result
// of pre-upgrade setup (an authenticated principal, a session) to the
// message loop without globals.
func WithHandshakeData(v any) HandshakeOption {
	return func(o *handshakeOpts) { o.data = v }
}

// WithCheckOrigin sets the origin policy. The default is strict same-origin:
// the request's Origin header must equal the request's scheme and Host, and
// requests without an Origin header are rejected.
func WithCheckOrigin(f func(r *http.Request) bool) Option {
	return func(c *Config) { c.CheckOrigin = f }
}

// WithRequireClientCert requires the request to carry a client certificate
// presented via mTLS and verified by the TLS layer (an
// http.Server.TLSConfig with ClientAuth set to VerifyClientCertIfGiven or
// RequireAndVerifyClientCert). Requests without a verified certificate are
// rejected with 403 before the protocol switch.
func WithRequireClientCert() Option {
	return func(c *Config) { c.RequireClientCert = true }
}

// WithSubprotocols advertises (server) or requests (client) the given
// subprotocols. The server selects the first one it advertises that the
// client requested, if any; the result is visible on both sides via
// [Conn.Subprotocol].
func WithSubprotocols(list ...string) Option {
	return func(c *Config) { c.Subprotocols = list }
}

// WithMaxMessageSize sets the maximum size of a single message (default
// 16 MiB) on either side. Frames and fragmented messages beyond the limit
// terminate the connection.
func WithMaxMessageSize(n int64) Option {
	return func(c *Config) { c.MaxMessageSize = n }
}

// WithIdleTimeout sets the keepalive idle timeout on either side (default
// 60s). When no frame has been received within the window, the next
// [Conn.ReadMessage] sends a ping and waits up to the timeout for any frame
// (pong included) before failing. Pass zero to disable keepalive and manage
// deadlines via [Conn.SetReadDeadline].
func WithIdleTimeout(d time.Duration) Option {
	return func(c *Config) { c.IdleTimeout = d }
}

// WithPreHandshake runs f on the request after protocol and origin checks,
// before the protocol switch. Return an error to reject the upgrade with
// 403, or a [*UpgradeError] to control the status code. Use it for policy
// checks that need the full request (rate limiting, per-path checks,
// logging).
func WithPreHandshake(f func(r *http.Request) error) Option {
	return func(c *Config) { c.PreHandshake = append(c.PreHandshake, f) }
}

// UpgradeError is returned by [Upgrader.Upgrade] when the handshake is
// rejected. The corresponding HTTP error response has already been written,
// so the caller only needs to log it.
type UpgradeError struct {
	Status int
	Msg    string
}

func (e *UpgradeError) Error() string {
	return fmt.Sprintf("ws: upgrade rejected: %s (HTTP %d)", e.Msg, e.Status)
}

func reject(w http.ResponseWriter, status int, msg string) (*Conn, error) {
	http.Error(w, msg, status)
	return nil, &UpgradeError{Status: status, Msg: msg}
}

// Upgrade validates the WebSocket handshake on r and switches the connection
// to a [Conn], which is returned. It is the last HTTP operation the calling
// handler should perform: once Upgrade succeeds, w must not be used again.
//
// On rejection, Upgrade writes an appropriate HTTP error response itself and
// returns a [*UpgradeError] for logging; the handler should simply return.
//
// Origin checking, client certificate requirements, and PreHandshake hooks
// are applied in that order.
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, opts ...HandshakeOption) (*Conn, error) {
	var ho handshakeOpts
	for _, o := range opts {
		o(&ho)
	}

	if r.Method != http.MethodGet {
		return reject(w, http.StatusMethodNotAllowed, "method not allowed")
	}
	// Authentication and policy checks run before protocol validation, so a
	// request that is not authorized is rejected before the server reveals
	// anything about the websocket handshake (and, for mTLS, before the
	// protocol headers are even inspected).
	if !u.checkOrigin(r) {
		return reject(w, http.StatusForbidden, "origin not allowed")
	}
	if u.requireClientCert && ClientCert(r) == nil {
		return reject(w, http.StatusForbidden, "client certificate required")
	}
	for _, f := range u.preHandshake {
		if err := f(r); err != nil {
			if ue, ok := err.(*UpgradeError); ok {
				return reject(w, ue.Status, ue.Msg)
			}
			return reject(w, http.StatusForbidden, err.Error())
		}
	}
	if !headerContainsToken(r.Header, "Connection", "Upgrade") {
		return reject(w, http.StatusBadRequest, "missing Connection: Upgrade header")
	}
	if !headerContainsToken(r.Header, "Upgrade", "websocket") {
		return reject(w, http.StatusBadRequest, "missing Upgrade: websocket header")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return reject(w, http.StatusUpgradeRequired, "unsupported websocket version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return reject(w, http.StatusBadRequest, "missing Sec-WebSocket-Key header")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return reject(w, http.StatusInternalServerError, "response writer does not support hijacking")
	}
	raw, buf, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("ws: hijack failed: %w", err)
	}
	// If the handler already wrote a response that has not been flushed,
	// its bytes are still sitting in buf; switching protocols now would
	// corrupt the stream. (A fully flushed response cannot be detected
	// after the fact; return before calling Upgrade when the request is
	// rejected, and never write to w after calling it.)
	if buf.Reader.Buffered() > 0 {
		_ = raw.Close()
		return nil, &UpgradeError{Status: 500, Msg: "response already started"}
	}

	protocol := negotiateProtocol(u.subprotocols, r.Header.Get("Sec-WebSocket-Protocol"))
	accept := acceptKey(key)

	var resp bytes.Buffer
	fmt.Fprintf(&resp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n", accept)
	if protocol != "" {
		fmt.Fprintf(&resp, "Sec-WebSocket-Protocol: %s\r\n", protocol)
	}
	resp.WriteString("\r\n")
	if _, err := raw.Write(resp.Bytes()); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("ws: write handshake response: %w", err)
	}

	c := newConn(raw, buf.Reader, false, u.maxMessageSize, u.idleTimeout)
	c.subprotocol = protocol
	c.handshakeData = ho.data
	return c, nil
}

// Handle returns an [http.Handler] that upgrades the request with u and then
// invokes fn, running the session for as long as the connection lives. When
// fn returns, the connection is closed: with the code carried by a returned
// [*CloseError], if any, or 1000 otherwise.
//
// The returned handler is ordinary: wrap it in further middleware as needed.
func (u *Upgrader) Handle(fn func(r *http.Request, c *Conn) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := u.Upgrade(w, r)
		if err != nil {
			return
		}
		err = fn(r, c)
		var ce *CloseError
		if errors.As(err, &ce) {
			_ = c.Close(ce.Code, ce.Reason)
			return
		}
		_ = c.Close(StatusNormalClosure, "")
	})
}

// Handle is [NewUpgrader].Handle with the default upgrader, for the simple
// cases where no upgrader configuration is needed.
func Handle(fn func(r *http.Request, c *Conn) error) http.Handler {
	return NewUpgrader().Handle(fn)
}

func defaultCheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

func headerContainsToken(h http.Header, key, token string) bool {
	for _, v := range h[key] {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func negotiateProtocol(server []string, clientHeader string) string {
	clientList := strings.Split(clientHeader, ",")
	for _, s := range server {
		for _, c := range clientList {
			if strings.TrimSpace(c) == s {
				return s
			}
		}
	}
	return ""
}

// Client-side settings, filled in from the same [Option] set as the
// upgrader; the symmetric fields (subprotocols, sizes, idle timeout) read
// from Config, the client-only ones live here.
type dialConfig struct {
	headers   http.Header
	tlsConfig *tls.Config
	timeout   time.Duration
}

// WithHeader sets a request header on the client handshake. Browsers cannot
// do this (they can only pass subprotocols and URLs), but programmatic
// clients use it for bearer tokens and the like.
func WithHeader(key, value string) Option {
	return func(c *Config) {
		if c.Headers == nil {
			c.Headers = make(http.Header)
		}
		c.Headers.Set(key, value)
	}
}

// WithTLS provides a complete TLS configuration for wss:// connections.
func WithTLS(cfg *tls.Config) Option {
	return func(c *Config) {
		c.tlsConfigClient = cfg
	}
}

// WithTLSClientCert enables mTLS by presenting the given client certificate
// and key. Server certificate verification uses the system root store
// (or cfg.InsecureSkipVerify if you say so via [WithTLS]). For custom root
// stores or SNI control, use [WithTLS] directly.
func WithTLSClientCert(cert *x509.Certificate, key any) Option {
	return func(c *Config) {
		cfg := c.tlsConfigClient
		if cfg == nil {
			cfg = &tls.Config{}
		}
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}
		c.tlsConfigClient = cfg
	}
}

// WithDialTimeout bounds the connect + handshake time (default: the context
// deadline, if any).
func WithDialTimeout(d time.Duration) Option {
	return func(c *Config) { c.dialTimeout = d }
}

// Dial opens a WebSocket client connection to rawurl (ws:// or wss://).
// It performs the handshake and returns an open [Conn] whose read state is
// owned by the calling goroutine.
func Dial(ctx context.Context, rawurl string, opts ...Option) (*Conn, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("ws: bad url %q: %w", rawurl, err)
	}
	switch u.Scheme {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("ws: unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	cfg := &Config{Headers: make(http.Header)}
	for _, o := range opts {
		o(cfg)
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = 16 << 20
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	dialCfg := &dialConfig{headers: cfg.Headers, tlsConfig: cfg.tlsConfigClient, timeout: cfg.dialTimeout}
	if d := dialCfg.timeout; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	dialer := &net.Dialer{}
	var nc net.Conn
	var plain net.Conn
	plain, err = dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("ws: dial %s: %w", host, err)
	}
	if u.Scheme == "wss" {
		tconn := tls.Client(plain, dialCfg.tlsConfig)
		if err := tconn.HandshakeContext(ctx); err != nil {
			plain.Close()
			return nil, fmt.Errorf("ws: tls handshake: %w", err)
		}
		nc = tconn
	} else {
		nc = plain
	}
	if deadline, ok := ctx.Deadline(); ok {
		nc.SetDeadline(deadline)
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		nc.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", u.RequestURI(), u.Host, key)
	if len(cfg.Subprotocols) > 0 {
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(cfg.Subprotocols, ", "))
	}
	for k, vs := range dialCfg.headers {
		switch {
		case strings.EqualFold(k, "Host"), strings.EqualFold(k, "Upgrade"),
			strings.EqualFold(k, "Connection"), strings.EqualFold(k, "Sec-WebSocket-Key"),
			strings.EqualFold(k, "Sec-WebSocket-Version"), strings.EqualFold(k, "Sec-WebSocket-Protocol"):
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&req, "%s: %s\r\n", k, v)
		}
	}
	req.WriteString("\r\n")
	if _, err := nc.Write(req.Bytes()); err != nil {
		nc.Close()
		return nil, fmt.Errorf("ws: write handshake: %w", err)
	}

	br := bufio.NewReaderSize(nc, 16<<10)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("ws: read handshake response: %w", err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		nc.Close()
		return nil, fmt.Errorf("ws: handshake failed: server replied %s", resp.Status)
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != acceptKey(key) {
		nc.Close()
		return nil, fmt.Errorf("ws: handshake failed: invalid Sec-WebSocket-Accept %q", got)
	}

	// The handshake is done; clear the connect deadline so the session is
	// governed by its own read/write deadlines and keepalive from here on.
	nc.SetReadDeadline(time.Time{})
	nc.SetWriteDeadline(time.Time{})

	c := newConn(nc, br, true, cfg.MaxMessageSize, cfg.IdleTimeout)
	c.subprotocol = resp.Header.Get("Sec-WebSocket-Protocol")
	return c, nil
}
