// Package ws is a WebSocket (RFC 6455) implementation for Go that uses only
// the standard library.
//
// # Quick start
//
// Server: one echo endpoint on an ordinary [http.ServeMux] — no callbacks,
// no pump goroutine; the goroutine that calls [Session.ReadMessage] is the
// connection's goroutine:
//
//	up := ws.NewUpgrader()
//	mux.Handle("/ws", up.Handle(func(_ *http.Request, c *ws.Session) error {
//		for {
//			op, data, err := c.ReadMessage()
//			if err != nil {
//				return err // io.EOF on a clean close, *ws.CloseError otherwise
//			}
//			if writeErr := c.WriteMessage(op, data); writeErr != nil {
//				return writeErr // a failed write means the transport is dead
//			}
//		}
//	}))
//
// Client:
//
//	c, err := ws.Dial(ctx, "wss://example.com/ws")
//	// err: TLS failure, an HTTP status, or a rejected handshake
//	defer c.Close(ws.StatusNormalClosure, "")
//	// err = c.WriteMessage(ws.OpText, []byte("hello"))
//
// Executable, runnable versions of both halves — plus bearer auth, the
// origin allowlist, application close codes, and the raw face — are the
// Example functions in examples_test.go; each is a test with pinned output.
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
//     tokens, mTLS client-certificate checks (r.TLS.PeerCertificates),
//     sessions, and anything else run before the upgrade, in plain
//     http.Handler code; the result rides on the request context into the
//     message handler.
//
//  3. There are no callbacks and no pump goroutine. The goroutine that calls
//     [Session.ReadMessage] is the connection's goroutine. Your handler does
//     its setup, upgrades, runs its read loop, and returns when the
//     connection dies — cleanup is a plain deferred call.
//
//     c, err := up.Upgrade(w, r)
//     if err != nil {
//     return // an appropriate 4xx/5xx response was already written
//     }
//     defer c.Close(ws.StatusNormalClosure, "")
//
//     for {
//     op, data, err := c.ReadMessage()
//     if errors.Is(err, io.EOF) {
//     break // normal close (1000, either direction)
//     }
//     if err != nil {
//     // abnormal end: transport error, protocol violation, or an
//     // application close code. See CloseCode for details.
//     break
//     }
//     // op is OpText or OpBinary
//     _ = c.WriteMessage(op, data)
//     }
//
//  4. Close detection covers all four classes of death, funneled into the
//     single read return: a close frame from the peer, a transport error, a
//     keepalive timeout (a silent peer is probed with a ping once silence
//     reaches the idle timeout, [WithIdleTimeout], and the connection is
//     considered dead if it is still silent after a second window — all
//     inline in the read path, no background goroutines), and a local
//     [Session.Close] call.
//
// # Two faces: the session and the raw connection
//
// The protocol core is [RawConn]: one read loop ([RawConn.ReadEvent]) that
// delivers every protocol event — each data message with its op-type, every
// ping, every pong, the peer's close with its resolved code and reason — and
// a write side that can fragment messages frame by frame
// ([RawConn.WriteFrame]). It enforces what the RFC requires (masking, the
// close-code table, UTF-8, the size limit, the mandatory close on protocol
// violation) and does no application policy: it never answers a ping for
// you, and, from [DialRaw], it sends no keepalive probes unless asked.
//
// [Session] is the policy layer built on the same core: [Dial] and
// [Upgrader.Upgrade] produce one, and its [Session.ReadMessage] runs the
// same loop with the control traffic handled for the application — pings
// answered automatically, pongs consumed (or handed to a
// [WithPongHandler]), and the peer's close mapped to the read's terminal
// error. Message-oriented applications use Session; protocol implementers
// use RawConn via [DialRaw] and [Upgrader.UpgradeRaw]. A Session
// deliberately does not expose its raw connection: two read loops over one
// transport would race.
//
// # Extensions
//
// permessage-deflate (RFC 7692) is the one extension this package speaks.
// The server answers it when the client offers it ([WithCompression] turns
// the whole negotiation off), and the client offers it on [Dial]. Messages
// compress per message — no context takeover — and the full 32 KiB window
// is used, so offers or responses that cap the window below that are
// declined (server) or fail the dial (client). [Session.Compressed] reports
// whether the extension was negotiated on a live connection. Every other
// reserved bit on a frame — and RSV1 on a control or continuation frame —
// is a protocol error.
//
// # Concurrency
//
//  1. [Session.WriteMessage] and its natural-typed forms ([Session.WriteText],
//     [Session.WriteBinary], [Session.WriteJSON]), [Session.Ping] — plus
//     [Session.Close] — are safe to call from any goroutine; the same holds
//     for the raw equivalents on [RawConn] (including [RawConn.WriteFrame]
//     and [RawConn.Pong]).
//  2. The read loop is not: [Session.ReadMessage] and [RawConn.ReadEvent]
//     are owned by the single goroutine that pumps the connection, and the
//     two are never mixed on one connection — read state is owned by that
//     goroutine. Never call either from two goroutines.
//  3. Between sequential read calls in the same goroutine there are no
//     visibility concerns: handler-local state modified in one iteration is
//     plainly visible in the next.
//
// # Cancellation
//
// A context bounds connection *establishment*: [Dial] takes one, and the
// [WithDialer] dial function takes one. On a live connection, the
// *deadlines* do the bounding: the keepalive window (or a read deadline
// when keepalive is disabled) bounds reads, and the write timeout bounds
// writes and [Session.Close]. Cancelling a live connection is therefore
// [Session.Close] from another goroutine — bounded, idempotent, and safe
// from anywhere — rather than a context cancellation, which is what the
// deadline ownership above makes the cheaper answer.
//
// # Real-world interop
//
// A few wire details are fixed by observation of real peers (browsers, Node
// ws) rather than by the RFCs alone; each fact below is pinned by the e2e
// interop suites so it fails loudly instead of drifting.
//
//   - Extension header spelling. The RFC 6455 and RFC 7692 examples use the
//     plural Sec-WebSocket-Extensions, while the IANA registration is
//     singular, and real handshakes carry both (Node's ws reads only the
//     plural in a 101 response). Input accepts both spellings; output uses
//     the RFC plural.
//   - Browser offers differ (measured, Chromium and Firefox): Chromium
//     sends "permessage-deflate; client_max_window_bits" (the parameter
//     without a value, i.e. no client-window limit), Firefox sends the bare
//     token. Both are accepted; RFC 7692 §7.1 makes every parameter
//     optional.
//   - Decompression tail (deviation from RFC 7692 §7.2.2). The RFC prescribes
//     appending four octets (00 00 ff ff) to complete the truncated stream.
//     Real peers additionally end the stream with an empty BFINAL=0 block,
//     which Go's strict compress/flate reader would run past into EOF and
//     report "unexpected EOF". This package therefore appends the four RFC
//     octets plus the BFINAL empty block (01 00 00 ff ff) — nine octets
//     total; see deflateTailBytes.
//   - Compression wire shape (RFC 7692 §7.2.1). The truncated stream is
//     produced from the stdlib flate writer by Flush (not Close, which would
//     emit a BFINAL=1 Huffman block, not the RFC wire encoding) and dropping
//     the final four octets of the BFINAL=0 empty block that Flush appends.
//   - Close code for non-UTF-8 text. RFC 6455 §5.6 mandates closing on a
//     non-UTF-8 text frame but names no code; Node's ws receiver fails such
//     frames with 1007 (WS_ERR_INVALID_UTF8), as do browsers per the WHATWG
//     spec, so this package fails with 1007 (invalid data type) — the
//     interop-correct choice for §7.4.
//
// # File map
//
// This is a single-file implementation. Go does not require declaration
// order, so the file is organized for reading instead — the high-level API
// first, the internals after:
//
//  1. the session face: [Session], [Session.ReadMessage], the session
//     write/close/accessor surface
//  2. options: [Option], [Config], and every [WithSubprotocols] function
//  3. server entry: [Upgrader], [Upgrader.Upgrade]/[Upgrader.UpgradeRaw],
//     [Upgrader.Handle]/[Upgrader.HandleRaw], the handshake validation and
//     negotiation helpers
//  4. client entry: [Dial]/[DialRaw] and the dial-time handshake
//  5. the raw face: [RawConn], [Event], [RawConn.ReadEvent], keepalive,
//     close-code resolution, [RawConn.WriteFrame]/[RawConn.Pong] and the
//     raw write surface
//  6. protocol core: terminal handling and permessage-deflate
//  7. wire format: the frame codec (readFrame, writeFrame)
//  8. protocol constants: close codes, frame opcodes, wire defaults
//  9. errors: [CloseError], [CloseCode], [ErrClosed], the internal sentinels
package ws

// This software is released into the public domain under the Unlicense
// (https://unlicense.org). The full license text is in LICENSE at the
// repository root; it is repeated here so the license travels with the
// file when it is vendored by copying, as this package is designed to be.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 mandates SHA-1 in the handshake
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 1 · The session face: Session, the message-oriented connection

// Session is a message-oriented WebSocket connection built on [RawConn]:
// data messages in, data messages out, and the control traffic handled
// for the application. Pings the peer sends are answered automatically;
// pongs are consumed (or delivered to a [WithPongHandler]); the peer's
// close is mapped to the read's terminal error — [io.EOF] for a clean end,
// a [*CloseError] otherwise. Keepalive probes ride on the underlying
// connection's idle timeout.
//
// A Session is tied to exactly one pumping goroutine: the goroutine that
// calls [Session.ReadMessage]. Every other method is safe from any
// goroutine.
//
// The raw protocol view — every ping, every pong, every close event, and
// fragmented writes — is [RawConn], produced by [DialRaw] and
// [Upgrader.UpgradeRaw]. A Session deliberately does not expose it: the
// two read loops over one transport would race.
type Session struct {
	raw         *RawConn
	pongHandler func([]byte) // invoked inline by ReadMessage (the pumping goroutine)
}

// newSession wraps the policy layer over a raw connection: the pong
// handler and, via ReadMessage, the automatic pong and the close mapping.
func newSession(raw *RawConn, pongHandler func([]byte)) *Session {
	return &Session{raw: raw, pongHandler: pongHandler}
}

// ReadMessage reads the next complete message from the connection.
//
// It returns (op, data, nil) for a complete text or binary message, where op
// is OpText or OpBinary. It returns (0, nil, [io.EOF]) when the connection
// has ended cleanly — a normal closure (code 1000) in either direction, or
// a close frame without a status — so [errors.Is] on [io.EOF] is the check
// for a clean end. Any other close — including expected ones like 1001
// "going away" — is reported as a [*CloseError] carrying the code and
// reason, so the distinction between a clean end and a notification is
// visible to the application.
//
// A frame-level protocol violation — a masking violation, reserved-bit
// misuse, a malformed or oversized frame header, an unknown opcode — is
// answered with a 1002 close frame before the transport is torn down
// (RFC 6455 §7.1.7). Errors detected while a data message is being
// assembled (fragmentation violations, size and decompression limits) end
// the connection without a close frame: the stream has already diverged,
// so anything written past that point is best effort at best.
//
// Pings and pongs are handled transparently: incoming pings are answered
// automatically and pongs are consumed, so neither appears in the return
// values. Text messages must be valid UTF-8 (RFC 6455 §5.6): a text
// message that is not — whole or reassembled from fragments — fails the
// connection with 1007 (invalid data type), the close the browser
// implementations use for exactly this. Binary messages are never checked.
//
// When the idle timeout is enabled and a blocking read has been silent for
// the window, a ping is sent inline and the read re-arms; if the peer is
// still silent after a second window the read fails with a timeout. All of
// this is inline — no background goroutine — so a silently dead peer is
// detected within about two windows.
//
// ReadMessage must only be called from one goroutine at a time.
func (s *Session) ReadMessage() (Op, []byte, error) {
	for {
		event, readErr := s.raw.ReadEvent()
		if readErr != nil {
			return 0, nil, readErr
		}
		// OpText and OpBinary are the data-message ops: the default arm.
		switch event.Op {
		case OpPing:
			// Answer inline, exactly as a raw application would with
			// RawConn.Pong: a failed pong write breaks the transport, so
			// the read reports it and the connection is torn down.
			pingErr := s.raw.Pong(event.Payload)
			if pingErr != nil {
				return 0, nil, s.raw.finish(pingErr)
			}

			continue
		case OpPong:
			if s.pongHandler != nil {
				s.pongHandler(event.Payload)
			}

			continue
		case OpClose:
			// The raw loop already replied and finished; report the
			// resolved close the way the read has always reported it.
			return 0, nil, terminalErr(closeErrFor(event.Code, event.Reason))
		default:
			return event.Op, event.Payload, nil
		}
	}
}

// WriteMessage writes a complete text or binary message, exactly as
// [RawConn.WriteMessage]: safe from any goroutine, validated before the
// wire, and a transport failure fails the connection.
func (s *Session) WriteMessage(op Op, data []byte) error { return s.raw.WriteMessage(op, data) }

// WriteText writes s as a text message, exactly as [RawConn.WriteText].
func (s *Session) WriteText(msg string) error { return s.raw.WriteText(msg) }

// WriteBinary writes data as a binary message, exactly as [RawConn.WriteBinary].
func (s *Session) WriteBinary(data []byte) error { return s.raw.WriteBinary(data) }

// WriteJSON marshals v to JSON and writes it as a text message, exactly as
// [RawConn.WriteJSON].
func (s *Session) WriteJSON(v any) error { return s.raw.WriteJSON(v) }

// Ping sends an application-level ping, exactly as [RawConn.Ping]; the
// peer's pong is consumed by the read loop (or delivered to the
// [WithPongHandler], if one was set).
func (s *Session) Ping(payload []byte) error { return s.raw.Ping(payload) }

// Close closes the connection, exactly as [RawConn.Close]: idempotent,
// safe from any goroutine, best-effort close frame, bounded write.
func (s *Session) Close(code int, reason string) error { return s.raw.Close(code, reason) }

// Closed reports whether the connection has been closed, exactly as
// [RawConn.Closed].
func (s *Session) Closed() bool { return s.raw.Closed() }

// ID returns the connection's unique identifier, exactly as [RawConn.ID].
func (s *Session) ID() uint64 { return s.raw.ID() }

// Subprotocol returns the negotiated subprotocol, exactly as
// [RawConn.Subprotocol].
func (s *Session) Subprotocol() string { return s.raw.Subprotocol() }

// RemoteAddr returns the peer's network address, exactly as
// [RawConn.RemoteAddr].
func (s *Session) RemoteAddr() net.Addr { return s.raw.RemoteAddr() }

// LocalAddr returns this endpoint's network address, exactly as
// [RawConn.LocalAddr].
func (s *Session) LocalAddr() net.Addr { return s.raw.LocalAddr() }

// SetReadDeadline sets the underlying connection's read deadline, exactly
// as [RawConn.SetReadDeadline].
func (s *Session) SetReadDeadline(t time.Time) error { return s.raw.SetReadDeadline(t) }

// SetWriteDeadline sets the underlying connection's write deadline,
// exactly as [RawConn.SetWriteDeadline].
func (s *Session) SetWriteDeadline(t time.Time) error { return s.raw.SetWriteDeadline(t) }

// Compressed reports whether permessage-deflate was negotiated, exactly as
// [RawConn.Compressed].
func (s *Session) Compressed() bool { return s.raw.Compressed() }

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 2 · Options: Option, Config, and every With* function

// Option configures a [Upgrader] (via [NewUpgrader]) or a client connection
// (via [Dial]). The same option names work on both sides where the setting
// is symmetric (subprotocols, message size, idle timeout); client-only
// options (headers, dial timeout, [WithDialer]) are ignored on the server
// side, and the server-only origin policy ([WithCheckOrigin]) is ignored on
// the client side.
type Option func(*Config)

// Config holds the resolved options described by [Option].
type Config struct {
	CheckOrigin    func(r *http.Request) bool
	Subprotocols   []string
	MaxMessageSize int64
	IdleTimeout    time.Duration
	WriteTimeout   time.Duration

	// Compression enables permessage-deflate (RFC 7692) on both sides
	// (default: true); CompressionLevel is the flate level used to
	// compress (default: flate.DefaultCompression).
	Compression      bool
	CompressionLevel int

	// Client-only fields, settable through the corresponding Options.
	Headers http.Header

	// Unexported client-only state.
	dialer      func(ctx context.Context, u *url.URL) (net.Conn, error)
	dialTimeout time.Duration

	// Unexported shared state.
	pongHandler func([]byte)
}

// WithSubprotocols advertises (server) or requests (client) the given
// subprotocols. The server selects the first one it advertises that the
// client requested, if any, and echoes it on the 101; when none match it
// selects none and the handshake still succeeds — an application that
// requires a subprotocol must reject the request itself, in its own
// [http.Handler] code before the request reaches the upgrader. The client
// verifies the server's choice: the echoed token must be one of the ones
// it offered (RFC 6455 §1.9), or the dial fails. An advertised token that
// is not a valid token (RFC 2616) fails every handshake on the upgrader
// with 400 — a misconfiguration the 101 must not echo onto the wire. The
// result is visible on both sides via [Session.Subprotocol].
func WithSubprotocols(list ...string) Option {
	return func(cfg *Config) { cfg.Subprotocols = list }
}

// WithCompression enables or disables permessage-deflate (RFC 7692) on
// either side; it is enabled by default. Disabling it makes the endpoint
// ignore the client's extension offer (server: the response carries no
// extension, the connection runs uncompressed) or never offer it (client).
//
// Compressed traffic is exactly as size-bounded as uncompressed traffic:
// the decompressed payload must fit [WithMaxMessageSize], and the bound is
// enforced while decompressing, not after.
func WithCompression(enabled bool) Option {
	return func(cfg *Config) { cfg.Compression = enabled }
}

// WithCompressionLevel sets the compression level used by permessage-deflate:
// any compress/flate level (flate.NoCompression, flate.BestSpeed, the
// intermediate tiers, flate.BestCompression; the default is
// flate.DefaultCompression). It only has an effect when [WithCompression] is
// enabled. Compressed messages trade CPU for bandwidth; on high-throughput
// byte tunnels (a screen stream, a file relay) flate.BestSpeed or
// flate.DefaultCompression is usually the right call.
func WithCompressionLevel(level int) Option {
	return func(cfg *Config) { cfg.CompressionLevel = level }
}

// WithMaxMessageSize sets the maximum size of a single message (default
// 16 MiB) on either side. Frames and fragmented messages received beyond
// the limit terminate the connection; a local WriteMessage over the limit
// simply returns an error. For chat-style traffic the OWASP WebSocket
// guidance is far lower — 64 KiB is a sane cap; set it per endpoint.
// A non-positive limit is not meaningful and is replaced by the default.
func WithMaxMessageSize(n int64) Option {
	return func(cfg *Config) { cfg.MaxMessageSize = n }
}

// WithIdleTimeout sets the keepalive window on either side (default 60s).
// When no frame has been received for the window, the next blocking
// [Session.ReadMessage] probes the peer with a ping; the connection is
// considered dead and the read fails with a timeout if the peer is still
// silent after a second window. A pong (or any frame) from the peer resets
// the clock, so an idle-but-alive connection is kept alive and probed
// roughly every window. The read deadline spans a whole frame, so a single
// frame that takes longer than the window to arrive — a large message on a
// slow link — triggers the probe and, if it is still incomplete after a
// second window, the kill. Pass zero to disable keepalive and manage
// deadlines via [Session.SetReadDeadline]. A negative window is invalid and is
// replaced by the default, never by "disabled".
func WithIdleTimeout(d time.Duration) Option {
	return func(cfg *Config) { cfg.IdleTimeout = d }
}

// WithWriteTimeout bounds how long a single [Session.WriteMessage] may block
// writing to the transport, so a blackholed peer cannot wedge the write
// mutex and, with it, [Session.Close]. The default is 30 s; pass 0 to remove
// the bound (a write then blocks until the transport completes or the
// connection is closed). A negative bound is invalid and is replaced by
// the default, never by "unbounded".
func WithWriteTimeout(d time.Duration) Option {
	return func(cfg *Config) { cfg.WriteTimeout = d }
}

// WithPongHandler sets a handler for pong frames received on a session:
// pongs are otherwise consumed transparently and never reach the
// application. The handler is invoked inline by [Session.ReadMessage], in
// the pumping goroutine itself, so it must be fast and non-blocking — the
// usual use is recording the arrival of the answer to an application
// [Session.Ping]. It is never invoked from any other goroutine, and never
// after ReadMessage has returned a terminal error. It has no effect on a
// [RawConn] produced by [DialRaw] or [Upgrader.UpgradeRaw]: there, pongs
// are events, not a callback.
func WithPongHandler(handler func(payload []byte)) Option {
	return func(cfg *Config) { cfg.pongHandler = handler }
}

// sanitizeLimits repairs non-sensical limits so a misconfiguration can
// never silently disable a protection: a non-positive message size, a
// negative idle window, or a negative write bound falls back to the
// library default. Zero keeps its documented meanings (disabled keepalive,
// unbounded writes).
func sanitizeLimits(cfg *Config) {
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = defaultMaxMessageSize
	}
	if cfg.IdleTimeout < 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.WriteTimeout < 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
}

// WithCheckOrigin sets the origin policy. The default is strict same-origin
// for requests that carry an Origin header (it must equal the request's
// scheme and Host); requests without one — programmatic clients — are
// allowed. See [NewUpgrader] for the rationale.
//
// The default compares against the request's Host exactly as received, so a
// Host that carries an explicit default port ("example.com:80") counts as a
// different origin, and behind a TLS-terminating proxy (request.TLS nil) the
// scheme is taken to be http; set a custom check for such deployments.
func WithCheckOrigin(check func(r *http.Request) bool) Option {
	return func(cfg *Config) { cfg.CheckOrigin = check }
}

// WithHeader sets a request header on the client handshake. Browsers cannot
// do this (they can only pass subprotocols and URLs), but programmatic
// clients use it for bearer tokens and the like.
func WithHeader(key, value string) Option {
	return func(cfg *Config) {
		if cfg.Headers == nil {
			cfg.Headers = make(http.Header)
		}
		cfg.Headers.Set(key, value)
	}
}

// WithDialer replaces the client's transport: dial returns the connection
// the WebSocket handshake runs over, so the application owns the transport
// policy — TLS (custom root stores, client certificates for mTLS), proxy
// CONNECT tunnels, Unix sockets — while the library performs only the
// WebSocket handshake. When set, the library applies no TLS of its own,
// even for wss:// URLs: the returned connection is used as-is, and the URL
// is passed so the dialer sees the scheme, host, and path. The context
// deadline, when one was given, is set on the returned connection for the
// handshake and cleared once it succeeds, exactly as on the default
// transport.
//
//	ws.Dial(ctx, "wss://example.com/ws", ws.WithDialer(func(ctx context.Context, u *url.URL) (net.Conn, error) {
//		conn, err := net.Dial("tcp", u.Host)
//		if err != nil {
//			return nil, err
//		}
//		return tls.Client(conn, &tls.Config{ServerName: u.Hostname(),
//			Certificates: clientCerts}), nil
//	}))
//
// Without this option the default transport is used: plain TCP for ws://
// and TLS with the system root store for wss://.
func WithDialer(dial func(ctx context.Context, u *url.URL) (net.Conn, error)) Option {
	return func(cfg *Config) { cfg.dialer = dial }
}

// WithDialTimeout bounds the connect + handshake time (default: the context
// deadline, if any).
func WithDialTimeout(d time.Duration) Option {
	return func(cfg *Config) { cfg.dialTimeout = d }
}

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 3 · Server entry: upgrading a request to a connection

// Upgrader validates the HTTP portion of a WebSocket handshake and performs
// the protocol switch to a [*Session].
type Upgrader struct {
	checkOrigin     func(r *http.Request) bool
	subprotocols    []string
	maxMessageSize  int64
	idleTimeout     time.Duration
	writeTimeout    time.Duration
	compressEnabled bool
	compressLevel   int // flate level, as configured
	pongHandler     func([]byte)
}

// NewUpgrader creates an Upgrader with sensible defaults: strict same-origin
// origin checking for requests that carry an Origin header (requests without
// one — programmatic clients — are allowed, since browsers always send it
// and a wrong-origin browser is still rejected), a 16 MiB message size
// limit, and a 60 second keepalive window: a connection silent for that long
// is probed with a ping, and is considered dead if it is still silent after
// a second window.
func NewUpgrader(opts ...Option) *Upgrader {
	cfg := &Config{
		CheckOrigin:      defaultCheckOrigin,
		MaxMessageSize:   defaultMaxMessageSize,
		IdleTimeout:      defaultIdleTimeout,
		WriteTimeout:     defaultWriteTimeout,
		Compression:      true,
		CompressionLevel: flate.DefaultCompression,
	}
	for _, apply := range opts {
		apply(cfg)
	}
	sanitizeLimits(cfg)

	return &Upgrader{
		checkOrigin:     cfg.CheckOrigin,
		subprotocols:    cfg.Subprotocols,
		maxMessageSize:  cfg.MaxMessageSize,
		idleTimeout:     cfg.IdleTimeout,
		writeTimeout:    cfg.WriteTimeout,
		compressEnabled: cfg.Compression,
		compressLevel:   cfg.CompressionLevel,
		pongHandler:     cfg.pongHandler,
	}
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

func reject(writer http.ResponseWriter, status int, msg string) (*RawConn, error) {
	return nil, rejectStatus(writer, status, msg)
}

// rejectStatus writes the HTTP error response and returns the matching
// [*UpgradeError] for the caller to log.
func rejectStatus(writer http.ResponseWriter, status int, msg string) *UpgradeError {
	http.Error(writer, msg, status)

	return &UpgradeError{Status: status, Msg: msg}
}

// rejectOnConn writes the HTTP error response directly on an already
// hijacked connection and tears it down. After the hijack the
// ResponseWriter is dead — net/http logs the write but the bytes never
// reach the client — so the response must go over the raw connection.
// Connection: close keeps the client from ever treating the remainder of
// the stream as WebSocket traffic.
func rejectOnConn(raw net.Conn, status int, msg string) *UpgradeError {
	text := http.StatusText(status)
	body := msg + "\n"
	_, _ = fmt.Fprintf(raw, "HTTP/1.1 %d %s\r\n"+
		"Content-Type: text/plain; charset=utf-8\r\n"+
		"X-Content-Type-Options: nosniff\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, text, len(body), body)
	_ = raw.Close()

	return &UpgradeError{Status: status, Msg: msg}
}

// checkHandshakeHeaders validates the websocket protocol headers on the
// request and returns its Sec-WebSocket-Key (RFC 6455 §4.1-§4.2): the
// Connection and Upgrade tokens, exactly one supported
// Sec-WebSocket-Version, and exactly one well-formed Sec-WebSocket-Key —
// the base64 of exactly 16 octets. Several header lines for the
// single-value headers are a malformed handshake: the value would be
// ambiguous, so they are rejected rather than resolved to the first line.
// Each rejection writes the HTTP error response itself; the version-mismatch
// response additionally names the version(s) the server understands, per
// §4.2.
func checkHandshakeHeaders(writer http.ResponseWriter, request *http.Request) (string, *UpgradeError) {
	if !headerContainsToken(request.Header, "Connection", "Upgrade") {
		return "", rejectStatus(writer, http.StatusBadRequest, "missing Connection: Upgrade header")
	}
	if !headerContainsToken(request.Header, "Upgrade", "websocket") {
		return "", rejectStatus(writer, http.StatusBadRequest, "missing Upgrade: websocket header")
	}
	versions := request.Header.Values("Sec-WebSocket-Version")
	if len(versions) == 0 {
		return "", rejectStatus(writer, http.StatusBadRequest, "missing Sec-WebSocket-Version header")
	}
	if len(versions) > 1 {
		return "", rejectStatus(writer, http.StatusBadRequest, "multiple Sec-WebSocket-Version headers")
	}
	if versions[0] != websocketVer {
		// RFC 6455 §4.2: the version-mismatch response names the
		// version(s) the server understands.
		writer.Header().Add("Sec-WebSocket-Version", websocketVer)

		return "", rejectStatus(writer, http.StatusUpgradeRequired, "unsupported websocket version")
	}
	keys := request.Header.Values("Sec-WebSocket-Key")
	if len(keys) == 0 {
		return "", rejectStatus(writer, http.StatusBadRequest, "missing Sec-WebSocket-Key header")
	}
	if len(keys) > 1 {
		return "", rejectStatus(writer, http.StatusBadRequest, "multiple Sec-WebSocket-Key headers")
	}
	// RFC 6455 §4.1: the key must be well-formed — the base64 of 16 octets.
	raw, decodeErr := base64.StdEncoding.DecodeString(keys[0])
	if decodeErr != nil || len(raw) != wsKeyBytes {
		return "", rejectStatus(writer, http.StatusBadRequest, "malformed Sec-WebSocket-Key header")
	}

	return keys[0], nil
}

// checkPolicy runs the upgrader's origin gate. Authentication and
// authorization are ordinary middleware in front of the upgrader; the
// origin check is the one policy the library itself enforces, because a
// cross-origin browser is the cross-site WebSocket hijacking attack case.
// Rejections write the HTTP error response themselves.
func (u *Upgrader) checkPolicy(writer http.ResponseWriter, request *http.Request) *UpgradeError {
	if !u.checkOrigin(request) {
		return rejectStatus(writer, http.StatusForbidden, "origin not allowed")
	}

	return nil
}

// writeSwitchingProtocols writes the 101 Switching Protocols response with
// the accept key and, when negotiated, the selected subprotocol and
// extension header (RFC 6455 §4.1).
func writeSwitchingProtocols(conn net.Conn, protocol, accept, extension string) error {
	var resp bytes.Buffer
	resp.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	resp.WriteString("Upgrade: websocket\r\n")
	resp.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&resp, "Sec-WebSocket-Accept: %s\r\n", accept)
	if protocol != "" {
		fmt.Fprintf(&resp, "Sec-WebSocket-Protocol: %s\r\n", protocol)
	}
	if extension != "" {
		fmt.Fprintf(&resp, "Sec-WebSocket-Extensions: %s\r\n", extension)
	}
	resp.WriteString("\r\n")
	_, err := conn.Write(resp.Bytes())
	if err != nil {
		return fmt.Errorf("ws: write 101 response: %w", err)
	}

	return nil
}

// Upgrade validates the WebSocket handshake on r and switches the
// connection to a [*Session], which is returned. It is the last HTTP
// operation the calling handler should perform: once Upgrade succeeds, w
// must not be used again.
//
// On rejection, Upgrade writes an appropriate HTTP error response itself
// and returns a [*UpgradeError] for logging; the handler should simply
// return.
//
// Origin checking is applied before the protocol headers are validated.
func (u *Upgrader) Upgrade(writer http.ResponseWriter, request *http.Request) (*Session, error) {
	raw, err := u.upgradeCore(writer, request)
	if err != nil {
		return nil, err
	}

	return newSession(raw, u.pongHandler), nil
}

// UpgradeRaw is [Upgrader.Upgrade] for the raw protocol view: the same
// handshake validation and protocol switch, but the returned connection is
// a [*RawConn] — every ping, pong, and close arrives as an [Event], pings
// are not answered automatically, and fragmented writes are available via
// [RawConn.WriteFrame].
func (u *Upgrader) UpgradeRaw(writer http.ResponseWriter, request *http.Request) (*RawConn, error) {
	return u.upgradeCore(writer, request)
}

// upgradeCore performs the handshake validation and protocol switch and
// returns the raw connection; [Upgrader.Upgrade] wraps it in a [*Session]
// on top.
func (u *Upgrader) upgradeCore(writer http.ResponseWriter, request *http.Request) (*RawConn, error) {
	if request.Method != http.MethodGet {
		return reject(writer, http.StatusMethodNotAllowed, "method not allowed")
	}
	// The origin check runs before protocol validation, so a request from a
	// cross-origin browser is rejected before the server reveals anything
	// about the websocket handshake.
	rejection := u.checkPolicy(writer, request)
	if rejection != nil {
		return nil, rejection
	}
	key, rejection := checkHandshakeHeaders(writer, request)
	if rejection != nil {
		return nil, rejection
	}
	// RFC 6455 §4.1: a request body must not be present; its bytes would be
	// indistinguishable from the first frames on the hijacked connection.
	if request.Body != http.NoBody {
		return reject(writer, http.StatusBadRequest, "request body not allowed")
	}

	hj, ok := writer.(http.Hijacker)
	if !ok {
		return reject(writer, http.StatusInternalServerError,
			"response writer does not support hijacking")
	}
	raw, buf, err := hj.Hijack()
	if err != nil {
		return nil, fmt.Errorf("ws: hijack failed: %w", err)
	}
	// buf holds any request bytes net/http read but did not consume —
	// pipelined requests; a body on the GET is caught earlier by the
	// request-body check. Switching protocols now would desynchronize the
	// stream, so reject with 400. (Bytes a handler wrote to the
	// ResponseWriter are flushed by net/http before the switch, so an
	// accidental pre-upgrade write reaches the client as the earlier
	// response rather than a corrupt stream; rejected requests should
	// return before calling Upgrade, and nothing may be written to writer
	// after it succeeds.)
	if buf.Reader.Buffered() > 0 {
		return nil, rejectOnConn(raw, http.StatusBadRequest, "unconsumed request data")
	}

	// §1.9: every Sec-WebSocket-Protocol line shares one 1#token value
	// space, so all lines participate in the selection.
	protocol, protoErr := negotiateProtocol(u.subprotocols,
		strings.Join(request.Header.Values("Sec-WebSocket-Protocol"), ", "))
	if protoErr != nil {
		return nil, rejectOnConn(raw, http.StatusBadRequest, protoErr.Error())
	}
	extension, extErr := u.negotiateExtensions(request)
	if extErr != nil {
		return nil, rejectOnConn(raw, http.StatusBadRequest, extErr.Error())
	}
	writeErr := writeSwitchingProtocols(raw, protocol, acceptKey(key), extension)
	if writeErr != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("ws: write handshake response: %w", writeErr)
	}

	return u.finishRaw(raw, buf, protocol, extension), nil
}

// finishRaw assembles the upgraded raw connection: the frame codec on the
// hijacked stream with the negotiated session state and the
// permessage-deflate switch when the extension was granted. The caller
// wraps it in a [*Session] when the message-oriented view was asked for.
func (u *Upgrader) finishRaw(raw net.Conn, buf *bufio.ReadWriter, protocol string,
	extension string,
) *RawConn {
	conn := newRawConn(raw, buf.Reader, false, u.maxMessageSize, u.idleTimeout, u.writeTimeout)
	conn.subprotocol = protocol
	if extension != "" {
		conn.applyCompression()
		conn.compressLevel = u.compressLevel
	}

	return conn
}

// negotiateExtensions runs permessage-deflate negotiation when compression is
// enabled, returning the extension header value for the 101 response ("" when
// compression is off or declined) and an error if the offer is malformed.
func (u *Upgrader) negotiateExtensions(request *http.Request) (string, error) {
	if !u.compressEnabled {
		return "", nil
	}

	return negotiateCompression(splitExtensionGroups(request.Header))
}

// Handle returns an [http.Handler] that upgrades the request with u and then
// invokes handler, running the session for as long as the connection lives.
// When handler returns, the connection is closed with the code the return
// value says: a returned [*CloseError] closes with its code, nil closes
// normally (1000), and any other error — a policy failure, a transport
// error, a keepalive timeout — closes with 1011 (unexpected condition),
// because the session did not end normally. An out-of-range code on a
// returned *CloseError is remapped to 1002 so the connection is always torn
// down. An application close code must be a usable one — in 1000-4999 and
// not one of the codes that cannot appear on the wire (1004, 1005, 1006,
// 1015): a must-not-set code goes out as an empty payload, which the peer
// reads as a clean close (io.EOF from ReadMessage), so the application's
// code is lost. When the handler's error already tore the connection down (the
// common case for transport errors: ReadMessage fails and records the
// error), the recorded close wins and nothing more goes on the wire.
//
// The returned handler is ordinary: wrap it in further middleware as needed.
func (u *Upgrader) Handle(handler func(request *http.Request, c *Session) error) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := u.Upgrade(writer, request)
		if err != nil {
			return
		}

		closeAfterHandler(conn, handler(request, conn))
	})
}

// HandleRaw is [NewUpgrader].Handle for the raw protocol view: the handler
// receives a [*RawConn] and drives the protocol itself — the returned
// close-code mapping is the same as Handle's, because the connection's
// teardown is the same.
func (u *Upgrader) HandleRaw(handler func(request *http.Request, c *RawConn) error) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := u.UpgradeRaw(writer, request)
		if err != nil {
			return
		}

		closeAfterHandler(conn, handler(request, conn))
	})
}

// closeAfterHandler tears down the connection after a handler returns, the
// same way for the session and the raw view: a returned [*CloseError]
// closes with its code (an out-of-range code remapped to 1002, so the
// connection is always torn down), nil closes normally (1000), and any
// other error — a policy failure, a transport error, a keepalive timeout —
// closes with 1011 (unexpected condition), because the session did not end
// normally. When the handler's error already tore the connection down (the
// common case for transport errors: the read fails and records the error),
// the recorded close wins and nothing more goes on the wire.
func closeAfterHandler(conn interface {
	Close(code int, reason string) error
}, err error) {
	var closeErr *CloseError
	if ok := errors.As(err, &closeErr); ok {
		code := closeErr.Code
		if code < closeCodeMin || code > closeCodeMax {
			// An out-of-range code cannot go on the wire; tear down with
			// 1002 so the connection is always closed.
			_ = conn.Close(StatusProtocolError, "invalid close code from handler")

			return
		}
		_ = conn.Close(code, closeErr.Reason)

		return
	}
	if err == nil {
		_ = conn.Close(StatusNormalClosure, "")

		return
	}
	_ = conn.Close(StatusUnexpectedCondition, "handler failure")
}

// Handle is [NewUpgrader].Handle with the default upgrader, for the simple
// cases where no upgrader configuration is needed.
func Handle(handler func(r *http.Request, c *Session) error) http.Handler {
	return NewUpgrader().Handle(handler)
}

// HandleRaw is [NewUpgrader].HandleRaw with the default upgrader, for the
// simple cases where no upgrader configuration is needed.
func HandleRaw(handler func(r *http.Request, c *RawConn) error) http.Handler {
	return NewUpgrader().HandleRaw(handler)
}

// defaultCheckOrigin enforces strict same-origin on requests that carry an
// Origin header: it must equal the request's scheme and Host. Requests
// without an Origin are allowed: browsers always send Origin, while
// programmatic clients (this package's [Dial], curl, other libraries) usually
// do not, so rejecting them would bar plain clients out by default. A
// cross-origin browser is still rejected, because it always presents an
// Origin.
func defaultCheckOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}

	return origin == scheme+"://"+request.Host
}

// headerContainsToken reports whether header key holds token in any of its
// (comma-separated) values, case-insensitively, per the RFC 6455 handshake
// token checks.
func headerContainsToken(h http.Header, key, token string) bool {
	for _, value := range h[key] {
		for part := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}

	return false
}

// negotiateProtocol selects the subprotocol for a handshake from the
// server's advertised list and the client's Sec-WebSocket-Protocol request
// (RFC 6455 §1.9): the first advertised token the client also requested,
// or "" when there is no overlap — a handshake with no subprotocol is
// legal. An advertised token that is not a valid token (RFC 2616) is a
// misconfiguration the 101 must not echo onto the wire, so it fails the
// handshake.
func negotiateProtocol(server []string, clientHeader string) (string, error) {
	for _, advertised := range server {
		if !validSubprotocol(advertised) {
			return "", fmt.Errorf("%w: %q", errBadSubprotocol, advertised)
		}
		for requested := range strings.SplitSeq(clientHeader, ",") {
			if strings.TrimSpace(requested) == advertised {
				return advertised, nil
			}
		}
	}

	return "", nil
}

// deflateParams is one parsed permessage-deflate token's parameters
// (RFC 7692 §7.1), direction-neutral: each field records what the
// counterparty asked for or granted.
type deflateParams struct {
	// clientWindowBits is the client_max_window_bits value: 0 for absent or
	// value-less (no limit on the client's compressor), 8-15 when valued.
	clientWindowBits int
	// serverWindowBits is the server_max_window_bits value: 0 for absent,
	// 8-15 when present (always valued per the ABNF).
	serverWindowBits int
	clientNoTakeover bool
	serverNoTakeover bool
}

// splitExtensionGroups splits every extension header value into extension
// groups (one per extension, comma-separated within a value), reading both
// the RFC plural and the IANA singular header spellings (see
// extHeaderSingular). Whitespace around a group is trimmed; empty groups
// are dropped.
func splitExtensionGroups(header http.Header) []string {
	values := append(append([]string(nil),
		header[http.CanonicalHeaderKey(extHeaderSingular)]...),
		header[http.CanonicalHeaderKey(extHeaderPlural)]...)
	groups := []string{}
	for _, value := range values {
		for group := range strings.SplitSeq(value, ",") {
			if trimmed := strings.TrimSpace(group); trimmed != "" {
				groups = append(groups, trimmed)
			}
		}
	}

	return groups
}

// parseCompressionParams validates the parameters of one permessage-deflate
// group and returns their meaning. Any malformed or unknown parameter — a
// value on a value-less parameter, a non-decimal or out-of-range window,
// a leading zero, a duplicate — is a protocol error; callers map it to a
// failed handshake.
func parseCompressionParams(group string) (deflateParams, error) {
	parts := strings.Split(group, ";")
	var params deflateParams
	seen := make(map[string]bool, truncateOctets)
	for i, raw := range parts {
		param := strings.TrimSpace(raw)
		if param == "" {
			return params, fmt.Errorf("%w: empty parameter in %q", errBadExtension, group)
		}
		if i == 0 {
			continue // the extension name; validated by the caller
		}
		key, value, hasValue := strings.Cut(param, "=")
		if seen[key] {
			return params, fmt.Errorf("%w: duplicate parameter %q", errBadExtension, key)
		}
		seen[key] = true
		switch key {
		case "client_no_context_takeover", "server_no_context_takeover":
			if hasValue {
				return params, fmt.Errorf("%w: %q must have no value", errBadExtension, key)
			}
			if key == "client_no_context_takeover" {
				params.clientNoTakeover = true
			} else {
				params.serverNoTakeover = true
			}
		case "client_max_window_bits":
			if hasValue {
				bits, err := parseWindowBits(value)
				if err != nil {
					return params, err
				}
				params.clientWindowBits = bits
			}
		case "server_max_window_bits":
			if !hasValue {
				return params, fmt.Errorf("%w: %q requires a value", errBadExtension, key)
			}
			bits, err := parseWindowBits(value)
			if err != nil {
				return params, err
			}
			params.serverWindowBits = bits
		default:

			return params, fmt.Errorf("%w: unknown parameter %q", errBadExtension, key)
		}
	}

	return params, nil
}

// parseWindowBits validates a max_window_bits value: decimal, no leading
// zeroes, 8-15 (RFC 7692 §7.1.2).
func parseWindowBits(value string) (int, error) {
	if len(value) > 1 && value[0] == '0' {
		return 0, fmt.Errorf("%w: leading zero in window bits %q", errBadExtension, value)
	}
	bits, err := strconv.Atoi(value)
	if err != nil || bits < 8 || bits > maxWindowBits {
		return 0, fmt.Errorf("%w: window bits out of range in %q", errBadExtension, value)
	}

	return bits, nil
}

// negotiateCompression decides the server's response to a client's
// Sec-WebSocket-Extension offer and returns the header value for the 101
// response ("" = no extension: the connection runs uncompressed).
//
// A malformed offer — an unrecognized extension (RFC 6455 §9.1), permessage-
// deflate offered twice, or an invalid parameter — fails the handshake. An
// offer that is well-formed but demands a smaller compressor window than
// this implementation can use (server_max_window_bits below the full 15
// bits) is declined (RFC 7692 §7.1.2.1): the response carries no extension
// and the connection proceeds uncompressed.
func negotiateCompression(groups []string) (string, error) {
	if len(groups) == 0 {
		return "", nil // no extension offered; the connection runs uncompressed
	}
	declined := false
	for idx, group := range groups {
		name, _, _ := strings.Cut(group, ";")
		name = strings.TrimSpace(name)
		if !strings.EqualFold(name, extPerMessageDeflate) {
			return "", fmt.Errorf("%w: unsupported extension %q", errBadExtension, name)
		}
		params, err := parseCompressionParams(group)
		if err != nil {
			return "", err
		}
		if idx > 0 {
			return "", fmt.Errorf("%w: offered more than once", errBadExtension)
		}
		// Our compressor always uses the full 32 KiB window, so a limit
		// below 15 bits cannot be honored: decline, per the doc comment.
		if bits := params.serverWindowBits; bits != 0 && bits < maxWindowBits {
			declined = true
		}
	}
	if declined {
		return "", nil
	}

	return deflateResponseHeader, nil
}

// verifyCompressionResponse validates the Sec-WebSocket-Extension header
// of a 101 response against what this client offered (RFC 7692 §5.1): the
// server must not select an extension the client never offered, must select
// permessage-deflate at most once, and must not demand more of the client's
// compressor than the client's capability — a response that caps the
// client window below the full 15 bits fails the dial, because the stdlib
// compressor cannot honor it. It reports whether compression was negotiated.
func verifyCompressionResponse(offered bool, groups []string) (bool, error) {
	if !offered && len(groups) > 0 {
		return false, fmt.Errorf("%w: 101 response selected the unoffered extension %q",
			errHandshakeFailed, strings.Join(groups, ", "))
	}
	if len(groups) == 0 {
		return false, nil // the server declined; the connection runs uncompressed
	}
	if len(groups) > 1 {
		return false, fmt.Errorf("%w: 101 response selected multiple extensions %q",
			errHandshakeFailed, strings.Join(groups, ", "))
	}
	params, err := parseCompressionParams(groups[0])
	if err != nil {
		return false, err
	}
	name, _, _ := strings.Cut(groups[0], ";")
	name = strings.TrimSpace(name)
	if !strings.EqualFold(name, extPerMessageDeflate) {
		return false, fmt.Errorf("%w: 101 response selected the unoffered extension %q",
			errHandshakeFailed, name)
	}
	if bits := params.clientWindowBits; bits != 0 && bits < maxWindowBits {
		return false, fmt.Errorf("%w: 101 response caps the client window at %d bits",
			errHandshakeFailed, bits)
	}

	return true, nil
}

// subprotocolSeparators are the RFC 2616 separator characters a subprotocol
// token may not contain (RFC 6455 §1.9 defines the header value as 1#token).
// Control characters, space, and DEL fall outside the token's U+0021..U+007E
// range and are checked separately.
const subprotocolSeparators = "()<>@,;:\"/[]?{}=\\"

// validSubprotocol reports whether s is a valid subprotocol token: printable
// US-ASCII (U+0021..U+007E) minus the RFC 2616 separator characters
// (RFC 6455 §1.9, 1#token). A token containing one of them would corrupt
// the Sec-WebSocket-Protocol header — a comma would split the value into
// several tokens.
func validSubprotocol(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r >= 0x7f || strings.ContainsRune(subprotocolSeparators, r) {
			return false
		}
	}

	return true
}

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 4 · Client entry: dialing

// wsGUID is the magic GUID from RFC 6455 §1.3.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec

	return base64.StdEncoding.EncodeToString(sum[:])
}

// dialTransport connects to host on the default transport: plain TCP for
// ws:// URLs and TLS with the system root store for wss:// URLs (the SNI
// server name falls back to the host the connection dialed). Custom
// transport policy — custom root stores, client certificates, proxy
// tunnels — goes through [WithDialer], which replaces this entirely.
func dialTransport(ctx context.Context, host string, isTLS bool) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("ws: dial %s: %w", host, err)
	}
	if isTLS {
		tconn := tls.Client(conn, nil)
		handshakeErr := tconn.HandshakeContext(ctx)
		if handshakeErr != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("ws: tls handshake: %w", handshakeErr)
		}
		conn = tconn
	}

	return conn, nil
}

// defaultDialConfig is the Config a [Dial] starts from before the caller's
// options are applied. Defaults run before the options so an explicit
// WithXxx(0) is preserved: WithIdleTimeout(0) disables keepalive, and
// WithWriteTimeout(0) removes the write bound. Compression is offered by
// default, matching the browser and Node ws clients.
func defaultDialConfig() *Config {
	return &Config{
		Headers:          make(http.Header),
		MaxMessageSize:   defaultMaxMessageSize,
		IdleTimeout:      defaultIdleTimeout,
		WriteTimeout:     defaultWriteTimeout,
		Compression:      true,
		CompressionLevel: flate.DefaultCompression,
	}
}

// dialTarget resolves the dial parameters for a ws/wss URL: the tcp
// target with the scheme's default port filled in, the request path, the
// parsed URL (for [WithDialer]), and whether the connection is TLS. A
// malformed URL, a non-ws scheme, or a missing host is an error before any
// network I/O. Port detection uses [url.URL.Port], so a bracketed IPv6
// literal without a port (ws://[::1]/) gets the default port too.
func dialTarget(rawurl string) (string, string, bool, *url.URL, error) {
	parsed, err := url.Parse(rawurl)
	if err != nil {
		return "", "", false, nil, fmt.Errorf("%w %q: %w", errBadURL, rawurl, err)
	}
	isTLS := parsed.Scheme == wssScheme
	if parsed.Scheme != wsScheme && parsed.Scheme != wssScheme {
		return "", "", false, nil, fmt.Errorf("%w: %q", errBadScheme, parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", "", false, nil, fmt.Errorf("%w %q: no host", errBadURL, rawurl)
	}
	host := parsed.Host
	if parsed.Port() == "" {
		// Port detection goes through url.URL.Port, not a colon search:
		// a bracketed IPv6 literal (ws://[::1]/) has colons in the host and
		// no port, and the default port belongs on the outside.
		// JoinHostPort adds the colon itself, so strip the constant's.
		defaultPort := wsDefaultPort[1:]
		if isTLS {
			defaultPort = wssDefaultPort[1:]
		}

		host = net.JoinHostPort(parsed.Hostname(), defaultPort)
	}

	return host, parsed.RequestURI(), isTLS, parsed, nil
}

// Dial opens a WebSocket client connection to rawurl (ws:// or wss://) and
// returns an open [*Session] whose read state is owned by the calling
// goroutine. For the raw protocol view — every ping, pong, and close as an
// event, no automatic pong, fragmented writes — use [DialRaw].
//
// The server's subprotocol selection is verified (RFC 6455 §1.9): the 101
// response may select none, or exactly one of the subprotocols this client
// offered. A selection the client never offered — or several at once —
// fails the dial, because a server that chooses a protocol on its own
// cannot be trusted with the protocol negotiation.
//
// When [WithCompression] is enabled (the default), the client offers
// permessage-deflate and verifies the response with the same discipline:
// the extension may be declined, or accepted with at most the client's own
// constraints — anything else fails the dial.
func Dial(ctx context.Context, rawurl string, opts ...Option) (*Session, error) {
	raw, cfg, err := dialConn(ctx, rawurl, opts...)
	if err != nil {
		return nil, err
	}

	return newSession(raw, cfg.pongHandler), nil
}

// DialRaw opens a raw WebSocket client connection to rawurl (ws:// or
// wss://), exactly as [Dial], and returns a [*RawConn]: every ping, pong,
// and close the peer sends arrives as an [Event] from
// [RawConn.ReadEvent], nothing is hidden, and writes can be fragmented with
// [RawConn.WriteFrame].
//
// Two defaults differ from [Dial], because a protocol implementer owns the
// control traffic: keepalive probes are off (no idle timeout is armed) —
// set [WithIdleTimeout] to enable them; the probe's answer then arrives as
// an OpPong event — and pings are never answered automatically: by RFC
// 6455 §5.5.3 you are the responder, with [RawConn.Pong]. A [WithPongHandler]
// is ignored: pongs are events, not a callback.
//
// Everything else — subprotocol verification, compression negotiation, the
// compliance rules the raw view cannot opt out of (masking, close-code
// table, UTF-8, the message size limit) — is exactly [Dial]'s.
func DialRaw(ctx context.Context, rawurl string, opts ...Option) (*RawConn, error) {
	cfg := defaultDialConfig()
	cfg.IdleTimeout = 0 // raw: no keepalive probes unless asked for
	for _, apply := range opts {
		apply(cfg)
	}
	sanitizeLimits(cfg)
	raw, _, err := dialConnWith(ctx, rawurl, cfg)

	return raw, err
}

// dialConn dials and performs the handshake, returning the raw connection
// and the resolved config. The default idle timeout keeps the session
// keepalive; the caller builds the session view on top.
func dialConn(ctx context.Context, rawurl string, opts ...Option) (*RawConn, *Config, error) {
	cfg := defaultDialConfig()
	for _, apply := range opts {
		apply(cfg)
	}
	sanitizeLimits(cfg)

	return dialConnWith(ctx, rawurl, cfg)
}

func dialConnWith(ctx context.Context, rawurl string, cfg *Config) (*RawConn, *Config, error) {
	host, path, isTLS, target, err := dialTarget(rawurl)
	if err != nil {
		return nil, nil, err
	}
	if d := cfg.dialTimeout; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}

	var conn net.Conn
	if cfg.dialer != nil {
		conn, err = cfg.dialer(ctx, target)
	} else {
		conn, err = dialTransport(ctx, host, isTLS)
	}
	if err != nil {
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		// Bound the handshake on the fresh connection, whether the transport
		// is the default one or [WithDialer]'s; cleared below once the
		// handshake succeeds, so the session is governed by its own
		// deadlines from there on.
		_ = conn.SetDeadline(deadline)
	}

	reader := bufio.NewReaderSize(conn, bufSize)
	key, reqErr := writeHandshakeRequest(conn, path, host,
		cfg.Subprotocols, cfg.Compression, cfg.Headers)
	if reqErr != nil {
		_ = conn.Close()

		return nil, nil, reqErr
	}
	subprotocol, compressed, respErr := readHandshakeResponse(reader, key, cfg.Subprotocols, cfg.Compression)
	if respErr != nil {
		_ = conn.Close()

		return nil, nil, respErr
	}

	// The handshake is done; clear the connect deadline so the session is
	// governed by its own read/write deadlines and keepalive from here on.
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Time{})

	raw := newRawConn(conn, reader, true, cfg.MaxMessageSize, cfg.IdleTimeout, cfg.WriteTimeout)
	raw.subprotocol = subprotocol
	if compressed {
		raw.applyCompression()
		raw.compressLevel = cfg.CompressionLevel
	}

	return raw, cfg, nil
}

// writeHandshakeRequest writes the client's opening HTTP request to conn and
// returns the Sec-WebSocket-Key it used, for verifying the server's
// response later.
func writeHandshakeRequest(conn io.Writer, path, host string, subprotocols []string,
	compression bool, headers http.Header,
) (string, error) {
	keyBytes := make([]byte, wsKeyBytes)
	_, randErr := rand.Read(keyBytes)
	if randErr != nil {
		return "", fmt.Errorf("ws: generate key: %w", randErr)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	var req bytes.Buffer
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\n", path, host)
	req.WriteString("Upgrade: websocket\r\n")
	req.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&req, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(&req, "Sec-WebSocket-Version: %s\r\n", websocketVer)
	if len(subprotocols) > 0 {
		for _, subprotocol := range subprotocols {
			if !validSubprotocol(subprotocol) {
				return "", fmt.Errorf("%w: %q", errBadSubprotocol, subprotocol)
			}
		}
		fmt.Fprintf(&req, "Sec-WebSocket-Protocol: %s\r\n", strings.Join(subprotocols, ", "))
	}
	if compression {
		req.WriteString("Sec-WebSocket-Extensions: " + deflateResponseHeader + "\r\n")
	}
	for headerKey, values := range headers {
		switch {
		case strings.EqualFold(headerKey, "Host"), strings.EqualFold(headerKey, "Upgrade"),
			strings.EqualFold(headerKey, "Connection"),
			strings.EqualFold(headerKey, "Sec-WebSocket-Key"),
			strings.EqualFold(headerKey, "Sec-WebSocket-Version"),
			strings.EqualFold(headerKey, "Sec-WebSocket-Protocol"),
			strings.EqualFold(headerKey, extHeaderPlural),
			strings.EqualFold(headerKey, extHeaderSingular):
			continue
		}
		if strings.ContainsAny(headerKey, "\r\n") {
			return "", fmt.Errorf("%w: %s contains a line break", errBadHeader, headerKey)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return "", fmt.Errorf("%w: %s value contains a line break", errBadHeader, headerKey)
			}
			fmt.Fprintf(&req, "%s: %s\r\n", headerKey, value)
		}
	}
	req.WriteString("\r\n")
	_, writeErr := conn.Write(req.Bytes())
	if writeErr != nil {
		return "", fmt.Errorf("ws: write handshake: %w", writeErr)
	}

	return key, nil
}

// readHandshakeResponse reads and verifies the server's 101 response,
// returning the negotiated subprotocol and whether permessage-deflate was
// negotiated.
func readHandshakeResponse(reader *bufio.Reader, key string, offered []string,
	compressionOffered bool,
) (string, bool, error) {
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return "", false, fmt.Errorf("ws: read handshake response: %w", err)
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return "", false, fmt.Errorf("%w: server replied %s", errHandshakeFailed, resp.Status)
	}
	// RFC 6455 §4.1: the 101 must carry the websocket upgrade tokens.
	if !headerContainsToken(resp.Header, "Upgrade", "websocket") ||
		!headerContainsToken(resp.Header, "Connection", "Upgrade") {
		return "", false, fmt.Errorf("%w: 101 response missing the upgrade headers", errHandshakeFailed)
	}
	// The 101 carries exactly one accept value: a second line would leave
	// the accept key ambiguous (§4.1).
	accepts := resp.Header.Values("Sec-WebSocket-Accept")
	if len(accepts) != 1 {
		return "", false, fmt.Errorf("%w: 101 response carried %d Sec-WebSocket-Accept values",
			errHandshakeFailed, len(accepts))
	}
	if accepts[0] != acceptKey(key) {
		return "", false, fmt.Errorf("%w: invalid Sec-WebSocket-Accept %q", errHandshakeFailed, accepts[0])
	}

	// As on the server, every protocol line shares one 1#token value
	// space, so all lines count against the §1.9 echo check.
	subprotocol := strings.Join(resp.Header.Values("Sec-WebSocket-Protocol"), ", ")
	echoErr := checkSubprotocolEcho(offered, subprotocol)
	if echoErr != nil {
		return "", false, echoErr
	}
	compressed, extErr := verifyCompressionResponse(compressionOffered, splitExtensionGroups(resp.Header))
	if extErr != nil {
		return "", false, extErr
	}

	return subprotocol, compressed, nil
}

// checkSubprotocolEcho validates the Sec-WebSocket-Protocol header of the
// 101 response against the subprotocols the client offered (RFC 6455
// §1.9): the server selects none (no header), or exactly one of the
// offered tokens. Conversely, several selections, or a token the client
// never offered, fail the handshake. Every offered token was already validated
// by [validSubprotocol] before it went on the wire, so membership in the
// offered list implies a valid token.
func checkSubprotocolEcho(offered []string, echoed string) error {
	selected := ""
	for token := range strings.SplitSeq(echoed, ",") {
		if selected != "" {
			return fmt.Errorf("%w: 101 response selected multiple subprotocols %q",
				errHandshakeFailed, echoed)
		}
		selected = strings.TrimSpace(token)
	}
	if selected == "" {
		return nil // the server selected no subprotocol
	}
	if !slices.Contains(offered, selected) {
		return fmt.Errorf("%w: 101 response selected the unoffered subprotocol %q",
			errHandshakeFailed, selected)
	}

	return nil
}

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 5 · The raw face: RawConn, the protocol as an event stream

const (
	stOpen int32 = iota
	stClosed
)

//nolint:gochecknoglobals // monotonic per-process sequence for RawConn.ID
var connSeq atomic.Uint64

// RawConn is a raw WebSocket connection: the RFC 6455 protocol as an
// event stream, with no policy layer above it.
//
// RawConn is the core of the package, and [Session] is built on it:
// Session runs the same read loop and consumes the control events the
// message-oriented application never wants. Use RawConn (via [DialRaw] or
// [Upgrader.UpgradeRaw]) when you are implementing a protocol on
// WebSockets and want to see and drive the control traffic yourself —
// every ping and every pong arrives as an [Event], the peer's close
// arrives as an OpClose event carrying its code and reason, and writes
// can be fragmented frame by frame with [RawConn.WriteFrame]. Use
// [Session] (via [Dial] or [Upgrader.Upgrade]) for ordinary
// message-oriented traffic.
//
// What RawConn does not do, by design: it never answers a ping for you —
// you are the responder ([RawConn.Pong]) — and, when produced by
// [DialRaw], it sends no keepalive probes unless an idle timeout was set
// with [WithIdleTimeout] (the probe's answer then arrives as an OpPong
// event). What RawConn cannot not do, because the RFC and the security
// invariants require it: mask client frames, enforce the close-code table,
// enforce UTF-8 on text (1007) and the message size limit, reassemble
// fragmented data messages, and close the connection on a protocol
// violation (answered with 1002 per RFC 6455 §7.1.7) or a transport
// failure. [RawConn.ReadEvent] is the single read loop; like
// [Session.ReadMessage] it must only be called from one goroutine at a
// time. Every write and [RawConn.Close] is safe from any goroutine.
type RawConn struct {
	nc net.Conn
	fc frameCodec
	mu sync.Mutex // serializes the write path

	id          uint64
	subprotocol string

	state    atomic.Int32 // stOpen or stClosed
	closeErr error        // valid once state == stClosed; guarded by c.mu

	idleTimeout  time.Duration
	writeTimeout time.Duration
	lastActivity time.Time
	// probedSinceLastActivity and probeAt are keepalive probe state, touched
	// only by the reading goroutine. After a silence timeout the connection
	// pings once (probeAt records when); a second silence timeout without
	// any activity in between means the peer is dead.
	probedSinceLastActivity bool
	probeAt                 time.Time

	inFrag         bool
	fragOp         Op
	fragBuf        []byte
	fragCompressed bool // assembled message is a compressed (RFC 7692) payload

	// permessage-deflate (RFC 7692): deflateNegotiated is set once, after
	// the handshake, by both sides; the compressor is write-path state
	// (owned by c.mu) and the decompressor is read-path state (owned by the
	// pumping goroutine), so each direction's scratch is exactly as isolated
	// as the frame codec's read/write scratch.
	deflateNegotiated bool
	compressLevel     int // flate level, as configured; defaults come from Config

	// Write-side scratch, touched under c.mu only: the deflate writer and
	// the buffer it fills, lazily created on the first compressed message.
	deflater    *flate.Writer
	compressBuf *bytes.Buffer

	// fragWriting is write-path fragmentation state, under c.mu: set while
	// a WriteFrame sequence with more=true is in progress, so a
	// continuation frame can only follow a start frame this connection
	// sent (RFC 6455 §5.4).
	fragWriting bool

	// Read-side scratch, touched by the pumping goroutine only: the
	// re-used decompressor ([flate.Resetter]) and its output, lazily
	// created on the first compressed message.
	inflateSrc   *bytes.Reader
	inflater     io.ReadCloser  // flate.NewReader result, read and closed
	inflaterRst  flate.Resetter // the same object, used to reset per message
	inflateBuf   *bytes.Buffer
	inflateLimit inflateGuard // bounds the decompressed output at maxMessageSize
	inflateCopy  []byte       // io.CopyBuffer scratch, sized once
	inflateWire  []byte       // payload + the four RFC bytes, grown to the largest message
}

func newRawConn(conn net.Conn, stream io.Reader, isClient bool, maxMessageSize int64,
	idleTimeout, writeTimeout time.Duration,
) *RawConn {
	var reader *bufio.Reader
	if existing, ok := stream.(*bufio.Reader); ok {
		reader = existing
	} else {
		reader = bufio.NewReaderSize(stream, bufSize)
	}

	return &RawConn{
		nc: conn,
		fc: frameCodec{
			br:       reader,
			bw:       bufio.NewWriterSize(conn, bufSize),
			isClient: isClient,
			maxMsg:   maxMessageSize,
		},
		id:           connSeq.Add(1),
		idleTimeout:  idleTimeout,
		writeTimeout: writeTimeout,
		lastActivity: time.Now(),
	}
}

// Event is one protocol event delivered by [RawConn.ReadEvent]: a control
// frame (each ping, each pong, the peer's close) or a complete data
// message. The fields are populated per Op:
//
//   - OpText / OpBinary: Payload is the reassembled, decompressed message;
//     Code and Reason are zero.
//   - OpPing / OpPong: Payload is the control-frame payload; Code and
//     Reason are zero.
//   - OpClose: Code is the resolved close code (StatusNoStatusReceived
//     for a payload-less close) and Reason the reason text; Payload is
//     nil. The connection is already replying to the close and tearing
//     down: the next ReadEvent returns the terminal error.
type Event struct {
	Op      Op
	Payload []byte
	Code    int
	Reason  string
}

// ReadEvent reads the next protocol event from the connection, in wire
// order, and delivers it unmodified: every ping, every pong, every close
// (with its resolved code and reason), and each complete data message
// carrying its op-type.
//
// ReadEvent is the policy-free core of the package: it enforces the RFC
// 6455 compliance rules — masking, the close-code table, UTF-8 on text
// (1007), the message size limit, RFC 7692 §6 reserved bits — and answers
// them where the RFC mandates an answer (a close frame is always replied
// to, a protocol violation is answered with a 1002 close frame, RFC
// 6455 §7.1.7) — but it does no application policy. It never answers a
// ping on the application's behalf, never sends a keepalive probe unless
// an idle timeout was configured, and never hides a frame: pongs the peer
// sends are events, not something that disappears. The [Session] type is
// the policy layer on top: its [Session.ReadMessage] runs this same loop
// and consumes the control events the message-oriented application never
// wants.
//
// A received ping is the application's to answer: by RFC 6455 §5.5.3 a
// peer that receives a ping must answer with a pong, and the answer is
// [RawConn.Pong] — call it from the read loop or another goroutine, with
// any payload you like (the RFC says the echo; your protocol may use the
// payload for its own correlation). If nobody answers, the peer's own
// keepalive will eventually declare the connection dead.
//
// Errors: a close frame from the peer is the OpClose event, after which
// the next ReadEvent returns the terminal error — [io.EOF] for a normal
// closure (1000, or a close frame without a status), a [*CloseError]
// otherwise. A protocol violation or an over-limit or corrupt data
// message is a terminal error that already closed the transport, as is a
// transport failure or an idle-timeout expiry.
//
// ReadEvent must only be called from one goroutine at a time.
func (c *RawConn) ReadEvent() (Event, error) {
	if c.state.Load() == stClosed {
		c.mu.Lock()
		closeErr := c.closeErr
		c.mu.Unlock()

		return Event{}, terminalErr(closeErr)
	}
	for {
		frm, readErr := c.readNextFrame()
		if readErr != nil {
			return Event{}, readErr
		}
		// Clear the keepalive deadline; a zero idle timeout never armed one,
		// so skip the call when keepalive is disabled.
		if c.idleTimeout > 0 {
			_ = c.nc.SetReadDeadline(time.Time{})
		}
		c.lastActivity = time.Now()
		c.probedSinceLastActivity = false

		// RFC 7692 §6: the "compressed" bit is reserved for data messages —
		// a control frame that carries it is a protocol violation.
		ctrlErr := c.checkCompressedControl(frm)
		if ctrlErr != nil {
			return Event{}, ctrlErr
		}

		switch frm.opcode {
		case OpPing, OpPong:
			return Event{Op: frm.opcode, Payload: frm.payload}, nil
		case OpClose:
			code, reason, closeErr := c.resolvePeerClose(frm.payload)
			if closeErr != nil {
				return Event{}, closeErr
			}
			// The close is resolved: reply with the same code and finish,
			// then deliver the event; the next ReadEvent reports the
			// terminal error the finish recorded.
			_ = c.Close(code, reason)
			_ = c.finish(closeErrFor(code, reason))

			return Event{Op: OpClose, Code: code, Reason: reason}, nil
		case OpText, OpBinary, OpContinuation:
			msgOp, payload, complete, dataErr := c.readData(frm)
			if dataErr != nil {
				return Event{}, c.finish(dataErr)
			}
			if !complete {
				continue
			}

			return Event{Op: msgOp, Payload: payload}, nil
		default:
			return Event{}, c.failProtocol(fmt.Sprintf("unknown opcode %d", frm.opcode))
		}
	}
}

// readNextFrame reads one frame, resolving read errors against the
// keepalive clock: a silence timeout that still allows a probe ping
// re-arms and retries; a frame-level protocol violation (masking, RSV,
// malformed or oversized header) is answered with a 1002 close frame
// before the transport is torn down (RFC 6455 §7.1.7), so the peer sees
// a close frame rather than a bare TCP close; a transport error or a
// silence timeout that killed the connection is terminal.
func (c *RawConn) readNextFrame() (frame, error) {
	for {
		armErr := c.armIdle()
		if armErr != nil {
			return frame{}, c.finish(armErr)
		}
		frm, err := c.fc.readFrame()
		if err == nil {
			return frm, nil
		}
		retry, connErr := c.keepaliveTimeout(err)
		if retry {
			continue
		}
		if errors.Is(connErr, errProtocol) {
			return frame{}, c.failProtocol(
				strings.TrimPrefix(connErr.Error(), errProtocol.Error()+": "))
		}

		return frame{}, c.finish(connErr)
	}
}

// readData assembles one data message from a frame and, when the message is
// compressed, expands it. It returns the message opcode and payload; complete
// reports whether a possibly fragmented message has ended. A decompression
// failure (a corrupt or oversized payload) is returned as the error.
func (c *RawConn) readData(frm frame) (Op, []byte, bool, error) {
	msgOp, payload, complete, compressed, msgErr := c.handleData(frm)
	if msgErr != nil {
		return 0, nil, false, msgErr
	}
	if !complete {
		return 0, nil, false, nil
	}
	out := payload
	if compressed {
		c.fragCompressed = false
		expanded, err := c.decompress(payload)
		if err != nil {
			return 0, nil, false, err
		}

		out = expanded
	}
	if msgOp == OpText && !utf8.Valid(out) {
		// RFC 6455 §5.6: a peer MUST close on a non-UTF-8 text frame; 1007
		// is the close the browser implementations assign to exactly this.
		// Close records the error, so the finish in the read loop reports
		// it.
		_ = c.Close(StatusInvalidDataType, "text message is not valid UTF-8")

		return 0, nil, false, fmt.Errorf("%w: text message is not valid UTF-8", errProtocol)
	}

	return msgOp, out, true, nil
}

// handleData processes one data or continuation frame. It returns complete
// when the message is finished — a single-frame message, or the final
// fragment — and compressed when that finished message arrived as a
// compressed (RFC 7692) payload (RSV1 on the first frame only); it holds
// the partial message in the connection otherwise.
func (c *RawConn) handleData(frm frame) (Op, []byte, bool, bool, error) {
	if frm.opcode == OpContinuation {
		if frm.compressed {
			return 0, nil, false, false, fmt.Errorf("%w: permessage-deflate bit set on a continuation frame", errProtocol)
		}
		if !c.inFrag {
			return 0, nil, false, false, fmt.Errorf("%w: continuation frame without start", errProtocol)
		}
		if int64(len(c.fragBuf)+len(frm.payload)) > c.fc.maxMsg {
			c.inFrag, c.fragBuf, c.fragCompressed = false, nil, false

			return 0, nil, false, false, fmt.Errorf("%w: %w", errProtocol, errMessageTooBig)
		}
		c.fragBuf = append(c.fragBuf, frm.payload...)
		if !frm.fin {
			return 0, nil, false, false, nil
		}

		opcode, data, compressed := c.fragOp, c.fragBuf, c.fragCompressed
		c.inFrag, c.fragBuf, c.fragCompressed = false, nil, false

		return opcode, data, true, compressed, nil
	}
	// OpText or OpBinary.
	if c.inFrag {
		return 0, nil, false, false, fmt.Errorf("%w: data frame while message is in progress",
			errProtocol)
	}
	if !frm.fin {
		c.inFrag, c.fragOp, c.fragBuf, c.fragCompressed = true, frm.opcode, frm.payload, frm.compressed

		return 0, nil, false, false, nil
	}

	return frm.opcode, frm.payload, true, frm.compressed, nil
}

// checkCompressedControl enforces RFC 7692 §6: the compressed (RSV1) bit is
// reserved for data messages, so a control frame that carries it is a
// protocol violation that terminates the connection.
func (c *RawConn) checkCompressedControl(frm frame) error {
	if frm.compressed && frm.isControl() {
		return c.failProtocol("permessage-deflate bit set on a control frame")
	}

	return nil
}

// keepaliveTimeout processes a read error against the keepalive clock. It
// returns retry=true when a probe ping was sent and the read loop should
// continue; otherwise it returns the connection error (transport error, or
// the silence timeout that killed the connection).
func (c *RawConn) keepaliveTimeout(err error) (bool, error) {
	if !isReadTimeout(err) {
		return false, err
	}
	if probeDecision(c.probedSinceLastActivity) == probeKill {
		return false, err
	}
	c.probedSinceLastActivity = true
	c.probeAt = time.Now()
	// The ping write carries the write-timeout bound (see RawConn.writeFrame),
	// so a blackholed transport cannot wedge the read loop here.
	pingErr := c.writeFrame(OpPing, nil, false)
	if pingErr != nil {
		return false, pingErr
	}

	return true, nil // armIdle re-arms with the grace window (probeAt + idle)
}

// armIdle arms the read deadline for the next blocking read: the point at
// which the connection has been silent long enough to probe for liveness
// (see ReadMessage). It sends no ping itself — the probe is issued in the
// timeout path, only when silence is actually observed. While a probe is
// outstanding the deadline is one full window past the probe, giving the
// peer time to answer.
func (c *RawConn) armIdle() error {
	if c.idleTimeout <= 0 {
		return nil
	}
	deadline := c.lastActivity.Add(c.idleTimeout)
	if c.probedSinceLastActivity {
		deadline = c.probeAt.Add(c.idleTimeout)
	}

	return c.nc.SetReadDeadline(deadline)
}

// probeAction is the keepalive response to a read timeout, which can only
// fire once silence has reached the idle threshold.
type probeAction int

const (
	probePing probeAction = iota // first timeout: probe liveness with a ping
	probeKill                    // second timeout: the peer never answered
)

// probeDecision decides the keepalive response to a silence timeout. The
// first timeout probes with a ping: a live peer pongs, and a reset
// connection often fails the ping write outright, both of which settle the
// question faster than a second full window of waiting. If the connection
// times out again without any activity, the peer is considered dead.
func probeDecision(probedOnce bool) probeAction {
	if probedOnce {
		return probeKill
	}

	return probePing
}

// isReadTimeout reports whether err is a read-deadline timeout, as opposed
// to a transport error or EOF.
func isReadTimeout(err error) bool {
	var nerr net.Error

	return errors.As(err, &nerr) && nerr.Timeout()
}

// resolvePeerClose validates a close frame received from the peer and
// returns its resolved close code and reason — or the protocol failure,
// when the payload is unusable. The caller ([RawConn.ReadEvent]) replies
// with the same code and tears the connection down; resolving is kept
// apart from tearing down because the raw read delivers the close as an
// event before reporting the terminal error.
//
// A close frame without a payload closes normally (1005 "no status"). A
// payload must carry a usable status code — in 1000-4999, not one of the
// codes that MUST NOT be set on the wire (1005, 1006, 1015), and not the
// reserved 1004 (RFC 6455 §7.4) — or the connection is failed with 1002
// (§7.1.5); an unusable code is never echoed back.
func (c *RawConn) resolvePeerClose(payload []byte) (int, string, error) {
	if len(payload) == 1 {
		return 0, "", c.failProtocol("close frame with one-byte payload")
	}
	if len(payload) >= closeCodeBytes {
		code := int(binary.BigEndian.Uint16(payload[:closeCodeBytes]))
		if !usableCloseCode(code) {
			return 0, "", c.failProtocol(fmt.Sprintf("close frame with unusable status code %d", code))
		}

		return code, string(payload[closeCodeBytes:]), nil
	}

	// len(payload) == 0: no status received; closes normally.
	return StatusNoStatusReceived, "", nil
}

// mustNotSetCloseCode reports whether code may not appear as a status code
// in a close frame payload. 1005, 1006, and 1015 MUST NOT be set (RFC 6455
// §7.4); 1004 is reserved there and is treated as unusable as well. Such
// codes go out with an empty payload, and a close frame received with one
// is a protocol error.
func mustNotSetCloseCode(code int) bool {
	switch code {
	case closeCodeUnexpected, StatusNoStatusReceived, StatusAbnormalClosure, closeCodeTLSFailure:
		return true
	}

	return false
}

// usableCloseCode reports whether code is a usable status code in a close
// frame payload: in 1000-4999 and not must-not-set or reserved (see
// mustNotSetCloseCode).
func usableCloseCode(code int) bool {
	return code >= closeCodeMin && code <= closeCodeMax && !mustNotSetCloseCode(code)
}

// truncateReason bounds a close reason to the on-wire limit, backing off to
// a UTF-8 rune boundary so the truncated reason stays valid UTF-8.
func truncateReason(reason string) string {
	if len(reason) <= maxCloseReason {
		return reason
	}
	n := maxCloseReason
	for n > 0 && !utf8.RuneStart(reason[n]) {
		n--
	}

	return reason[:n]
}

// failProtocol tears the connection down with 1002 (protocol error) and
// returns the violation for ReadMessage to report.
func (c *RawConn) failProtocol(what string) error {
	err := fmt.Errorf("%w: %s", errProtocol, what)
	_ = c.Close(StatusProtocolError, what)

	return c.finish(err)
}

// opcodeName is the human-readable name of an opcode for error messages.
func opcodeName(opcode Op) string {
	switch opcode {
	case OpContinuation:
		return "continuation"
	case OpText:
		return "text"
	case OpBinary:
		return "binary"
	case OpClose:
		return "close"
	case OpPing:
		return "ping"
	case OpPong:
		return "pong"
	default:
		return fmt.Sprintf("opcode %d", opcode)
	}
}

// closedWriteErr is the error a write path returns for a closed
// connection: the recorded close error when there is one, ErrClosed for a
// normal closure.
func (c *RawConn) closedWriteErr() error {
	if c.closeErr != nil {
		return c.closeErr
	}

	return ErrClosed
}

// writeFrame writes a frame, taking the write lock. It serves every frame
// write on the connection — data frames ([RawConn.WriteMessage]), the
// automatic pong and keepalive ping, and the close frame ([RawConn.Close]) —
// each of which validates its own use. A closed connection yields
// [RawConn.closedWriteErr], never a silent success.
func (c *RawConn) writeFrame(opcode Op, payload []byte, compressed bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Load() == stClosed {
		return c.closedWriteErr()
	}
	if c.writeTimeout > 0 {
		// The same bound WriteMessage applies: an internal frame (pong,
		// keepalive ping) written to a stalled transport must fail on
		// deadline, not wedge the read loop or hold the write mutex
		// against Close. Cleared on return so the bound is per-frame.
		_ = c.nc.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		defer func() { _ = c.nc.SetWriteDeadline(time.Time{}) }()
	}

	return c.fc.writeFrame(opcode, payload, compressed, true)
}

// WriteMessage writes a complete text or binary message. It is safe to call
// from any goroutine. Writes do not fragment: the message is sent in a
// single frame, so messages must fit within maxMessageSize.
//
// OpText payloads must be valid UTF-8 (RFC 6455 §5.6): an OpText write that
// is not fails before anything reaches the wire, and the connection stays
// open; OpBinary payloads pass through untouched.
//
// On a closed connection WriteMessage always fails: with the recorded close
// error, or [ErrClosed] after a normal closure (1000) — never a silent
// success for a frame that will not be sent.
//
// A transport-level write failure fails the connection. A write that
// reaches the transport and fails — the write deadline fires, or the
// connection resets — means the pipe is broken, so the connection is
// marked closed with the error recorded, exactly as the read path reacts
// to a failed pong or keepalive probe. Later writes and [Close] then
// return the recorded error at once instead of re-stalling, [Closed]
// turns true so background writers can stop, and the transport is closed
// (as [Close] does) so a reader blocked in [ReadMessage] wakes instead of
// waiting for keepalive. The write timeout therefore bounds the
// connection, not just a single write. Validation failures (opcode,
// size, UTF-8, JSON) are not transport failures: they are returned
// without touching the connection.
//
// The write lock is held for the whole transport write, so a writer stuck
// at the [WithWriteTimeout] bound delays by that bound the automatic pong
// the read path answers to a peer ping. A peer whose keepalive window is
// shorter than the write bound may therefore declare the connection dead
// while a write is in flight; tune the two to match.
func (c *RawConn) WriteMessage(opcode Op, data []byte) error {
	if opcode != OpText && opcode != OpBinary {
		return fmt.Errorf("%w: WriteMessage requires OpText or OpBinary", errProtocol)
	}
	if opcode == OpText && !utf8.Valid(data) {
		// RFC 6455 §5.6: text frames must be valid UTF-8. Refused before
		// anything reaches the wire; the connection stays open.
		return fmt.Errorf("%w: %d bytes", errInvalidUTF8, len(data))
	}
	if int64(len(data)) > c.fc.maxMsg {
		return fmt.Errorf("%w: message of %d bytes exceeds the %d byte limit",
			errMessageTooBig, len(data), c.fc.maxMsg)
	}
	c.mu.Lock()
	if c.state.Load() == stClosed {
		c.mu.Unlock()

		return c.closedWriteErr()
	}
	if c.writeTimeout > 0 {
		// Bound the write so a blackholed transport cannot hold the write
		// mutex forever: a stuck write must fail (releasing the mutex) so
		// [RawConn.Close] can still tear the connection down. Cleared on return
		// so the bound is per-write, not sticky.
		_ = c.nc.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	// permessage-deflate (RFC 7692 §6.1): the whole message is one raw
	// DEFLATE stream and RSV1 marks the single frame as compressed.
	// Compressing happens under the write lock, with the compressor's
	// scratch therefore owned by exactly one writer at a time.
	frame, compressed := data, false
	if c.deflateNegotiated {
		compressErr := c.compress(data)
		if compressErr != nil {
			_ = c.nc.SetWriteDeadline(time.Time{})
			c.mu.Unlock()

			return compressErr
		}
		frame, compressed = c.compressBuf.Bytes(), true
		// Incompressible or high-entropy data expands under deflate, so the
		// compressed frame can exceed maxMessageSize even though the raw
		// message fit the pre-check above. A peer rejects any frame over its
		// own limit with 1002, so refuse the write here instead of sending a
		// frame that a peer with the same limit would fail — the connection
		// stays open, exactly as with the other validation rejections.
		if int64(len(frame)) > c.fc.maxMsg {
			_ = c.nc.SetWriteDeadline(time.Time{})
			c.mu.Unlock()

			return fmt.Errorf("%w: compressed message of %d bytes exceeds the %d byte limit",
				errMessageTooBig, len(frame), c.fc.maxMsg)
		}
	}
	writeErr := c.fc.writeFrame(opcode, frame, compressed, true)
	_ = c.nc.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		// The transport write failed, so the pipe is broken: no later
		// write on this connection can succeed. Fail the connection with
		// the error recorded — the same verdict the read path gives a
		// failed pong or keepalive probe — and close the transport, as
		// [RawConn.Close] does, so a reader blocked in ReadMessage wakes
		// now instead of on keepalive, and the hijacked conn cannot
		// leak if the read path is not currently in a read.
		if c.state.Load() == stOpen {
			c.state.Store(stClosed)
			c.closeErr = writeErr
			_ = c.nc.Close()
		}
	}
	c.mu.Unlock()

	return writeErr
}

// WriteFrame writes one raw frame — the low-level counterpart of
// [RawConn.WriteMessage] — safe to call from any goroutine, with the same
// write-mutex, write-bound, and closed-connection semantics, and the same
// verdict on a transport failure: the connection is failed with the error
// recorded, exactly as [RawConn.WriteMessage].
//
// WriteFrame is how a raw application fragments a message across frames:
// start it with a frame of OpText or OpBinary and more=true, continue with
// OpContinuation frames, and end with more=false. A peer reassembles the
// fragments into one message — [RawConn.ReadEvent] and
// [Session.ReadMessage] both report the finished message, never the
// fragments — so fragmentation is a transport-level tool (stream a large
// message while interleaving control traffic, pace a write across event
// loop iterations), not a way to change what the peer receives. A
// continuation frame may only follow a start frame sent on this
// connection; a standalone continuation is refused (RFC 6455 §5.4). A
// frame with more=false is a complete one-frame message, exactly as
// WriteMessage.
//
// Validation, per frame: the opcode must be OpText, OpBinary,
// OpContinuation, OpPing, or OpPong (anything else is a protocol error);
// control frames (ping, pong) carry at most 125 payload bytes and may not
// be fragmented; each frame's payload must fit the connection's message
// limit. A single-frame text message (OpText with more=false) must be
// valid UTF-8, as any OpText message; fragments of a longer text message
// are not checked, because a fragment boundary may split a rune — keep
// every fragment of a text message valid UTF-8 if you want the reassembled
// message to pass the peer's check (RFC 6455 §5.6). The frame is written
// uncompressed: permessage-deflate applies to whole messages, and only
// [RawConn.WriteMessage] compresses.
func (c *RawConn) WriteFrame(opcode Op, payload []byte, more bool) error {
	validateErr := c.validateRawFrame(opcode, payload, more)
	if validateErr != nil {
		return validateErr
	}
	c.mu.Lock()
	if c.state.Load() == stClosed {
		writeErr := c.closedWriteErr()
		c.mu.Unlock()

		return writeErr
	}
	if opcode == OpContinuation && !c.fragWriting {
		// The stream has no message in progress for this to continue.
		c.mu.Unlock()

		return fmt.Errorf("%w: continuation frame without a start frame in progress", errProtocol)
	}
	if opcode <= OpBinary {
		// Data frames — continuation, text, and binary, the opcodes 0-2 —
		// drive the fragmentation state; control frames cannot fragment
		// and leave the state untouched.
		c.fragWriting = more
	}
	if c.writeTimeout > 0 {
		_ = c.nc.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	writeErr := c.fc.writeFrame(opcode, payload, false, !more)
	_ = c.nc.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		// The transport write failed, so the pipe is broken: fail the
		// connection, as WriteMessage does.
		if c.state.Load() == stOpen {
			c.state.Store(stClosed)
			c.closeErr = writeErr
			_ = c.nc.Close()
		}
	}
	c.mu.Unlock()

	return writeErr
}

// validateRawFrame applies WriteFrame's pre-write validation: the message
// size limit, the writable opcode set, the control-frame shape, and the
// single-frame UTF-8 rule. A refused frame never reaches the wire and
// never touches the connection's state.
func (c *RawConn) validateRawFrame(opcode Op, payload []byte, more bool) error {
	if int64(len(payload)) > c.fc.maxMsg {
		return fmt.Errorf("%w: frame of %d bytes exceeds the %d byte limit",
			errMessageTooBig, len(payload), c.fc.maxMsg)
	}
	switch {
	case opcode == OpPing || opcode == OpPong:
		if more {
			return fmt.Errorf("%w: %s frames are never fragmented", errProtocol, opcodeName(opcode))
		}
		if len(payload) > maxControlPayload {
			return fmt.Errorf("%w: %s payload of %d bytes exceeds the %d byte control-frame limit",
				errProtocol, opcodeName(opcode), len(payload), maxControlPayload)
		}
	case opcode == OpText && !more && !utf8.Valid(payload):
		// RFC 6455 §5.6: a single-frame text message is the whole
		// message, so it must be valid UTF-8. Fragments are exempt: a
		// boundary may split a rune.
		return fmt.Errorf("%w: %d bytes", errInvalidUTF8, len(payload))
	case opcode == OpText || opcode == OpBinary || opcode == OpContinuation:

	default:
		return fmt.Errorf("%w: %s frame is not writable", errProtocol, opcodeName(opcode))
	}

	return nil
}

// Ping sends an application-level ping frame carrying the given payload
// (RFC 6455 §5.5). It is safe to call from any goroutine, exactly as
// [RawConn.WriteMessage]: the write takes the write mutex, obeys the
// connection's write bound, and on a closed connection yields the recorded
// close error — [ErrClosed] after a normal closure — never a silent
// success.
//
// The peer answers with a pong carrying the same payload. On a [Session]
// the pong is consumed transparently unless a [WithPongHandler] was set, which
// is the half that makes the pair useful for round-trip-time measurement:
// ping, and time the handler's wake. On a [RawConn] the pong arrives as an
// OpPong [Event]. Any frame — the pong included — resets the keepalive
// idle clock, so an application ping also proves liveness.
//
// A ping is a control frame, so its payload is at most 125 bytes.
func (c *RawConn) Ping(payload []byte) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("%w: ping payload of %d bytes exceeds the %d byte control-frame limit",
			errProtocol, len(payload), maxControlPayload)
	}

	return c.writeFrame(OpPing, payload, false)
}

// Pong sends a pong frame carrying the given payload (RFC 6455 §5.5) — the
// answer to a ping. It is safe to call from any goroutine, exactly as
// [RawConn.Ping]. On a [RawConn] this is how you answer the pings that
// arrive as OpPing events: by RFC 6455 §5.5.3 the answer is mandatory, and
// a peer whose keepalive window elapses without one declares the
// connection dead. The RFC prescribes echoing the ping's payload; your
// protocol may use the payload for its own correlation instead.
//
// A pong is a control frame, so its payload is at most 125 bytes.
func (c *RawConn) Pong(payload []byte) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("%w: pong payload of %d bytes exceeds the %d byte control-frame limit",
			errProtocol, len(payload), maxControlPayload)
	}

	return c.writeFrame(OpPong, payload, false)
}

// WriteText writes s as a text message. If s is not valid UTF-8 it is
// rejected before reaching the wire, exactly as any OpText write
// (RFC 6455 §5.6).
func (c *RawConn) WriteText(s string) error {
	return c.WriteMessage(OpText, []byte(s))
}

// WriteBinary writes data as a binary message: the bytes pass through
// unchanged, with no copy and no validation.
func (c *RawConn) WriteBinary(data []byte) error {
	return c.WriteMessage(OpBinary, data)
}

// WriteJSON marshals v to JSON and writes it as a text message. The
// marshal happens before the write lock is taken, so a large marshal does
// not hold up other writers or [RawConn.Close]; a marshal failure is returned
// before anything reaches the wire. JSON output is valid UTF-8 by
// construction, so the text-frame rule (RFC 6455 §5.6) holds by
// construction as well.
func (c *RawConn) WriteJSON(v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %w", errBadJSON, err)
	}

	return c.WriteMessage(OpText, payload)
}

// closeWith performs the close sequence shared by [RawConn.Close] and
// [RawConn.CloseFrame]: it validates the close code, builds the payload, and,
// on an open connection, records the terminal error, sends the close frame
// (bounded by the write timeout or the fixed fallback), and closes the
// transport. It returns (writeErr, terminal) — the close-frame write status
// and the terminal error recorded on the connection. A validation failure
// returns (error, nil) and leaves the connection untouched; an already
// closed connection returns (recorded, recorded) without touching the wire.
func (c *RawConn) closeWith(code int, reason string) (error, error) {
	if code < closeCodeMin || code > closeCodeMax {
		return fmt.Errorf("%w: %d", errBadCloseCode, code), nil
	}
	var payload []byte
	if !mustNotSetCloseCode(code) {
		// RFC 6455 §5.5: the reason is the UTF-8 of a text message, so a
		// non-UTF-8 reason is dropped — the close frame carries the code
		// alone — rather than putting invalid bytes on the wire.
		if !utf8.ValidString(reason) {
			reason = ""
		}
		// Close frame payloads max out at 125 bytes: 2-byte code + reason.
		reason = truncateReason(reason)
		payload = make([]byte, closeCodeBytes+len(reason))
		binary.BigEndian.PutUint16(payload, uint16(code))
		copy(payload[closeCodeBytes:], reason)
	}
	c.mu.Lock()
	if c.state.Load() == stClosed {
		writeErr := c.closedWriteErr()
		terminal := terminalErr(c.closeErr)
		c.mu.Unlock()

		return writeErr, terminal
	}
	c.state.Store(stClosed)
	c.closeErr = closeErrFor(code, reason)
	// The close frame is sent best-effort: the kernel delivers queued data
	// before the FIN, so it reaches the peer in order when the transport
	// allows. The write is bounded by the connection's write timeout when
	// the caller set one — the same bound every other write on this
	// connection obeys — and by the fixed fallback otherwise, so a silent
	// or half-dead peer must not be able to hold the close open forever.
	closeBound := closeWriteTimeout
	if c.writeTimeout > 0 {
		closeBound = c.writeTimeout
	}
	_ = c.nc.SetWriteDeadline(time.Now().Add(closeBound))
	writeErr := c.fc.writeFrame(OpClose, payload, false, true)
	_ = c.nc.SetWriteDeadline(time.Time{})
	c.mu.Unlock()
	_ = c.nc.Close()

	return writeErr, terminalErr(c.closeErr)
}

// Close closes the connection, sending a close frame with the given code and
// reason before tearing down the transport. It is idempotent and safe to
// call from any goroutine, including the pumping goroutine.
//
// Close codes must be in the range 1000-4999. Codes that cannot appear as a
// status on the wire — 1005, 1006, 1015 (MUST NOT, RFC 6455 §7.4) plus the
// reserved 1004 — go out with an empty payload. A reason that is not valid
// UTF-8 is dropped (the frame carries the code alone), because RFC 6455
// §5.5 says the reason is the UTF-8 of a text message. The return value is the
// terminal error recorded on the connection — [io.EOF] for a normal
// closure (1000), a [*CloseError] otherwise — not the status of the
// close-frame write, which is best effort: the kernel delivers queued data
// before the FIN, so the frame reaches the peer in order when the transport
// allows. Concurrent Close callers all observe the same recorded error, from
// the first one to close.
//
// Teardown latency on a stalled transport. The close-frame write is bounded
// by the connection's [WithWriteTimeout] when one was set, and by a fixed
// 5-second fallback otherwise — a silent or half-dead peer must not be able
// to hold the close open forever. Two stacking effects are worth knowing:
// Close takes the same write mutex as every other writer, so it queues
// behind an in-flight data write (itself bounded by the write timeout), and
// the read path answers the peer's close frame with its own, so a peer that
// stops reading can also delay the [Session.ReadMessage] that reports the
// closure by that same bound. Worst case, handler teardown waits on the
// order of the write timeout plus the close bound. The close-frame write
// status itself is [RawConn.CloseFrame]'s return value.
func (c *RawConn) Close(code int, reason string) error {
	writeErr, terminal := c.closeWith(code, reason)
	if terminal == nil {
		// terminal is nil only when the code was rejected: the connection
		// is untouched and the validation error is the return value.
		return writeErr
	}

	return terminal
}

// CloseFrame is the low-level half of [RawConn.Close]: the same validation,
// the same close frame, the same bounded write, and the same teardown —
// but it returns the status of the close-frame write itself instead of the
// recorded terminal error. It returns nil when the frame was written, a
// transport error when the write failed or its deadline fired, the recorded
// close error (or [ErrClosed] after a normal closure) when the connection
// was already closed — never a silent success for a frame that will not be
// sent — and an error wrapping [errBadCloseCode], with the connection
// untouched, for an out-of-range code. Use it when you need to know whether
// the peer actually received the close frame, not just how the connection
// ended.
//
// Like [RawConn.Close], it is idempotent and safe to call from any
// goroutine, including the pumping goroutine. The session face does not
// expose it: [Session.Close] reports the terminal error.
func (c *RawConn) CloseFrame(code int, reason string) error {
	writeErr, _ := c.closeWith(code, reason)

	return writeErr
}

// Closed reports whether the connection has been closed, from any goroutine.
// It is the cheap, race-free signal a background writer goroutine needs to
// stop: it can check Closed() (or select on work and bail when true) instead
// of waiting for its next WriteMessage to fail with ErrClosed.
func (c *RawConn) Closed() bool {
	return c.state.Load() == stClosed
}

// ID returns a unique identifier for the connection (unique within this
// process), useful as a key in session registries.
func (c *RawConn) ID() uint64 { return c.id }

// Subprotocol returns the negotiated subprotocol, or "" if none.
func (c *RawConn) Subprotocol() string { return c.subprotocol }

// RemoteAddr returns the peer's network address.
func (c *RawConn) RemoteAddr() net.Addr { return c.nc.RemoteAddr() }

// LocalAddr returns this endpoint's network address.
func (c *RawConn) LocalAddr() net.Addr { return c.nc.LocalAddr() }

// SetReadDeadline sets the underlying connection's read deadline. When the
// idle timeout keepalive is enabled it is overridden by the keepalive for
// the duration of each blocking read; use WithIdleTimeout(0) to manage
// deadlines yourself.
func (c *RawConn) SetReadDeadline(t time.Time) error { return c.nc.SetReadDeadline(t) }

// SetWriteDeadline sets the underlying connection's write deadline.
func (c *RawConn) SetWriteDeadline(t time.Time) error { return c.nc.SetWriteDeadline(t) }

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 6 · Protocol core: terminal handling and permessage-deflate

// finish records a terminal state. It is safe to call concurrently: the
// first caller's error wins, and the returned error is the one recorded at
// close time. A nil return means the connection closed normally (1000).
//
// The state transition and the closeErr write happen under c.mu so that no
// reader — which also reads closeErr under c.mu — can ever observe the
// closed state without the recorded error.
func (c *RawConn) finish(err error) error {
	c.mu.Lock()
	if c.state.Load() == stOpen {
		c.state.Store(stClosed)
		c.closeErr = err
	}
	err = terminalErr(c.closeErr)
	c.mu.Unlock()
	_ = c.nc.Close()

	return err
}

// applyCompression records a successful permessage-deflate negotiation on
// the connection: the RSV1 bit becomes the "compressed" marker on the read
// side, and the write side starts compressing data messages.
func (c *RawConn) applyCompression() {
	c.fc.deflate = true
	c.deflateNegotiated = true
}

// Compressed reports whether permessage-deflate was negotiated, i.e. whether
// data messages on this connection travel compressed and carry RSV1.
func (c *RawConn) Compressed() bool { return c.deflateNegotiated }

// compress deflates data into the write scratch. The output is a truncated
// raw DEFLATE stream: after writing the payload we Flush (not Close), which
// finishes the current block and appends a BFINAL=0 empty stored block
// instead of terminating the stream, then we drop that block's final four
// octets (0x00 0x00 0xff 0xff). That is exactly the wire encoding RFC 7692
// §7.2.1 prescribes and that every peer's decompressor expects (see
// decompress and deflateTailBytes). A fresh writer context per message
// implements the per-message (no context takeover) mode. The scratch
// outlives the frame write: bufio consumes it synchronously before
// writeFrame returns, and the next compress resets it under the same write
// lock.
func (c *RawConn) compress(data []byte) error {
	if c.deflater == nil {
		c.compressBuf = &bytes.Buffer{}
		writer, err := flate.NewWriter(c.compressBuf, c.compressLevel)
		if err != nil {
			return fmt.Errorf("ws: create compressor: %w", err)
		}
		c.deflater = writer
	}
	c.compressBuf.Reset()
	c.deflater.Reset(c.compressBuf)
	_, err := c.deflater.Write(data)
	if err != nil {
		return fmt.Errorf("ws: compress message: %w", err)
	}
	// Flush finishes the block and appends the BFINAL=0 empty stored block
	// without terminating the stream (Close would emit a BFINAL=1 Huffman
	// block, which is not the RFC wire encoding).
	flushErr := c.deflater.Flush()
	if flushErr != nil {
		return fmt.Errorf("ws: finish compressed message: %w", flushErr)
	}
	// The RFC wire payload is the flushed stream minus its final four octets
	// (the empty block's length and its complement). Flush guarantees those
	// four are present; compressTailCheck guards against an unexpected
	// encoder change without panicking on an undersized stream.
	out, tailErr := compressTailCheck(c.compressBuf.Bytes())
	if tailErr != nil {
		return tailErr
	}
	c.compressBuf.Truncate(len(out))

	return nil
}

// compressTailCheck validates the tail of a flushed flate stream and returns
// the stream minus its final four octets. A stream shorter than the tail, or
// one that does not end with the empty stored block's length and complement
// (RFC 7692 §7.2.1), is an internal invariant breach (errCompressTail): the
// standard library encoder changed in an unexpected way. Both branches are
// length-guarded, so a mismatched encoder is reported as an error, never an
// index panic.
func compressTailCheck(stream []byte) ([]byte, error) {
	if len(stream) < truncateOctets {
		return nil, fmt.Errorf("%w: stream of %d bytes is shorter than the %d-byte empty block tail",
			errCompressTail, len(stream), truncateOctets)
	}
	if !bytes.Equal(stream[len(stream)-truncateOctets:], deflateTailBytes[:truncateOctets]) {
		return nil, fmt.Errorf("%w: % x", errCompressTail, stream[len(stream)-truncateOctets:])
	}

	return stream[:len(stream)-truncateOctets], nil
}

// decompress expands a compressed message payload. The received data is a
// truncated raw DEFLATE stream; appending deflateTailBytes completes the
// trailing empty block the compressor cut off and adds a BFINAL terminator
// so Go's strict decoder ends cleanly instead of reporting "unexpected EOF"
// (see that variable's comment). An empty compressed payload is legal and
// decompresses to an empty message. The result is at most maxMessageSize —
// the bound is enforced while decompressing so a high-ratio payload cannot
// inflate unboundedly before being rejected. The returned slice is fresh: the caller owns it and may
// retain it, while every decompressor buffer is per-connection scratch reused
// on the next message — one heap allocation per compressed message.
func (c *RawConn) decompress(src []byte) ([]byte, error) {
	if c.inflater == nil {
		c.inflateSrc = &bytes.Reader{}
		reader := flate.NewReader(c.inflateSrc)
		resetter, ok := reader.(flate.Resetter)
		if !ok {
			// flate.NewReader always implements Resetter; a mismatch means the
			// standard library changed. Fail closed instead of panicking on a
			// per-message assertion.
			_ = reader.Close()

			return nil, errNoResetter
		}
		c.inflater = reader
		c.inflaterRst = resetter
		c.inflateBuf = &bytes.Buffer{}
		c.inflateLimit.buf = c.inflateBuf
		if c.inflateCopy == nil {
			c.inflateCopy = make([]byte, inflateCopyScratch)
		}
	}
	// Lay the payload out next to the decompression tail in per-connection
	// scratch, so the steady-state decompression allocates only the
	// returned payload.
	need := len(src) + len(deflateTailBytes)
	if len(c.inflateWire) < need {
		c.inflateWire = make([]byte, need)
	}
	copy(c.inflateWire, src)
	copy(c.inflateWire[len(src):], deflateTailBytes[:])
	c.inflateSrc.Reset(c.inflateWire[:need])
	resetErr := c.inflaterRst.Reset(c.inflateSrc, nil)
	if resetErr != nil {
		return nil, fmt.Errorf("ws: reset decompressor: %w", resetErr)
	}
	c.inflateBuf.Reset()
	c.inflateLimit.limit = int(c.fc.maxMsg)
	_, err := io.CopyBuffer(&c.inflateLimit, c.inflater, c.inflateCopy)
	if err != nil {
		if errors.Is(err, errMessageTooBig) {
			return nil, fmt.Errorf("%w: decompressed message exceeds the %d byte limit",
				errMessageTooBig, c.fc.maxMsg)
		}

		return nil, fmt.Errorf("%w: invalid compressed payload: %w", errProtocol, err)
	}
	payload := make([]byte, c.inflateBuf.Len())
	copy(payload, c.inflateBuf.Bytes())

	return payload, nil
}

// inflateGuard bounds how many bytes the decompressor may produce, so a
// small high-ratio payload cannot inflate past maxMessageSize before being
// rejected. It is a per-connection field, not a fresh struct per call:
// a struct value passed as an io.Writer would escape to the heap and cost
// an allocation per message.
type inflateGuard struct {
	buf   *bytes.Buffer
	limit int
}

func (g *inflateGuard) Write(p []byte) (int, error) {
	if g.buf.Len()+len(p) > g.limit {
		return 0, errMessageTooBig
	}

	n, err := g.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("ws: decompress output buffer: %w", err)
	}

	return n, nil
}

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 7 · Wire format: the frame codec

// frame is one decoded RFC 6455 frame.
type frame struct {
	fin        bool
	opcode     Op
	payload    []byte
	compressed bool // RSV1 set on the first frame of this data message
}

func (f frame) isControl() bool { return f.opcode >= OpClose }

// frameCodec is the byte-level half of a [RawConn]: it reads and writes RFC
// 6455 frames on a buffered stream pair. Masking enforcement depends on
// which side we are on; everything else is independent of connection state,
// so it lives in its own struct — frame encoding and decoding can be
// benchmarked, fuzzed, and tested with plain buffers, no live connection.
type frameCodec struct {
	br       *bufio.Reader
	bw       *bufio.Writer
	isClient bool
	maxMsg   int64
	deflate  bool // permessage-deflate negotiated: RSV1 may carry compression

	// Per-frame scratch, kept here instead of on each call's stack because
	// the header/length/mask buffers otherwise escape to the heap through
	// the read and random-number interfaces: one to three small
	// allocations per frame. The read-side and write-side scratch are kept
	// apart on purpose: the reader goroutine (readFrame) and the writer
	// goroutines (writeFrame, serialized by the RawConn's write mutex) run
	// concurrently, so each side's scratch must be owned by exactly one.
	// Neither side needs synchronization of its own.
	in    [4]byte  // read: header (2) + 16-bit extended length (2)
	len8  [8]byte  // read: extended length
	mask  [4]byte  // read: mask key
	hdr   [14]byte // write: header (max: 10-byte len + 4-byte mask)
	rand4 [4]byte  // write: fresh per-frame mask key

	// maskScratch is the masked-write copy. Masking must not modify the
	// caller's payload, and the copy is safe to reuse: by the time
	// writeFrame returns, bufio has consumed the bytes synchronously.
	// It grows to the largest masked frame sent and stays there — a
	// bounded, one-time cost per connection, not per message.
	maskScratch []byte
}

// readFrame reads one frame from the connection. A client must mask its
// frames and a server must not, so the peer's frames are masked exactly
// when we are the server.
func (fc *frameCodec) readFrame() (frame, error) {
	_, err := io.ReadFull(fc.br, fc.in[:2])
	if err != nil {
		return frame{}, fmt.Errorf("ws: read frame header: %w", err)
	}
	frm := frame{fin: fc.in[0]&finBit != 0, opcode: Op(fc.in[0] & opcodeMask)}
	rsvErr := fc.checkRSV()
	if rsvErr != nil {
		return frame{}, rsvErr
	}
	masked := fc.in[1]&maskBit != 0
	if masked == fc.isClient {
		return frame{}, fmt.Errorf("%w: frame masking violation", errProtocol)
	}
	size, err := fc.readFrameLen(int(fc.in[1] & lenMask))
	if err != nil {
		return frame{}, err
	}
	if frm.isControl() && (!frm.fin || size > maxControlPayload) {
		return frame{}, fmt.Errorf("%w: invalid control frame", errProtocol)
	}
	if size > fc.maxMsg {
		return frame{}, fmt.Errorf("%w: frame of %d bytes exceeds the %d byte limit",
			errProtocol, size, fc.maxMsg)
	}

	payload, err := fc.readFramePayload(size, masked)
	if err != nil {
		return frame{}, err
	}
	frm.payload = payload
	if fc.in[0]&rsv1Bit != 0 {
		frm.compressed = true
	}

	return frm, nil
}

// checkRSV validates the reserved bits on the frame header (RFC 6455 §5.2,
// RFC 7692 §6): RSV2 and RSV3 are always zero; RSV1 is the
// permessage-deflate "compressed" bit and may be set only when the
// extension was negotiated. RSV1 marks the first frame of a data message,
// so its misuse on control frames and continuation frames is checked where
// the message context is known: RawConn.ReadEvent and handleData.
func (fc *frameCodec) checkRSV() error {
	rsv := fc.in[0] & rsvMask
	if rsv&rsv23Mask != 0 {
		return fmt.Errorf("%w: reserved bits 2 or 3 set", errProtocol)
	}
	if rsv1Set := rsv == rsv1Bit; rsv1Set && !fc.deflate {
		return fmt.Errorf("%w: RSV1 set without permessage-deflate negotiated", errProtocol)
	}

	return nil
}

// readFramePayload reads the mask key (when masked) and the payload, then
// unmasks in place.
func (fc *frameCodec) readFramePayload(size int64, masked bool) ([]byte, error) {
	if masked {
		_, err := io.ReadFull(fc.br, fc.mask[:])
		if err != nil {
			return nil, fmt.Errorf("ws: read mask key: %w", err)
		}
	}
	payload := make([]byte, size)
	_, readErr := io.ReadFull(fc.br, payload)
	if readErr != nil {
		return nil, fmt.Errorf("ws: read payload: %w", readErr)
	}
	if masked {
		xorMaskKey(payload, payload, fc.mask)
	}

	return payload, nil
}

// readFrameLen reads and validates the payload length for a header whose 7
// length bits held shortLen.
func (fc *frameCodec) readFrameLen(shortLen int) (int64, error) {
	switch shortLen {
	case len16:
		_, err := io.ReadFull(fc.br, fc.in[2:4])
		if err != nil {
			return 0, fmt.Errorf("ws: read 16-bit length: %w", err)
		}

		return int64(binary.BigEndian.Uint16(fc.in[2:4])), nil
	case len64:
		_, err := io.ReadFull(fc.br, fc.len8[:])
		if err != nil {
			return 0, fmt.Errorf("ws: read 64-bit length: %w", err)
		}
		if fc.len8[0] != 0 {
			return 0, fmt.Errorf("%w: frame too large", errProtocol)
		}
		// len8[0] == 0 above, so the value is < 2^63: the conversion
		// below cannot overflow.

		return int64(binary.BigEndian.Uint64(fc.len8[:])), nil //nolint:gosec // bounded above
	default:

		return int64(shortLen), nil
	}
}

// encodeFrameLen encodes payloadLen into the header and returns the total
// header length in bytes, not counting the mask key.
func encodeFrameLen(hdr []byte, payloadLen int) int {
	switch {
	case payloadLen <= maxShortLen:
		hdr[1] = byte(payloadLen) //nolint:gosec // payloadLen <= 125 here

		return hdrLen7Bit
	case payloadLen <= len16Max:
		hdr[1] = len16
		binary.BigEndian.PutUint16(hdr[2:4], uint16(payloadLen))

		return hdrLen16Bit
	default:
		hdr[1] = len64
		binary.BigEndian.PutUint64(hdr[2:10], uint64(payloadLen))

		return hdrLen64Bit
	}
}

// xorMaskKey applies the repeating 4-byte mask key to the bytes of src,
// writing the result into dst; dst may alias src (in-place unmasking).
// The four-byte stride lets the compiler vectorize the loop — a byte
// loop with the i&3 mask index runs about 2.5x slower on the same data.
func xorMaskKey(dst, src []byte, key [4]byte) {
	k := binary.LittleEndian.Uint32(key[:])
	full := len(src) / maskKeyLen * maskKeyLen
	for i := 0; i < full; i += 4 {
		binary.LittleEndian.PutUint32(dst[i:], binary.LittleEndian.Uint32(src[i:])^k)
	}
	for i := full; i < len(src); i++ {
		dst[i] = src[i] ^ key[i&3]
	}
}

// writeFrame writes one frame. fin sets the FIN bit — every caller but
// the fragmented-write path sends complete frames, which is also the only
// legal form for control frames (RFC 6455 §5.5). compressed sets RSV1,
// which is reserved for permessage-deflate and must only be set on data
// frames carrying a compressed message (RFC 7692 §6). It does not take any
// lock; the [RawConn] serializes calls via its write mutex.
func (fc *frameCodec) writeFrame(opcode Op, payload []byte, compressed, fin bool) error {
	hdr := fc.hdr[:]
	// opcode is a 4-bit value (0-15), so the conversion cannot overflow.
	first := byte(opcode) //nolint:gosec // 4-bit opcode
	if fin {
		first |= finBit
	}
	if compressed {
		first |= rsv1Bit
	}
	hdr[0] = first
	hdrLen := encodeFrameLen(hdr, len(payload))
	if fc.isClient {
		_, randErr := rand.Read(fc.rand4[:])
		if randErr != nil {
			return fmt.Errorf("ws: generate frame mask: %w", randErr)
		}
		copy(hdr[hdrLen:hdrLen+4], fc.rand4[:])
		hdr[1] |= maskBit
		hdrLen += 4
	}
	_, hdrErr := fc.bw.Write(hdr[:hdrLen])
	if hdrErr != nil {
		return fmt.Errorf("ws: write frame header: %w", hdrErr)
	}
	if fc.isClient {
		// Masking must not modify the caller's buffer, so the masked
		// copy goes through reusable scratch (see maskScratch).
		if len(fc.maskScratch) < len(payload) {
			fc.maskScratch = make([]byte, len(payload))
		}
		buf := fc.maskScratch[:len(payload)]
		mask := [4]byte(hdr[hdrLen-4 : hdrLen])
		xorMaskKey(buf, payload, mask)
		_, payloadErr := fc.bw.Write(buf)
		if payloadErr != nil {
			return fmt.Errorf("ws: write payload: %w", payloadErr)
		}
	} else {
		_, payloadErr := fc.bw.Write(payload)
		if payloadErr != nil {
			return fmt.Errorf("ws: write payload: %w", payloadErr)
		}
	}
	flushErr := fc.bw.Flush()
	if flushErr != nil {
		return fmt.Errorf("ws: flush frame: %w", flushErr)
	}

	return nil
}

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 8 · Protocol constants (close codes, opcodes, wire defaults)

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

// Close code range: close codes must be in 1000-4999 (RFC 6455 §7.4).
const (
	closeCodeMin = 1000
	closeCodeMax = 4999
)

// Close codes this package never places in a close frame payload.
// 1004 is reserved by RFC 6455 §7.4, and 1015 is reserved there as well —
// designated for use by libraries to report a TLS handshake failure, not
// for transmission.
const (
	closeCodeUnexpected = 1004 // RFC 6455 §7.4: reserved, no assigned meaning
	closeCodeTLSFailure = 1015 // library-designated: TLS handshake failure
)

// Op is the WebSocket message and frame op-type (RFC 6455 §5.2). The data
// messages reported by [Session.ReadMessage] and [RawConn.ReadEvent] carry
// OpText or OpBinary; the writable set is documented on
// [RawConn.WriteMessage] and [RawConn.WriteFrame].
type Op int

// Frame opcodes (RFC 6455 §5.2).
const (
	OpContinuation Op = 0
	OpText         Op = 1
	OpBinary       Op = 2
	OpClose        Op = 8
	OpPing         Op = 9
	OpPong         Op = 10
)

// Wire format constants (RFC 6455 §5-§6).
const (
	finBit     = 0x80 // frame[0] high bit: final fragment
	rsvMask    = 0x70 // frame[0] reserved bits
	rsv1Bit    = 0x40 // reserved bit 1: permessage-deflate "compressed" (RFC 7692)
	rsv23Mask  = 0x30 // reserved bits 2 and 3, must always be zero
	opcodeMask = 0x0f // frame[0] low 4 bits: opcode
	maskBit    = 0x80 // frame[1] high bit: payload is masked
	lenMask    = 0x7f // frame[1] low 7 bits: payload length
	len16      = 126  // 16-bit extended length follows the header
	len64      = 127  // 64-bit extended length follows the header
	len16Max   = 0xffff
	maskKeyLen = 4 // masking key size (RFC 6455 §5.3)
)

// Frame size limits (RFC 6455 §5.5, §7.1).
const (
	maxShortLen       = 125 // largest length encoded in the 7 header bits
	maxControlPayload = 125 // max control-frame payload
	closeCodeBytes    = 2   // close payload: 2-byte status code prefix
	maxCloseReason    = 123 // close payload caps at 125 bytes total
)

// Header lengths for each payload-length encoding.
const (
	hdrLen7Bit  = 2  // 7-bit length
	hdrLen16Bit = 4  // header + 16-bit extended length
	hdrLen64Bit = 10 // header + 64-bit extended length
)

// Defaults shared by [NewUpgrader] and [Dial].
const (
	defaultMaxMessageSize = 16 << 20
	defaultIdleTimeout    = 60 * time.Second
	defaultWriteTimeout   = 30 * time.Second
	closeWriteTimeout     = 5 * time.Second

	bufSize        = 16 << 10 // bufio buffer for reads and writes
	wsKeyBytes     = 16       // raw key bytes, base64-encoded into the handshake
	websocketVer   = "13"     // Sec-WebSocket-Version (the only valid value)
	wsScheme       = "ws"     // plain-text scheme
	wssScheme      = "wss"    // TLS scheme
	wsDefaultPort  = ":80"    // appended when the URL has no port
	wssDefaultPort = ":443"
)

// permessage-deflate (RFC 7692) negotiation constants.
const (
	// extPerMessageDeflate is the only extension this package negotiates.
	extPerMessageDeflate = "permessage-deflate"
	// maxWindowBits is the largest LZ77 window the stdlib flate compressor
	// can honor: 2^15 = 32,768 bytes. Offers or responses that demand a
	// smaller window than this cannot be accepted.
	maxWindowBits = 15
	// deflateResponseHeader is this package's fixed extension negotiation
	// response and offer. Per-message (no context takeover) in both
	// directions is enforced by construction — the compressor and the
	// decompressor are per-message by design — so the response says so
	// explicitly, and the offer asks for the same of the peer.
	deflateResponseHeader = "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
)

// WebSocket extension header spellings. RFC 6455 and RFC 7692 use the
// plural "Sec-WebSocket-Extensions" throughout their examples, while the
// IANA registration uses the singular "Sec-WebSocket-Extension"; both
// forms circulate in real handshakes (browsers send the plural). This
// package accepts both on input and sends the RFC example spelling
// (plural) in both the offer and the 101 response.
const (
	extHeaderSingular = "Sec-Websocket-Extension"
	extHeaderPlural   = "Sec-Websocket-Extensions"
)

const (
	// truncateOctets is the length of the empty stored block's length and
	// complement octets stripped from a compressed stream (see compress).
	truncateOctets = 4
	// inflateCopyScratch sizes the per-connection io.CopyBuffer scratch used
	// to move decompressed bytes into the message payload.
	inflateCopyScratch = 32 << 10
)

// deflateTailBytes are the octets appended to a received compressed payload
// before DEFLATE. The first four are the ones RFC 7692 §7.2.2 prescribes;
// they complete the trailing empty block the compressor truncated. The final
// four add a BFINAL=1 empty stored block: real permessage-deflate peers
// (browsers, Node) end their stream with a BFINAL=0 empty block, so a
// strict DEFLATE decoder (Go's compress/flate) would otherwise run past it
// into EOF and report "unexpected EOF". See decompress and compress.
var deflateTailBytes = [9]byte{ //nolint:gochecknoglobals // RFC 7692 §7.2 constant, never mutated
	0x00, 0x00, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff,
}

// ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
// 9 · Errors (CloseError, CloseCode, ErrClosed, internal sentinels)

// CloseError is returned by [Session.ReadMessage] when the connection is closed
// with a status code other than a normal closure (1000, or a close frame
// with no status). A normal closure reads as [io.EOF] from ReadMessage
// instead; expected notices such as 1001 "going away" arrive here so the
// application can react to them.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	return fmt.Sprintf("ws: closed with code %d %q", e.Code, e.Reason)
}

// CloseCode extracts the close code and reason from an error returned by
// [Session.ReadMessage], by a write that failed with the connection's
// recorded close error, or from [Session.Close] itself. ok is false if the
// error does not carry a close code.
func CloseCode(err error) (int, string, bool) {
	var closeErr *CloseError
	if !errors.As(err, &closeErr) {
		return 0, "", false
	}

	return closeErr.Code, closeErr.Reason, true
}

// ErrClosed is returned by [Session.WriteMessage] when the connection has been
// closed with a normal closure (1000). A normal closure records a nil
// terminal error, so without a sentinel a write after such a close would
// report success for a frame that is never sent.
var ErrClosed = errors.New("ws: connection closed")

// errProtocol marks a protocol violation that terminates the connection.
var errProtocol = errors.New("ws: protocol violation")

// errMessageTooBig marks a frame or message that exceeds maxMessageSize.
var errMessageTooBig = errors.New("ws: message exceeds size limit")

var errInvalidUTF8 = errors.New("ws: text message is not valid UTF-8")

var errBadJSON = errors.New("ws: cannot marshal JSON message")

// Static error bases, wrapped with context where the detail varies.
var (
	errBadScheme = errors.New("ws: unsupported scheme")
	// errBadURL is the base for a URL that cannot be dialed: malformed,
	// or missing its host.
	errBadURL          = errors.New("ws: bad url")
	errBadCloseCode    = errors.New("ws: invalid close code")
	errHandshakeFailed = errors.New("ws: handshake failed")
	errBadSubprotocol  = errors.New("ws: invalid subprotocol")
	errBadHeader       = errors.New("ws: invalid request header")
	// errBadExtension is the base for a malformed permessage-deflate offer
	// or 101 response (RFC 7692 §7.1.2); the detail naming the offending
	// parameter is wrapped on top so logs stay useful while callers can
	// match the base.
	errBadExtension = errors.New("ws: invalid permessage-deflate parameter")
	// errCompressTail marks an internal invariant breach in the compressor:
	// the flushed stream did not end with the expected empty-block octets,
	// or was shorter than the tail itself.
	errCompressTail = errors.New("ws: internal error: unexpected flate stream tail")
	// errNoResetter marks an internal invariant breach: the stdlib decompressor
	// no longer supports Reset, so per-message reuse is impossible.
	errNoResetter = errors.New("ws: internal error: decompressor does not support reset")
)

// closeErrFor maps a close code to the terminal error recorded on the
// connection: a normal closure (1000, or an absent status) yields nil,
// everything else yields a *CloseError so callers can see the code and
// reason (e.g. 1001 "going away").
// terminalErr maps the recorded terminal error to what the connection's
// surfaces report: a clean end — a normal closure (1000) in either
// direction, or a close frame without a status — reads as [io.EOF];
// anything else is the recorded error, so [errors.Is] on [io.EOF] is the
// one check that distinguishes a clean end from an abnormal one.
func terminalErr(closeErr error) error {
	if closeErr == nil {
		return io.EOF
	}

	return closeErr
}

func closeErrFor(code int, reason string) error {
	switch code {
	case StatusNormalClosure, StatusNoStatusReceived:
		return nil
	default:

		return &CloseError{Code: code, Reason: reason}
	}
}
