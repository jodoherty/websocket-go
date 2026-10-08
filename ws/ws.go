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
//	defer c.Close()
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
//     defer c.Close()
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
//     [Session.Close] call. The read and write deadline options bind only
//     where the stream can enforce deadlines; over a stream that cannot (the
//     standard library's extended-CONNECT streams), a session with a nonzero
//     window is refused at construction — never silently inert.
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
//  2. The read loop is not: [Session.ReadMessage], [RawConn.ReadEvent], and
//     their drain forms ([Session.Drain], [RawConn.Drain]) are owned by the
//     single goroutine that pumps the connection, and the two faces are
//     never mixed on one connection — read state is owned by that
//     goroutine. Never call two of them on one connection at once.
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
// writes and [Session.Shutdown] — the call that puts a close frame on the
// wire. [Session.Close] itself only tears the transport down, so it never
// blocks and needs no bound. Cancelling a live connection is therefore
// [Session.Close] from another goroutine — idempotent, immediate, and safe
// from anywhere — rather than a context cancellation, which is what the
// deadline ownership above makes the cheaper answer. The deadline options
// bind only where the underlying stream can enforce them (a hijacked net.Conn
// always can; see [DeadlineStream]); over a stream that cannot, a session
// with a nonzero window is refused, so the bounds are never promised and
// silently absent.
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
//     optional. This client's own offer instead carries both
//     no-context-takeover parameters — it never reuses the LZ77 window
//     across messages, so it says so — and requires the response to echo
//     server_no_context_takeover (RFC 7692 §7.1.1.1); measured responses
//     from Node ws and gorilla/websocket servers both carry it, and
//     gorilla's client enforces the same requirement.
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
// # HTTP/2 and HTTP/3
//
// One handler serves WebSockets over all three transports. The HTTP/1.1
// handshake is the [Upgrader.Upgrade] request; over HTTP/2 and HTTP/3 the same
// handshake rides an extended CONNECT (RFC 8441 / RFC 9220), which
// [Upgrader.Upgrade] detects from the request method and the :protocol
// pseudo-header and answers with a 200 whose body is the frame tunnel. Where a
// toolchain's HTTP/2 server does not route extended CONNECT the CONNECT branch
// is simply never taken and clients use the HTTP/1.1 upgrade instead.
// [Upgrader.SessionOnStream] is the entry point for a stream the standard
// library does not drive — an HTTP/3 or QUIC stream — which the application
// hands over after running the extended-CONNECT handshake on it itself. The
// protocol core is transport-agnostic; only the handshake surface changes.
// Because those streams expose no per-stream deadline, the read and write
// deadline options bind only where the stream implements [DeadlineStream];
// with a nonzero window on a stream that cannot enforce one, the CONNECT
// branch refuses the upgrade with a 501 before the tunnel opens, and
// [Upgrader.SessionOnStream] returns [ErrNoDeadlineSupport] — set both
// options to zero and bound liveness in the transport instead.
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
//     [Upgrader.Handle]/[Upgrader.HandleRaw], [Upgrader.SessionOnStream], and
//     the handshake validation and negotiation helpers (the HTTP/1.1 Upgrade
//     and the HTTP/2/3 extended CONNECT)
//  4. client entry: [Dial]/[DialRaw] and the dial-time handshake
//  5. the raw face: [RawConn], [Event], [RawConn.ReadEvent], keepalive,
//     close-code resolution, [RawConn.WriteFrame]/[RawConn.Pong] and the
//     raw write surface
//  6. protocol core: terminal handling and permessage-deflate
//  7. wire format: the frame codec (readFrame, writeFrame)
//  8. protocol constants: close codes, frame opcodes, wire defaults
//  9. errors: [CloseError], [CloseCode], [ErrClosed], the sentinels
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
// calls [Session.ReadMessage] — or [Session.Drain], which runs that same
// read side to its terminal. Every other method is safe from any
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

// Close closes the underlying transport, exactly as [RawConn.Close]: it never
// blocks and never writes, so a connection that has been read to its terminal
// is already down here and this is an idempotent no-op. To close politely,
// send a close frame first with [Session.Shutdown] and let the read loop run
// to its terminal ([Session.Drain] runs that loop as one call); a bare Close
// is an abrupt close that the peer resolves to 1006. It is safe to call from
// any goroutine.
func (s *Session) Close() error { return s.raw.Close() }

// Shutdown starts the closing handshake the way RFC 6455 §7.1.2 defines it:
// it sends a close frame with the given code and reason and stops this side
// from sending more data, but leaves the transport up and the read side live.
// The peer's frames keep arriving on [Session.ReadMessage] until its own close
// lands, and that read loop ending is how the handshake completes — §7.1.5
// defines the connection's close code as the first close frame received, so
// reading is the only way to learn it.
//
// This is the writer's half of the close: write your last messages, Shutdown,
// then [Session.Close]. A reader instead loops on [Session.ReadMessage] until
// it returns the terminal error and then calls [Session.Close]. Shutdown is
// idempotent, safe from any goroutine, and returns the status of the close-
// frame write rather than how the connection ended.
func (s *Session) Shutdown(code int, reason string) error { return s.raw.Shutdown(code, reason) }

// Drain runs the session's read side to its terminal, consuming and
// discarding every message and control frame, and returns the terminal
// error: [io.EOF] for a clean end, a [*CloseError] otherwise — exactly what
// [Session.ReadMessage] would have returned last. It is [RawConn.Drain] on
// the session face: the read-side half of the closing sequence
// ([Session.Shutdown], Drain, [Session.Close]) as one call, for the
// writer's half of the connection, which wants the close to complete and its
// code learned without running the message loop.
//
// Events are discarded on the way: pings are answered automatically, exactly
// as [Session.ReadMessage] answers them, and data messages are not
// delivered. The terminal is the only information retained, and it carries
// the connection's close code (RFC 6455 §7.1.5).
//
// Like [Session.ReadMessage] it must only be called from the pumping
// goroutine, and never concurrently with [Session.ReadMessage]. On a
// connection that is already terminal it returns the recorded terminal at
// once. The wait it performs is bounded the way [RawConn.Drain] documents
// it: by the idle window when one is set, otherwise by the transport alone.
func (s *Session) Drain() error {
	for {
		_, _, readErr := s.ReadMessage()
		if readErr != nil {
			return readErr
		}
	}
}

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

// EffectiveIdleTimeout reports the idle window this session actually
// enforces, exactly as [RawConn.EffectiveIdleTimeout]: the configured window
// when the stream enforces read deadlines, and zero otherwise.
func (s *Session) EffectiveIdleTimeout() time.Duration {
	return s.raw.EffectiveIdleTimeout()
}

// EffectiveWriteTimeout reports the write bound this session actually
// enforces, exactly as [RawConn.EffectiveWriteTimeout]: the configured bound
// when the stream enforces write deadlines, and zero otherwise.
func (s *Session) EffectiveWriteTimeout() time.Duration {
	return s.raw.EffectiveWriteTimeout()
}

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
//
// The window binds only where the stream enforces read deadlines: over the
// standard library's extended-CONNECT streams, and over a [SessionOnStream]
// stream that does not implement [DeadlineStream], it cannot be enforced, so
// the upgrade (or [SessionOnStream]) is refused with [ErrNoDeadlineSupport]
// unless this option is zero — there, liveness is the transport's job.
func WithIdleTimeout(d time.Duration) Option {
	return func(cfg *Config) { cfg.IdleTimeout = d }
}

// WithWriteTimeout bounds how long a single [Session.WriteMessage] may block
// writing to the transport, so a blackholed peer cannot wedge the write
// mutex and, with it, [Session.Shutdown]. The default is 30 s; pass 0 to remove
// the bound (a write then blocks until the transport completes or the
// connection is closed). A negative bound is invalid and is replaced by
// the default, never by "unbounded".
//
// The bound binds only where the stream enforces write deadlines; over a
// stream that does not (see [WithIdleTimeout]) a session with a nonzero
// bound is refused with [ErrNoDeadlineSupport] unless this option is zero.
// [Session.EffectiveWriteTimeout] reports the bound a live session
// actually enforces.
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
// different origin. Behind a TLS-terminating proxy (request.TLS nil) the
// default derives the scheme as http, which is wrong in both directions:
// a legitimate https origin is rejected, and — the dangerous case — a
// browser page served from the same host over plain http (a different
// origin by the browser's own rules) passes the check, opening cross-site
// WebSocket hijacking for same-name deployments. Such deployments must set
// a custom check that validates Origin against the scheme the proxy
// forwarded (X-Forwarded-Proto as the proxy sets it, with the proxy
// stripping any client-supplied header) and a host allowlist.
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
//
// The library trusts the returned connection's deadline methods: if the
// dialer hands back a transport whose SetReadDeadline/SetWriteDeadline are
// no-ops, the read and write deadline options are unenforceable — the
// connection must have real deadline semantics, or the options must be
// zero.
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
// a second window. Behind a TLS-terminating proxy the default origin check
// cannot see the real scheme — replace it with a [WithCheckOrigin]
// allowlist keyed on the proxy-forwarded scheme; see [WithCheckOrigin].
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

// checkHandshakeHeaders validates the HTTP/1.1 Upgrade handshake on the
// request and returns its Sec-WebSocket-Key: the Connection and Upgrade
// tokens, then the shared version-and-key checks of [checkWebSocketKey]. The
// Connection and Upgrade tokens are HTTP/1.1-only; over HTTP/2 and HTTP/3 the
// protocol is named by the :protocol pseudo-header instead and those checks
// are skipped.
func checkHandshakeHeaders(writer http.ResponseWriter, request *http.Request) (string, *UpgradeError) {
	if !headerContainsToken(request.Header, "Connection", "Upgrade") {
		return "", rejectStatus(writer, http.StatusBadRequest, "missing Connection: Upgrade header")
	}
	if !headerContainsToken(request.Header, "Upgrade", "websocket") {
		return "", rejectStatus(writer, http.StatusBadRequest, "missing Upgrade: websocket header")
	}

	return checkWebSocketKey(writer, request)
}

// checkWebSocketKey validates the RFC 6455 §4.2 fields carried by BOTH the
// HTTP/1.1 Upgrade and the HTTP/2/3 extended-CONNECT handshake — exactly one
// supported Sec-WebSocket-Version and exactly one well-formed
// Sec-WebSocket-Key, the base64 of 16 octets — and returns the key. Several
// header lines for a single-value header are a malformed handshake: the value
// would be ambiguous, so they are rejected rather than resolved to the first
// line. Each rejection writes the HTTP error response itself; the
// version-mismatch response additionally names the version(s) the server
// understands, per §4.2.
// checkWebSocketVersion validates the Sec-WebSocket-Version header. It is
// shared by the HTTP/1.1 upgrade and the RFC 8441 extended-CONNECT path:
// the version is still required over a tunnel, but the handshake key is
// not — the key and its accept value are HTTP/1-only (RFC 8441 §5).
func checkWebSocketVersion(writer http.ResponseWriter, request *http.Request) *UpgradeError {
	versions := request.Header.Values("Sec-WebSocket-Version")
	if len(versions) == 0 {
		return rejectStatus(writer, http.StatusBadRequest, "missing Sec-WebSocket-Version header")
	}
	if len(versions) > 1 {
		return rejectStatus(writer, http.StatusBadRequest, "multiple Sec-WebSocket-Version headers")
	}
	if versions[0] != websocketVer {
		// RFC 6455 §4.2: the version-mismatch response names the
		// version(s) the server understands.
		writer.Header().Add("Sec-WebSocket-Version", websocketVer)

		return rejectStatus(writer, http.StatusUpgradeRequired, "unsupported websocket version")
	}

	return nil
}

func checkWebSocketKey(writer http.ResponseWriter, request *http.Request) (string, *UpgradeError) {
	versionErr := checkWebSocketVersion(writer, request)
	if versionErr != nil {
		return "", versionErr
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
// Over an extended CONNECT (HTTP/2 or HTTP/3) the connection's stream
// carries the frames. The stream exposes no per-stream deadline, so the
// read and write deadline options bind only where the stream can enforce
// them: with a nonzero [WithIdleTimeout] or [WithWriteTimeout] the
// extended-CONNECT upgrade is refused with a 501 before the tunnel opens
// (the HTTP/1.1 upgrade is unaffected — a hijacked net.Conn always
// enforces deadlines). Set both options to zero and bound liveness in the
// transport instead.
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
	// RFC 8441 / RFC 9220: over HTTP/2 and HTTP/3 the WebSocket handshake rides
	// an extended CONNECT instead of the HTTP/1.1 Upgrade, and the transport
	// surfaces the negotiated protocol as the :protocol pseudo-header. Branch on
	// the request shape so one handler serves a client that upgraded (h1) or
	// connected (h2/h3); on a toolchain whose HTTP/2 server does not route
	// extended CONNECT the branch is simply never taken and h1 is used.
	if request.Method == http.MethodConnect {
		return u.upgradeConnect(writer, request)
	}
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
	// A hijacked net.Conn always enforces deadlines, so finishRaw cannot
	// fail here; the guard keeps the path total if that ever changes.
	conn, finishErr := u.finishRaw(raw, buf.Reader, protocol, extension)
	if finishErr != nil {
		return nil, rejectOnConn(raw, http.StatusInternalServerError, finishErr.Error())
	}

	return conn, nil
}

// finishRaw assembles the upgraded raw connection: the frame codec on the
// upgraded channel with the negotiated session state and the permessage-deflate
// switch when the extension was granted. The caller wraps it in a [*Session]
// when the message-oriented view was asked for.
//
// It refuses the connection — [ErrNoDeadlineSupport] — when the upgrader has
// a nonzero idle or write window but the channel cannot enforce deadlines
// (does not implement [DeadlineStream]): the options must be real
// protections or absent, never silently inert. Set both options to zero to
// run over a deadline-less stream; liveness then rests on the transport's
// own idle timeout.
func (u *Upgrader) finishRaw(channel transport, read io.Reader, protocol, extension string) (*RawConn, error) {
	if (u.idleTimeout > 0 || u.writeTimeout > 0) && !deadlineCapable(channel) {
		return nil, ErrNoDeadlineSupport
	}
	conn := newRawConn(channel, read, false, u.maxMessageSize, u.idleTimeout, u.writeTimeout)
	conn.subprotocol = protocol
	if extension != "" {
		conn.applyCompression()
		conn.compressLevel = u.compressLevel
	}

	return conn, nil
}

// upgradeConnect handles a WebSocket that arrived as an HTTP/2 or HTTP/3
// extended CONNECT (RFC 8441 / RFC 9220). The handshake headers are the RFC
// 6455 set minus the HTTP/1.1-only Connection and Upgrade tokens — the
// protocol is named by the :protocol pseudo-header instead — and the response
// is a 200 whose body becomes the frame tunnel, kept open with full-duplex
// I/O. A CONNECT to any other protocol is not this request.
func (u *Upgrader) upgradeConnect(writer http.ResponseWriter, request *http.Request) (*RawConn, error) {
	if request.Header.Get(":protocol") != "websocket" {
		return reject(writer, http.StatusNotImplemented, "unsupported :protocol")
	}
	rejection := u.checkPolicy(writer, request)
	if rejection != nil {
		return nil, rejection
	}
	// RFC 8441 §5: over extended CONNECT the handshake key is superseded by
	// :protocol — no key is required and no accept value is generated. Only
	// the version is still validated.
	versionErr := checkWebSocketVersion(writer, request)
	if versionErr != nil {
		return nil, versionErr
	}
	protocol, protoErr := negotiateProtocol(u.subprotocols,
		strings.Join(request.Header.Values("Sec-WebSocket-Protocol"), ", "))
	if protoErr != nil {
		return reject(writer, http.StatusBadRequest, protoErr.Error())
	}
	extension, extErr := u.negotiateExtensions(request)
	if extErr != nil {
		return reject(writer, http.StatusBadRequest, extErr.Error())
	}
	// The response writer buffers separately from the frame codec's bufio, so
	// both the success headers and every frame write must be flushed at the
	// HTTP layer — without that, interactive traffic stalls (the 200 headers
	// and small frames were never delivered while the tunnel stayed open).
	controller := http.NewResponseController(writer)
	flush := func() error { return controller.Flush() }
	// The deadline gate runs before the tunnel opens: a stream that cannot
	// enforce the configured windows is refused up front, 501 — the options
	// must be real protections or zero, never silently inert.
	channel := streamTransport{body: request.Body, tunnel: writer, flush: flush}
	raw, finishErr := u.finishRaw(channel, channel, protocol, extension)
	if finishErr != nil {
		return reject(writer, http.StatusNotImplemented, finishErr.Error())
	}
	// The tunnel is full-duplex: the frame loop reads request.Body and writes
	// the response body interleaved until the stream closes.
	duplexErr := controller.EnableFullDuplex()
	if duplexErr != nil {
		return reject(writer, http.StatusInternalServerError, "full-duplex unsupported")
	}
	respondErr := respondExtendedConnect(writer, protocol, extension, flush)
	if respondErr != nil {
		return nil, rejectStatus(writer, http.StatusInternalServerError, respondErr.Error())
	}

	return raw, nil
}

// respondExtendedConnect writes the extended-CONNECT success response: a 200
// carrying any negotiated headers and, critically, a flush that delivers them
// before the tunnel carries frames. Unlike the HTTP/1.1 path there is no
// "Switching Protocols" status, no Upgrade/Connection headers, and no
// Sec-WebSocket-Accept — RFC 8441 §5 supersedes the handshake key with
// :protocol, so there is no key to accept.
func respondExtendedConnect(writer http.ResponseWriter, protocol, extension string, flush func() error) error {
	hdr := writer.Header()
	if protocol != "" {
		hdr.Set("Sec-WebSocket-Protocol", protocol)
	}
	if extension != "" {
		hdr.Set("Sec-WebSocket-Extensions", extension)
	}
	writer.WriteHeader(http.StatusOK)

	// Deliver the 200 before the tunnel carries any frame: a client that
	// waits on the handshake response stalls forever without this flush.
	return flush()
}

// deadlineNoop is the [DeadlineStream] for a channel that cannot enforce
// deadlines: the calls are error-free no-ops. A RawConn over such a channel
// exists only with the deadline options waived, so the no-op is honest —
// nothing is promised that is not enforced.
type deadlineNoop struct{}

func (deadlineNoop) SetReadDeadline(time.Time) error  { return nil }
func (deadlineNoop) SetWriteDeadline(time.Time) error { return nil }

// streamTransport adapts an extended-CONNECT stream to [transport]: reads come
// from the request body and writes go to the response tunnel, which
// [http.ResponseController.EnableFullDuplex] keeps open. The stream has no
// address of its own, so the address accessors report nil. HTTP/2 and HTTP/3
// expose no per-stream deadline, so the adapter has no deadline methods at
// all: deadline enforcement is structurally absent, and finishRaw refuses a
// session with a nonzero deadline option over it ([ErrNoDeadlineSupport])
// unless the options are zero, in which case liveness rests on the
// transport's own idle timeout.
type streamTransport struct {
	body   io.ReadCloser
	tunnel io.Writer
	// flush delivers buffered bytes at the HTTP response-writer layer; nil
	// (the SessionOnStream path) means the tunnel needs no separate flush.
	flush func() error
}

// Read, Write and Close are thin pass-throughs to the underlying transport:
// the frame codec already wraps their errors, and Read must deliver io.EOF
// unwrapped for the read loop's clean-end detection. Write also flushes the
// HTTP writer so a completed frame reaches the peer while the tunnel is open.
func (s streamTransport) Read(p []byte) (int, error) { return s.body.Read(p) } //nolint:wrapcheck

func (s streamTransport) Write(p []byte) (int, error) {
	written, err := s.tunnel.Write(p)
	if err == nil {
		if s.flush != nil {
			err = s.flush()
		}
	}

	return written, err
}

func (s streamTransport) Close() error {
	if closer, ok := s.tunnel.(io.Closer); ok {
		_ = closer.Close()
	}

	return s.body.Close() //nolint:wrapcheck
}

func (s streamTransport) RemoteAddr() net.Addr { return nil }

func (s streamTransport) LocalAddr() net.Addr { return nil }

// deadlineStream adapts a [DeadlineStream] that does not report addresses to
// the full [transport] surface: the deadline calls pass through to the
// stream, so the upgrader's deadline options bind, and the address accessors
// report nil. A stream that implements neither addresses nor deadlines is
// adapted by streamTransport instead, and its session is refused by finishRaw
// with [ErrNoDeadlineSupport] when a deadline option is nonzero.
type deadlineStream struct {
	rwc io.ReadWriteCloser
	ds  DeadlineStream
}

func (d deadlineStream) Read(p []byte) (int, error) {
	return d.rwc.Read(p) //nolint:wrapcheck // pass-through adapter: the stream's error is the error
}

func (d deadlineStream) Write(p []byte) (int, error) {
	return d.rwc.Write(p) //nolint:wrapcheck // pass-through adapter: the stream's error is the error
}

func (d deadlineStream) Close() error {
	return d.rwc.Close() //nolint:wrapcheck // pass-through adapter: the stream's error is the error
}

func (d deadlineStream) RemoteAddr() net.Addr { return nil }
func (d deadlineStream) LocalAddr() net.Addr  { return nil }

func (d deadlineStream) SetReadDeadline(t time.Time) error {
	return d.ds.SetReadDeadline(t)
}

func (d deadlineStream) SetWriteDeadline(t time.Time) error {
	return d.ds.SetWriteDeadline(t)
}

// DeadlineStream is implemented by a stream that can enforce read and write
// deadlines. A session built over a DeadlineStream — a stream handed to
// [SessionOnStream], or the hijacked net.Conn behind [Upgrader.Upgrade] —
// honors the upgrader's [WithIdleTimeout] and [WithWriteTimeout]. A stream
// that does not implement it cannot enforce them, so with either option
// nonzero the session is refused ([ErrNoDeadlineSupport] from
// [SessionOnStream]; a 501 from the extended-CONNECT branch of
// [Upgrader.Upgrade]).
//
// Implementing it is a claim, not a query: the library trusts that your
// deadlines actually fire and does not verify them. Do not implement no-ops
// to satisfy an interface — if the underlying transport cannot enforce
// deadlines, omit the methods, set the timeout options to zero, and bound
// liveness in your transport instead.
type DeadlineStream interface {
	SetReadDeadline(deadline time.Time) error
	SetWriteDeadline(deadline time.Time) error
}

// deadlineCapable reports whether channel can enforce read and write
// deadlines, i.e. implements [DeadlineStream]. A hijacked net.Conn always
// does; streamTransport has no deadline methods at all, so it never does.
func deadlineCapable(channel transport) bool {
	_, ok := channel.(DeadlineStream)

	return ok
}

// SessionOnStream builds a [*Session] over an already-established
// extended-CONNECT stream that the standard library does not drive — typically
// an HTTP/3 or QUIC stream from an external transport. The stream carries the
// WebSocket frames in both directions; the subprotocol and extension must
// already be negotiated. The session is refused — [ErrNoDeadlineSupport] —
// when the upgrader has a nonzero [WithIdleTimeout] or [WithWriteTimeout] but
// the stream cannot enforce deadlines: a stream that also reports an address
// and deadlines, as a [net.Conn] does, is used directly; a stream that
// implements [DeadlineStream] without addresses is adapted so its deadlines
// pass through; a bare stream reports a nil address and carries the no-op
// deadline enforcement, so
// the deadline options must be zero over it. Standard-library HTTP/2 callers use [Upgrader.Upgrade]
// instead, which detects the extended CONNECT itself.
func (u *Upgrader) SessionOnStream(stream io.ReadWriteCloser, subprotocol, extension string) (*Session, error) {
	var channel transport
	if full, ok := stream.(transport); ok {
		channel = full
	} else if ds, ok := stream.(DeadlineStream); ok {
		channel = deadlineStream{rwc: stream, ds: ds}
	} else {
		channel = streamTransport{body: stream, tunnel: stream}
	}
	raw, err := u.finishRaw(channel, stream, subprotocol, extension)
	if err != nil {
		return nil, err
	}

	return newSession(raw, u.pongHandler), nil
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
		// The teardown is armed the moment the upgrade succeeds, so an
		// application panic still closes the connection: net/http's
		// recovery path deliberately skips hijacked connections and would
		// otherwise leak the transport. The panic propagates after the
		// cleanup — never swallowed.
		defer func() {
			if panicked := recover(); panicked != nil {
				_ = conn.Shutdown(StatusUnexpectedCondition, "handler panic")
				_ = conn.Close()

				panic(panicked)
			}
		}()

		closeAfterHandler(conn.raw, handler(request, conn))
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
		// Same panic-safety as [Upgrader.Handle]: the teardown is armed
		// immediately after the upgrade so a panicking callback cannot leak
		// the hijacked transport; the panic propagates after cleanup.
		defer func() {
			if panicked := recover(); panicked != nil {
				_ = conn.Shutdown(StatusUnexpectedCondition, "handler panic")
				_ = conn.Close()

				panic(panicked)
			}
		}()

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
func closeAfterHandler(conn *RawConn, err error) {
	var closeErr *CloseError
	code, reason := StatusNormalClosure, ""
	switch {
	case errors.As(err, &closeErr):
		code = closeErr.Code
		reason = closeErr.Reason
		if code < closeCodeMin || code > closeCodeMax {
			// An out-of-range code cannot go on the wire; tear down with
			// 1002 so the connection is always closed.
			code, reason = StatusProtocolError, "invalid close code from handler"
		}
	case err != nil:
		code, reason = StatusUnexpectedCondition, "handler failure"
	}
	// The server does not drain here. RFC 6455 §7.1.1 draws the asymmetry
	// explicitly: a server instructed to close "SHOULD initiate a TCP Close
	// immediately", where it is the client that "SHOULD wait for a TCP Close
	// from the server". The handler's own read loop has already returned, so
	// there is no reader left to complete the handshake with, and waiting for
	// a peer that may never answer is exactly what this path must not do.
	_ = conn.Shutdown(code, reason)
	_ = conn.Close()
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
//
// The scheme comes from request.TLS, so a request that reached the server
// through a TLS-terminating proxy compares against http://<Host>; see
// [WithCheckOrigin] for why such deployments must set their own check.
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
	// hasClientWindowBits records whether client_max_window_bits appears at
	// all — valued or value-less — since RFC 7692 §7.1.2.2 forbids it in a
	// response to an offer that did not carry it. (Its value, when valued,
	// is validated by parseWindowBits but never needed: this client offers
	// no client window and its compressor always uses the full one.)
	hasClientWindowBits bool
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
			params.hasClientWindowBits = true
			_, windowErr := checkWindowBits(key, value, hasValue, false)
			if windowErr != nil {
				return params, windowErr
			}
		case "server_max_window_bits":
			bits, err := checkWindowBits(key, value, hasValue, true)
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

// unquoteExtensionValue applies RFC 6455 §9.1 to one extension parameter
// value: a quoted-string value is unescaped before the parameter-specific
// validation, and the quoting itself is validated — a closing DQUOTE at the
// end of the value, every backslash escaping a legal character (SP / HTAB /
// %x21-7E), and only token-compatible characters (HTAB, SP, %x21-7E)
// unescaped. Unquoted values pass through unchanged.
func unquoteExtensionValue(value string) (string, error) {
	if value == "" || value[0] != '"' {
		return value, nil
	}
	var out strings.Builder
	for idx := 1; idx < len(value); idx++ {
		switch cur := value[idx]; cur {
		case '"':
			if idx+1 != len(value) {
				return "", fmt.Errorf("%w: trailing characters after quoted value %q", errBadExtension, value)
			}

			return out.String(), nil
		case '\\':
			if idx+1 >= len(value) {
				return "", fmt.Errorf("%w: dangling escape in quoted value %q", errBadExtension, value)
			}
			next := value[idx+1]
			escapeErr := invalidEscape(next, value)
			if escapeErr != nil {
				return "", escapeErr
			}
			out.WriteByte(next)
			idx++
		default:
			quotedErr := invalidQuoted(cur, value)
			if quotedErr != nil {
				return "", quotedErr
			}
			out.WriteByte(cur)
		}
	}

	return "", fmt.Errorf("%w: unterminated quoted value %q", errBadExtension, value)
}

// invalidEscape reports whether a backslash escapes an illegal character in
// an RFC 6455 §9.1 quoted value: anything but a double-quote, a backslash,
// or a printable ASCII byte (SP .. ~).
func invalidEscape(next byte, value string) error {
	if next != '"' && next != '\\' && (next < 0x20 || next > 0x7e) {
		return fmt.Errorf("%w: invalid escape in quoted value %q", errBadExtension, value)
	}

	return nil
}

// invalidQuoted reports whether a bare character is illegal in an RFC 6455
// §9.1 quoted value: anything but HTAB or a printable ASCII byte (SP .. ~).
func invalidQuoted(ch byte, value string) error {
	if ch != 0x09 && (ch < 0x20 || ch > 0x7e) {
		return fmt.Errorf("%w: invalid character in quoted value %q", errBadExtension, value)
	}

	return nil
}

// checkWindowBits validates a max_window_bits parameter value, unquoting a
// quoted value first (RFC 6455 §9.1). required reports whether the key
// demands a value: server_max_window_bits does, client_max_window_bits does
// not. A missing value on a non-required key is valid and returns zero.
func checkWindowBits(key, value string, hasValue, required bool) (int, error) {
	if !hasValue {
		if required {
			return 0, fmt.Errorf("%w: %q requires a value", errBadExtension, key)
		}

		return 0, nil
	}
	unquoted, unquoteErr := unquoteExtensionValue(value)
	if unquoteErr != nil {
		return 0, unquoteErr
	}

	return parseWindowBits(unquoted)
}

// parseWindowBits validates a max_window_bits value: decimal digits
// (RFC 7692 §7.1.2: 1*DIGIT), no leading zeroes, 8-15. A value with any
// non-digit — "+10", "1a", ".5" — is malformed, not out of range.
func parseWindowBits(value string) (int, error) {
	if len(value) > 1 && value[0] == '0' {
		return 0, fmt.Errorf("%w: leading zero in window bits %q", errBadExtension, value)
	}
	for i := range value {
		ch := value[i]
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("%w: non-numeric window bits %q", errBadExtension, value)
		}
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
// A malformed offer — an unrecognized extension (RFC 6455 §9.1) or an
// invalid parameter — fails the handshake. RFC 7692 §7 permits several
// permessage-deflate offers as alternative configurations, ordered by
// preference: the first alternative the server can honor wins. An
// alternative that is well-formed but demands a smaller compressor window
// than this implementation can use (server_max_window_bits below the full
// 15 bits) is skipped, and the offer is declined — the response carries no
// extension and the connection proceeds uncompressed — when no alternative
// can be honored (RFC 7692 §7.1.2.1).
func negotiateCompression(groups []string) (string, error) {
	for _, group := range groups {
		name, _, _ := strings.Cut(group, ";")
		name = strings.TrimSpace(name)
		if !strings.EqualFold(name, extPerMessageDeflate) {
			return "", fmt.Errorf("%w: unsupported extension %q", errBadExtension, name)
		}
		params, err := parseCompressionParams(group)
		if err != nil {
			return "", err
		}
		// Our compressor always uses the full 32 KiB window, so a limit
		// below 15 bits cannot be honored: try the next alternative
		// (declining when this was the last one), per the doc comment.
		if bits := params.serverWindowBits; bits != 0 && bits < maxWindowBits {
			continue
		}

		return deflateResponseHeader, nil
	}

	return "", nil // no extension offered, or every alternative declined
}

// verifyCompressionResponse validates the Sec-WebSocket-Extension header
// of a 101 response against what this client offered (RFC 7692 §5.1): the
// server must not select an extension the client never offered, must select
// permessage-deflate at most once, and must honor the response-side MUSTs
// of §7.1: this client's offer carries server_no_context_takeover, so the
// response must carry it too (§7.1.1.1 — its absence means the server may
// use context takeover, streams the per-message-resetting decompressor
// cannot decode); and because the offer carries no client_max_window_bits,
// the response must not either (§7.1.2.2), valued or value-less. The
// server may set server_max_window_bits even unoffered (§7.1.2.1): that
// parameter configures the SERVER's compressor and client decompressor
// (RFC 7692 §7), and this client decodes with the full window, so any
// supported smaller server window is accepted without restricting this
// client's compressor.
// It reports whether compression was negotiated.
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
	if !params.serverNoTakeover {
		return false, fmt.Errorf("%w: 101 response omits server_no_context_takeover",
			errHandshakeFailed)
	}
	if params.hasClientWindowBits {
		return false, fmt.Errorf("%w: 101 response sets the unoffered parameter client_max_window_bits",
			errHandshakeFailed)
	}
	// §7.1.2.1: server_max_window_bits may appear in the response even
	// unoffered. It bounds the server's compressor window, which this
	// client's full-window decompressor decodes unconditionally — no
	// rejection here, whatever the supported value.

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
// ws:// URLs and TLS with the system root store for wss:// URLs. The SNI
// server name is serverName (the dial host's hostname), so the default
// transport performs real hostname verification against the server's
// certificate; a dial by IP address verifies against IP SANs. Custom
// transport policy — custom root stores, client certificates, proxy
// tunnels — goes through [WithDialer], which replaces this entirely.
func dialTransport(ctx context.Context, host, serverName string, isTLS bool) (net.Conn, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("ws: dial %s: %w", host, err)
	}
	if isTLS {
		// serverName is set from the dial host's hostname so the handshake
		// verifies the server's certificate against the host (and sends SNI):
		// crypto/tls refuses to handshake a client with neither ServerName nor
		// InsecureSkipVerify, so an empty config would fail every wss dial.
		// The empty otherwise (no RootCAs) keeps the system root store.
		tconn := tls.Client(conn, &tls.Config{ServerName: serverName})
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
		conn, err = dialTransport(ctx, host, target.Hostname(), isTLS)
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
	// The cancellation hook bounds the handshake itself, not just the
	// connect: once the transport is up, a cancelled context must be able
	// to unblock a pending handshake on a stalled transport — with or
	// without a deadline. The hook is disarmed before a live connection is
	// returned, so cancelling the establishment context afterwards cannot
	// close an established session.
	hook := installCancelHook(ctx, conn)
	key, reqErr := writeHandshakeRequest(conn, path, host,
		cfg.Subprotocols, cfg.Compression, cfg.Headers)
	if reqErr != nil {
		hook.stop()
		_ = conn.Close()

		return nil, nil, reqErr
	}
	subprotocol, compressed, respErr := readHandshakeResponse(reader, key, cfg.Subprotocols, cfg.Compression)
	if respErr != nil {
		hook.stop()
		_ = conn.Close()

		return nil, nil, respErr
	}
	if !hook.stop() {
		// The establishment was cancelled between the handshake finishing
		// and the hook being disarmed: the hook already closed the
		// transport, and the dial fails rather than handing over a dead
		// session.
		_ = conn.Close()

		return nil, nil, fmt.Errorf("ws: handshake cancelled: %w", ctx.Err())
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

// cancelHook closes conn if the establishment context is cancelled while
// the handshake is in flight, and synchronizes the disarm (stop) against
// the cancel exactly once: whichever outcome wins first is the only one
// that takes effect, so a cancel racing the disarm can neither close an
// established session nor slip past the failed-dial report.
type cancelHook struct {
	mu      sync.Mutex
	outcome int // 0 pending, 1 cancelled, 2 stopped
	conn    net.Conn
	// stopped is closed by stop to release the watcher goroutine. It is a
	// plain channel, deliberately NOT derived from the establishment
	// context: a child context would become ready at the same instant the
	// parent is cancelled, and the watcher's select could then take the
	// disarm branch and exit without closing the transport.
	stopped chan struct{}
}

// installCancelHook arms the hook and starts its watcher goroutine. The
// watcher exits when the hook is disarmed (stop) or when the establishment
// context is cancelled (it closes the transport first), so no goroutine
// outlives the handshake.
func installCancelHook(ctx context.Context, conn net.Conn) *cancelHook {
	hook := &cancelHook{conn: conn, stopped: make(chan struct{})}
	go func() {
		select {
		case <-ctx.Done():
			hook.fire()
		case <-hook.stopped:
			// disarmed; the watcher exits with the handshake
		}
	}()

	return hook
}

// fire records the cancellation win and closes the transport.
func (h *cancelHook) fire() {
	h.mu.Lock()
	if h.outcome != 0 {
		h.mu.Unlock()

		return
	}
	h.outcome = 1
	h.mu.Unlock()
	_ = h.conn.Close()
}

// stop disarms the hook, synchronizing against a concurrent cancellation
// exactly once: whichever outcome wins first is the only one that takes
// effect. It reports true when the connection may live on as an
// established session, and false when the establishment was cancelled (the
// hook closed the transport).
func (h *cancelHook) stop() bool {
	h.mu.Lock()
	if h.outcome != 0 {
		cancelled := h.outcome == 1
		h.mu.Unlock()

		return !cancelled
	}
	h.outcome = 2
	h.mu.Unlock()
	close(h.stopped)

	return true
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

// handshakeHeaderLimit bounds the total byte size of the handshake
// response's status line and headers. A legitimate 101 is a handful of
// short headers (well under a KiB); the cap exists only so a malicious or
// compromised server cannot exhaust client memory by streaming an unbounded
// number of handshake headers, which the bare http.ReadResponse would
// otherwise accumulate without limit. It matches the stdlib http client's
// default response-header cap.
const handshakeHeaderLimit = 1 << 20

// readHandshakeResponseHead reads the handshake response's status line and
// headers from reader, bounded, and returns the raw bytes up to and
// including the terminating blank line. The reader is left positioned
// immediately after that blank line — at the first frame — so the frame
// codec can continue from it.
//
// The bound is enforced two ways: any single header line longer than the
// reader's buffer is rejected (bufio.ReadSlice reports ErrBufferFull without
// pulling more), and the accumulated header set is capped at
// handshakeHeaderLimit. A bare http.ReadResponse has neither limit, so this
// pre-read is what stops a hostile server from a header-flood memory DoS.
func readHandshakeResponseHead(reader *bufio.Reader) ([]byte, error) {
	head := make([]byte, 0, bufSize)
	for {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, fmt.Errorf("%w: handshake response ended without a complete header set: %w", errHandshakeFailed, err)
		}
		head = append(head, line...)
		if len(head) > handshakeHeaderLimit {
			return nil, fmt.Errorf(
				"%w: handshake response headers exceed the %d byte limit", errHandshakeFailed, handshakeHeaderLimit)
		}
		if string(line) == "\r\n" {
			return head, nil
		}
	}
}

// readHandshakeResponse reads and verifies the server's 101 response,
// returning the negotiated subprotocol and whether permessage-deflate was
// negotiated.
func readHandshakeResponse(reader *bufio.Reader, key string, offered []string,
	compressionOffered bool,
) (string, bool, error) {
	// Bound the status line + headers before parsing: see
	// readHandshakeResponseHead. The response is parsed from the bounded
	// in-memory copy, not the live reader — for a 101 the parser records no
	// body, and the frames are read from the original reader, which the
	// head read positioned right after the terminating blank line.
	head, headErr := readHandshakeResponseHead(reader)
	if headErr != nil {
		return "", false, headErr
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(head)), nil)
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
	// stClosing: a Close frame has been sent and the transport is still open,
	// waiting for the peer's Close to complete the closing handshake
	// (RFC 6455 7.1.3).
	stClosing
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
// time. Every write, [RawConn.Shutdown], and [RawConn.Close] is safe from
// any goroutine.
//
// The close API is the RFC's own three-step example (§7.1.1) with one method
// per step: [RawConn.Shutdown] sends this endpoint's Close frame and half-
// closes the write side, the read side finishing is [RawConn.ReadEvent] run
// to its terminal — or [RawConn.Drain], which runs that loop and reports
// the terminal — and [RawConn.Close] closes the transport. Nothing can wait
// for the closing handshake without reading, because reading is what
// finishes it and what learns the close code; the drain, like the loop,
// belongs to the pumping goroutine.
type RawConn struct {
	nc transport
	// deadlines is the channel's deadline enforcement, resolved once at
	// construction: the channel's own methods when it implements
	// [DeadlineStream], deadlineNoop otherwise. Every read and write
	// deadline call on the connection goes through this field, so
	// capability is decided in one place — at creation — and the call
	// sites never ask.
	deadlines DeadlineStream
	fc        frameCodec
	mu        sync.Mutex // serializes the write path

	id          uint64
	subprotocol string

	state    atomic.Int32 // stOpen, stClosing, or stClosed
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

// transport is the bidirectional channel a [RawConn] runs its frames on. It is
// the subset of [net.Conn] the protocol engine needs — deliberately without
// the deadline methods: deadline enforcement is a separate, checked
// capability ([DeadlineStream]), not part of the channel contract. A channel
// that cannot enforce deadlines is still a transport; a [RawConn] over it
// carries the no-op [deadlineNoop] in its deadlines field instead. A
// [net.Conn] satisfies transport directly; an extended-CONNECT stream
// satisfies it via [streamTransport]. Addresses may be unavailable on a
// stream — a nil address — and [RawConn] surfaces exactly what the channel
// reports.
type transport interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
}

func newRawConn(channel transport, read io.Reader, isClient bool, maxMessageSize int64,
	idleTimeout, writeTimeout time.Duration,
) *RawConn {
	var reader *bufio.Reader
	if existing, ok := read.(*bufio.Reader); ok {
		reader = existing
	} else {
		reader = bufio.NewReaderSize(read, bufSize)
	}
	var deadlines DeadlineStream = deadlineNoop{}
	if de, ok := channel.(DeadlineStream); ok {
		deadlines = de
	}

	return &RawConn{
		nc:        channel,
		deadlines: deadlines,
		fc: frameCodec{
			br:       reader,
			bw:       bufio.NewWriterSize(channel, bufSize),
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
			_ = c.deadlines.SetReadDeadline(time.Time{})
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
			// The close is resolved: echo it if we haven't sent one ourselves,
			// then close the transport and record the terminal; the next
			// ReadEvent reports that terminal error.
			c.finalizeClose(code, reason)

			return Event{Op: OpClose, Code: code, Reason: reason}, nil
		case OpText, OpBinary, OpContinuation:
			msgOp, payload, complete, closeCode, dataErr := c.readData(frm)
			if dataErr != nil {
				// A protocol violation the peer can still receive a Close frame
				// for (the 7.1.7 SHOULD): answer with the code readData
				// reports. A decompression failure (code 0) owes no Close frame
				// here and is reported directly.
				if closeCode != 0 {
					what := strings.TrimPrefix(dataErr.Error(), errProtocol.Error()+": ")

					return Event{}, c.failWith(closeCode, what)
				}

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
		if retry && c.fc.pulled > 0 {
			// A keepalive timeout interrupted a frame whose bytes were
			// already consumed: a retry would re-read the remaining
			// payload as a new frame and could deliver a corrupted
			// success. The only safe recovery is to fail the
			// connection; bytes of an interrupted frame are never
			// reinterpreted as protocol structure.
			return frame{}, c.finish(err)
		}
		if retry {
			continue
		}
		if errors.Is(connErr, io.EOF) {
			// The transport ended without a close frame: an abnormal
			// closure (RFC 6455 §7.1.5). Report status 1006 — a code
			// that is never transmitted on the wire — and never as
			// io.EOF, the documented clean-close signal, so transport
			// loss stays distinguishable from a normal protocol
			// shutdown.
			return frame{}, c.finish(errTransportAbnormalClose)
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
// reports whether a possibly fragmented message has ended. On a protocol
// failure it also returns the close code the peer should be told (the 7.1.7
// SHOULD): 1002 for a message-level violation, 1007 for a non-UTF-8 text
// message, and 0 when no Close frame is owed (a decompression failure, which
// the caller reports directly).
func (c *RawConn) readData(frm frame) (Op, []byte, bool, int, error) {
	msgOp, payload, complete, compressed, msgErr := c.handleData(frm)
	if msgErr != nil {
		// A message-level protocol violation (a continuation without a start,
		// a data frame mid-fragment, a cross-frame overflow): the peer is
		// still the sender and can receive a Close frame, so the 7.1.7
		// SHOULD applies — answer with 1002, uniform with the frame-level
		// violations the read loop already answers.
		return 0, nil, false, StatusProtocolError, msgErr
	}
	if !complete {
		return 0, nil, false, 0, nil
	}
	out := payload
	if compressed {
		c.fragCompressed = false
		expanded, err := c.decompress(payload)
		if err != nil {
			// A decompression failure fails the connection but owes the peer
			// no Close frame here (out of scope for the 7.1.7 reassembly
			// contract): the caller reports the error directly (code 0).
			return 0, nil, false, 0, err
		}

		out = expanded
	}
	if msgOp == OpText && !utf8.Valid(out) {
		// RFC 6455 §5.6: a peer MUST close on a non-UTF-8 text frame; 1007
		// is the close the browser implementations assign to exactly this.
		return 0, nil, false, StatusInvalidDataType,
			fmt.Errorf("%w: text message is not valid UTF-8", errProtocol)
	}

	return msgOp, out, true, 0, nil
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
			total := len(c.fragBuf) + len(frm.payload)
			c.inFrag, c.fragBuf, c.fragCompressed = false, nil, false

			return 0, nil, false, false, fmt.Errorf(
				"%w: message of %d bytes exceeds the %d byte limit", errProtocol, total, c.fc.maxMsg)
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
// the silence timeout that killed the connection). With keepalive disabled
// (a zero idle window) the timeout belongs to the application's own read
// deadline, not the idle window: no probe is sent and the read fails with
// it, so the deadline the application manages is the one that decides.
func (c *RawConn) keepaliveTimeout(err error) (bool, error) {
	if !isReadTimeout(err) {
		return false, err
	}
	if c.idleTimeout <= 0 {
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

	return c.deadlines.SetReadDeadline(deadline)
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
// (§7.1.5); an unusable code is never echoed back. The reason, when
// present, must be valid UTF-8 — it is the UTF-8 of a text message
// (§5.5) — or the connection is failed with 1002 as well (§8.1); a
// non-UTF-8 reason is never delivered to the application.
func (c *RawConn) resolvePeerClose(payload []byte) (int, string, error) {
	if len(payload) == 1 {
		return 0, "", c.failProtocol("close frame with one-byte payload")
	}
	if len(payload) >= closeCodeBytes {
		code := int(binary.BigEndian.Uint16(payload[:closeCodeBytes]))
		if !usableCloseCode(code) {
			return 0, "", c.failProtocol(fmt.Sprintf("close frame with unusable status code %d", code))
		}
		if !utf8.Valid(payload[closeCodeBytes:]) {
			// RFC 6455 §7.1.5: the reason, when present, is the UTF-8 of
			// a text message, and §8.1 fails the connection on a
			// non-UTF-8 stream. Never hand the raw bytes to the
			// application: a peer could otherwise plant arbitrary bytes
			// (newlines included) in CloseError.Reason.
			return 0, "", c.failProtocol("close frame with non-UTF-8 reason")
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
// failWith answers a protocol error with a Close frame carrying the given
// status code and fails the connection; it returns the terminal error
// recorded on the connection. This is the RFC 6455 7.1.7 SHOULD: an endpoint
// failing the connection SHOULD send a Close frame with an appropriate status
// code before proceeding to Close the connection. failProtocol is failWith
// with 1002, the code the SHOULD carries for a protocol violation that is not
// the invalid-data-type 1007.
func (c *RawConn) failWith(code int, what string) error {
	// Send the close frame (the 7.1.7 SHOULD) and finalize immediately on the
	// code we are answering with — the peer's close is not expected here (we
	// are failing the connection, not completing a handshake it initiated), so
	// there is nothing to wait for and the transport goes down at once.
	_ = c.Shutdown(code, what)

	return c.finish(closeErrFor(code, what))
}

func (c *RawConn) failProtocol(what string) error { return c.failWith(StatusProtocolError, what) }

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
// normal closure. The caller must hold c.mu: closeErr is written under it by
// whichever path drove the connection to stClosed.
func (c *RawConn) closedWriteErr() error {
	if c.closeErr != nil {
		return c.closeErr
	}

	return ErrClosed
}

// writeFrame writes a frame, taking the write lock. It serves every frame
// write on the connection — the automatic pong and keepalive ping, and
// the application control writes ([RawConn.Ping], [RawConn.Pong]) — each
// of which validates its own use. A closed connection yields
// [RawConn.closedWriteErr], never a silent success.
//
// A transport-level write failure fails the connection — terminal state
// with the error recorded, transport closed — exactly as the data writes
// do: a ping or pong that cannot reach the peer means the pipe is broken,
// and leaving the connection nominally open would keep background writers
// running and a blocked reader asleep. Validation failures are not
// transport failures and leave the connection untouched.
func (c *RawConn) writeFrame(opcode Op, payload []byte, compressed bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.Load() != stOpen {
		return c.closedWriteErr()
	}
	if c.writeTimeout > 0 {
		// The same bound WriteMessage applies: an internal frame (pong,
		// keepalive ping) written to a stalled transport must fail on
		// deadline, not wedge the read loop or hold the write mutex
		// against Close. Cleared on return so the bound is per-frame.
		_ = c.deadlines.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	writeErr := c.fc.writeFrame(opcode, payload, compressed, true)
	c.clearWriteDeadline()
	if writeErr != nil {
		// A transport-level frame write failure breaks the connection
		// exactly as a data-write failure does (finding 2), so the failure
		// is terminal, not merely returned.
		c.failTransportWrite(writeErr)
	}

	return writeErr
}

// failTransportWrite applies the terminal-failure verdict to a failed
// transport write, with the write lock already held: a write that reached
// the transport and failed means the pipe is broken, so the connection is
// failed with the error recorded and the transport is closed, as
// [RawConn.Close] does. It is idempotent through the state check, so a
// racing Close or reader-goroutine failure cannot double-record. The
// caller still returns the write error itself. Validation failures are
// not transport failures and must not use this.
func (c *RawConn) failTransportWrite(writeErr error) {
	if c.state.Load() != stClosed {
		c.state.Store(stClosed)
		c.closeErr = writeErr
		_ = c.nc.Close()
	}
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
// to a failed pong or keepalive probe. Later writes then return the
// recorded error at once instead of re-stalling, [Closed]
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
	if c.state.Load() != stOpen {
		// Read the recorded error while still holding the lock: closeErr is
		// written under c.mu by the read path, so reading it after unlocking
		// would race the very close this branch reports.
		writeErr := c.closedWriteErr()
		c.mu.Unlock()

		return writeErr
	}
	if c.fragWriting {
		c.mu.Unlock()

		return fmt.Errorf("%w: a fragmented message is in progress; finish it before starting a new one", errProtocol)
	}
	if c.writeTimeout > 0 {
		// Bound the write so a blackholed transport cannot hold the write
		// mutex forever: a stuck write must fail (releasing the mutex) so
		// [RawConn.Shutdown] can still get its close frame out. Cleared on return
		// so the bound is per-write, not sticky.
		_ = c.deadlines.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	// permessage-deflate (RFC 7692 §6.1): the whole message is one raw
	// DEFLATE stream and RSV1 marks the single frame as compressed.
	// Compressing happens under the write lock, with the compressor's
	// scratch therefore owned by exactly one writer at a time.
	frame, compressed := data, false
	if c.deflateNegotiated {
		compressErr := c.compress(data)
		if compressErr != nil {
			c.clearWriteDeadline()
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
			c.clearWriteDeadline()
			c.mu.Unlock()

			return fmt.Errorf("%w: compressed message of %d bytes exceeds the %d byte limit",
				errMessageTooBig, len(frame), c.fc.maxMsg)
		}
	}
	writeErr := c.fc.writeFrame(opcode, frame, compressed, true)
	c.clearWriteDeadline()
	if writeErr != nil {
		c.failTransportWrite(writeErr)
	}
	c.mu.Unlock()

	return writeErr
}

// clearWriteDeadline undoes the bound [RawConn] armed before a write, so the
// library timeout is per-write, not sticky; an application-managed deadline
// (the library timeout disabled) is left untouched.
func (c *RawConn) clearWriteDeadline() {
	if c.writeTimeout > 0 {
		_ = c.deadlines.SetWriteDeadline(time.Time{})
	}
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
	if c.state.Load() != stOpen {
		writeErr := c.closedWriteErr()
		c.mu.Unlock()

		return writeErr
	}
	if opcode == OpContinuation && !c.fragWriting {
		// The stream has no message in progress for this to continue.
		c.mu.Unlock()

		return fmt.Errorf("%w: continuation frame without a start frame in progress", errProtocol)
	}
	if c.fragWriting && (opcode == OpText || opcode == OpBinary) {
		// RFC 6455 §5.4: a new data message cannot be started while a
		// fragmented message is in progress; control frames may still be
		// interleaved and the in-progress message must be finished first.
		c.mu.Unlock()

		return fmt.Errorf("%w: a fragmented message is in progress; finish it before starting a new one", errProtocol)
	}
	if opcode <= OpBinary {
		// Data frames — continuation, text, and binary, the opcodes 0-2 —
		// drive the fragmentation state; control frames cannot fragment
		// and leave the state untouched.
		c.fragWriting = more
	}
	if c.writeTimeout > 0 {
		_ = c.deadlines.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	}
	writeErr := c.fc.writeFrame(opcode, payload, false, !more)
	if c.writeTimeout > 0 {
		// Clear the bound the write armed; an application-managed
		// deadline (the library timeout disabled) is left untouched.
		_ = c.deadlines.SetWriteDeadline(time.Time{})
	}
	if writeErr != nil {
		c.failTransportWrite(writeErr)
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
// A ping is a control frame, so its payload is at most 125 bytes — and, as
// on the read side, it must also respect the connection's message size
// limit, since the limit applies to every frame the peer receives.
//
// A transport-level write failure fails the connection exactly as a data
// write does — terminal state, transport closed — because a ping that
// cannot reach the peer means the pipe is broken; validation failures
// (oversized payload) leave the connection untouched.
func (c *RawConn) Ping(payload []byte) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("%w: ping payload of %d bytes exceeds the %d byte control-frame limit",
			errProtocol, len(payload), maxControlPayload)
	}
	if int64(len(payload)) > c.fc.maxMsg {
		return fmt.Errorf("%w: ping of %d bytes exceeds the %d byte limit",
			errMessageTooBig, len(payload), c.fc.maxMsg)
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
// A pong is a control frame, so its payload is at most 125 bytes — and, as
// on the read side, it must also respect the connection's message size
// limit. A transport-level write failure fails the connection exactly as
// a data write does, as with [RawConn.Ping]; validation failures leave the
// connection untouched.
func (c *RawConn) Pong(payload []byte) error {
	if len(payload) > maxControlPayload {
		return fmt.Errorf("%w: pong payload of %d bytes exceeds the %d byte control-frame limit",
			errProtocol, len(payload), maxControlPayload)
	}
	if int64(len(payload)) > c.fc.maxMsg {
		return fmt.Errorf("%w: pong of %d bytes exceeds the %d byte limit",
			errMessageTooBig, len(payload), c.fc.maxMsg)
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
// not hold up other writers or [RawConn.Shutdown]; a marshal failure is returned
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

// buildClosePayload assembles the close frame payload from a close code that
// is already known to be in the valid range: the two-byte status plus the
// reason, for codes that may carry a status. Codes that MUST NOT appear as
// a status on the wire (1004-1006, 1015, RFC 6455 §7.4) yield an empty
// payload; a non-UTF-8 reason is dropped (§5.5: the reason is the UTF-8 of a
// text message); and the whole payload is truncated to the 125-byte frame
// limit (2-byte code + reason).
func (c *RawConn) buildClosePayload(code int, reason string) []byte {
	if mustNotSetCloseCode(code) {
		return nil
	}
	if !utf8.ValidString(reason) {
		reason = ""
	}
	reason = truncateReason(reason)
	payload := make([]byte, closeCodeBytes+len(reason))
	// #nosec G115 -- every caller passes a code already vetted by usableCloseCode
	// (1000..4999), so the conversion to the wire's 2-byte field cannot truncate.
	binary.BigEndian.PutUint16(payload, uint16(code))
	copy(payload[closeCodeBytes:], reason)

	return payload
}

// sendCloseFrame sends a close frame with the given code and reason on a
// connection that has not sent one yet, moving it to stClosing. It does not
// close the transport: that happens when the peer's close is read and resolved
// (see [RawConn.Shutdown]), or immediately in [RawConn.Close]. It is the
// single place the library writes a close frame, so it is safe to call from
// any goroutine and from the read path (the echo of the peer's close).
//
// It returns the status of the close-frame write, bounded by the connection's
// write timeout when set and by a fixed fallback otherwise, so a silent or
// half-dead peer cannot hold the close open forever. On a connection that is
// already closing or closed it sends no second frame and returns the recorded
// (or [ErrClosed]) error.
func (c *RawConn) sendCloseFrame(code int, reason string) error {
	c.mu.Lock()
	if c.state.Load() != stOpen {
		writeErr := c.closedWriteErr()
		c.mu.Unlock()

		return writeErr
	}
	payload := c.buildClosePayload(code, reason)
	c.state.Store(stClosing)
	closeBound := closeWriteTimeout
	if c.writeTimeout > 0 {
		closeBound = c.writeTimeout
	}
	// The close frame is sent best-effort: the kernel delivers queued data
	// before the FIN, so it reaches the peer in order when the transport
	// allows.
	_ = c.deadlines.SetWriteDeadline(time.Now().Add(closeBound))
	writeErr := c.fc.writeFrame(OpClose, payload, false, true)
	_ = c.deadlines.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		// A close frame that cannot reach the peer means the pipe is broken:
		// the same verdict as any other transport-level write failure, so the
		// connection is failed with the write error recorded rather than left
		// sitting in stClosing on a dead transport.
		c.failTransportWrite(writeErr)
	}
	c.mu.Unlock()

	return writeErr
}

// Shutdown starts the closing handshake: RFC 6455 §7.1.2, "_Start the
// WebSocket Closing Handshake_". It validates the close code and sends a
// Close frame carrying it, which moves the connection to stClosing. It does
// not close the transport.
//
// This is the shutdown(SHUT_WR) half of the clean-closure sequence the RFC
// gives as its own example in §7.1.1: shut the write side, keep reading until
// the peer has said its piece, then close. After Shutdown the write half is
// closed — RFC 6455 §5.5.1 says an application MUST NOT send any more data
// frames after sending a Close frame, so writes fail with [ErrClosed] — while
// the read half stays fully live, and it must: §7.1.5 defines this
// connection's close code as the first Close frame *received*, which cannot be
// learned without reading, and §5.5.1 lets the peer keep sending data until it
// has sent its own Close.
//
// So the idiomatic reader is: run the read side to its terminal —
// [RawConn.ReadEvent] in a loop, or [RawConn.Drain] as one call — then call
// [RawConn.Close]. The read loop ends by itself —
// when the peer's Close arrives the handshake is complete, §5.5.1 requires the
// transport down, and the next read reports the terminal — so no explicit wait
// on the closing handshake is needed anywhere.
//
// Shutdown is idempotent and safe to call from any goroutine, including the
// pumping goroutine. Its return value is the status of the close-frame write,
// bounded by the connection's write timeout when one is set and by a fixed
// fallback otherwise; it is not how the connection ended, which is what the
// read's terminal error reports.
//
// Close codes must be in the range 1000-4999. Codes that cannot appear as a
// status on the wire (1004-1006, 1015) go out with an empty payload; a
// non-UTF-8 reason is dropped (§5.5). The code passed here is what goes out on
// this endpoint's own frame; the code the connection resolves to is the peer's.
func (c *RawConn) Shutdown(code int, reason string) error {
	if code < closeCodeMin || code > closeCodeMax {
		return fmt.Errorf("%w: %d", errBadCloseCode, code)
	}

	return c.sendCloseFrame(code, reason)
}

// finalizeClose completes the closing handshake from the read path, when the
// peer's close frame has been read and resolved. It echoes the peer's close
// if this endpoint has not sent one yet — in stOpen the peer's close is the
// first one we received, and §5.5.1 requires the answer — and then closes the
// transport, recording the terminal error. In stClosing (we already sent a
// close via Shutdown) there is nothing to echo: the peer's close is the one
// that completes the handshake. Either way the recorded close code is the one
// the peer sent (§7.1.5), not this endpoint's.
func (c *RawConn) finalizeClose(code int, reason string) {
	if c.state.Load() == stOpen {
		_ = c.sendCloseFrame(code, reason)
	}
	_ = c.finish(closeErrFor(code, reason))
}

// Close closes the underlying transport: RFC 6455 §7.1.1, "_Close the
// WebSocket Connection_". It is the final step of the §7.1.1 example, the
// close() that follows shutdown(SHUT_WR) and draining the reads.
//
// Close never blocks and never writes. It takes no write lock and puts nothing
// on the wire, so it cannot queue behind a stalled writer, cannot deadlock, and
// needs no timeout: the closing handshake is completed by *reading* (see
// [RawConn.Shutdown]), which is the only way to learn the peer's close code,
// and a connection that has been read to its terminal is already closed here —
// §5.5.1 requires the transport down once both Close frames have been
// exchanged.
//
// Calling Close without a preceding [RawConn.Shutdown] is an abrupt close: no
// Close frame goes out, so the peer resolves the connection to 1006 (§7.1.5,
// no Close frame received). That is deliberate rather than a gap — §7.1.1 lets
// an endpoint "close the connection via any means available" — and it is what
// a bare `defer c.Close()` cleanup does when the application never said
// goodbye. Close records no error of its own: how a connection ended is what
// the read's terminal error reports, and a connection closed without being read
// to its terminal reports a clean end rather than an invented one.
//
// Close is idempotent and safe to call from any goroutine; only the first call
// touches the transport. It returns the status of closing the transport.
func (c *RawConn) Close() error {
	// A swap, not a check-then-store: Close must not take c.mu, because c.mu is
	// the write lock and a stalled writer may be holding it for the whole write
	// bound. That is the wedge this design exists to remove.
	if c.state.Swap(stClosed) == stClosed {
		return nil
	}

	closeErr := c.nc.Close()
	if closeErr != nil {
		return fmt.Errorf("ws: closing the transport: %w", closeErr)
	}

	return nil
}

// Drain runs the read side to its terminal, consuming and discarding every
// event, and returns the terminal error: [io.EOF] for a clean end, a
// [*CloseError] otherwise. It is the read-side half of the RFC 6455 §7.1.1
// closing sequence — [RawConn.Shutdown], Drain, [RawConn.Close] — as one
// call, for the application that wants the connection ended and its close
// code learned (the first Close frame received, §7.1.5) without running the
// message loop: the writer's half of the connection.
//
// Events are discarded on the way: pings are consumed without a pong answer
// (the connection is ending, and RawConn never pongs on the application's
// behalf), and data messages are not delivered (RFC 6455 §5.5.1 does not
// require a closing endpoint to keep processing data). The terminal is the
// only information retained.
//
// Drain must only be called from the goroutine that pumps the connection —
// it runs [RawConn.ReadEvent] — and never concurrently with
// [RawConn.ReadEvent]. On a connection that is already terminal — read to
// its terminal, or [RawConn.Close]d — it returns the recorded terminal at
// once.
//
// The wait it performs is the read wait, so it is bounded the way reads are:
// with the idle timeout set, a silent peer is probed with a ping and the
// drain fails with a timeout after a second window; with keepalive disabled
// it is bounded only by the transport — bound it with
// [RawConn.SetReadDeadline] before calling. After a [RawConn.Shutdown] it
// reads the peer's reply; called without one it waits for the peer to
// initiate the closing handshake.
func (c *RawConn) Drain() error {
	for {
		_, readErr := c.ReadEvent()
		if readErr != nil {
			return readErr
		}
	}
}

// Closed reports whether the connection is closed or closing, from any
// goroutine. It is true in both stClosing (a close frame has been sent; the
// transport is still up, awaiting the peer's close) and
// stClosed (the transport is down). It is the cheap, race-free signal a
// background writer goroutine needs to stop: it can check Closed() (or select
// on work and bail when true) instead of waiting for its next WriteMessage to
// fail with ErrClosed.
func (c *RawConn) Closed() bool { return c.state.Load() != stOpen }

// EffectiveIdleTimeout reports the idle window this connection actually
// enforces: the configured window when the stream enforces read deadlines, and
// zero otherwise. A session is only created with a nonzero window over a
// stream that implements [DeadlineStream], so the reported window is the one
// the read path arms; zero means the window was never configured or was
// waived because the stream cannot enforce it (see [ErrNoDeadlineSupport]).
func (c *RawConn) EffectiveIdleTimeout() time.Duration { return c.idleTimeout }

// EffectiveWriteTimeout reports the write bound this connection actually
// enforces: the configured bound when the stream enforces write deadlines, and
// zero otherwise — see [RawConn.EffectiveIdleTimeout] for the same contract.
// Zero means writes are unbounded on this stream.
func (c *RawConn) EffectiveWriteTimeout() time.Duration { return c.writeTimeout }

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
// deadlines yourself. On a stream that cannot enforce deadlines it is a
// no-op.
func (c *RawConn) SetReadDeadline(t time.Time) error { return c.deadlines.SetReadDeadline(t) }

// SetWriteDeadline sets the underlying connection's write deadline. On a
// stream that cannot enforce deadlines it is a no-op.
func (c *RawConn) SetWriteDeadline(t time.Time) error { return c.deadlines.SetWriteDeadline(t) }

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
	if c.state.Load() != stClosed {
		// stOpen -> stClosed (a protocol failure, a transport EOF) or
		// stClosing -> stClosed (the peer's Close completes the closing
		// handshake). Either way this is the terminal: record the error that
		// resolved the connection (first terminal wins).
		c.state.Store(stClosed)
		if err != nil {
			c.closeErr = err
		}
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

// decompress expands a compressed message payload. The wire payload is a
// DEFLATE block sequence (RFC 7692 §7.2.1) that may carry several complete
// DEFLATE streams — a peer may end a stream at a byte-aligned final block and
// continue with further blocks — followed by the §7.2.2 trailing empty block
// the compressor truncates on the wire. A bare flate reader stops at the
// first final block and silently discards everything after it; decompress
// therefore locates every final-block boundary (finalBlockBoundary, using
// the flate decoder itself as the oracle) and decodes each complete stream in
// turn, concatenating the output so no content after an early final block is
// lost. The final, non-final segment is decoded with deflateTailBytes, which
// completes the truncated trailing empty block and adds a BFINAL terminator
// so the strict decoder ends cleanly. An empty compressed payload is legal
// and decompresses to an empty message.
//
// The result is at most maxMessageSize, enforced while decompressing so a
// high-ratio payload cannot inflate unboundedly before rejection; a
// malformed block — corrupt DEFLATE or a block past the payload — is a
// protocol failure, never silently discarded bytes.
//
// The returned slice is fresh (the caller owns and may retain it); every
// other buffer is per-connection scratch, so steady-state decompression
// allocates only the payload: one heap allocation per compressed message.
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
	c.inflateBuf.Reset()
	c.inflateLimit.limit = int(c.fc.maxMsg)
	start := 0
	for start < len(src) {
		boundary := c.finalBlockBoundary(src, start)
		if boundary < 0 {
			// No final block in src[start:]: the last (non-final) stream,
			// decoded with the completion tail.
			streamErr := c.decodeStream(src[start:], true)
			if streamErr != nil {
				return nil, c.wrapDecompress(streamErr)
			}

			break
		}

		// src[start:boundary] is a complete DEFLATE stream ending in a final
		// block; decode it. The completion tail is harmless here — the
		// decoder ignores anything after a final block.
		streamErr := c.decodeStream(src[start:boundary], true)
		if streamErr != nil {
			return nil, c.wrapDecompress(streamErr)
		}

		start = boundary
	}
	payload := make([]byte, c.inflateBuf.Len())
	copy(payload, c.inflateBuf.Bytes())

	return payload, nil
}

// wrapDecompress maps the decompressor's errors: a size overflow keeps its
// sentinel; everything else is a protocol violation.
func (c *RawConn) wrapDecompress(err error) error {
	if errors.Is(err, errMessageTooBig) {
		return fmt.Errorf("%w: decompressed message exceeds the %d byte limit", errMessageTooBig, c.fc.maxMsg)
	}

	return fmt.Errorf("%w: invalid compressed payload: %w", errProtocol, err)
}

// decodeStream decodes one segment with the re-used decompressor and appends
// the output to c.inflateBuf. When withTail, the completion octets
// (deflateTailBytes) are appended to segment: required for the final
// non-final stream (they complete the truncated trailing empty block) and
// ignored otherwise (the decoder discards anything after a final block).
func (c *RawConn) decodeStream(segment []byte, withTail bool) error {
	need := len(segment)
	if withTail {
		need += len(deflateTailBytes)
	}
	if len(c.inflateWire) < need {
		c.inflateWire = make([]byte, need)
	}
	copy(c.inflateWire, segment)
	if withTail {
		copy(c.inflateWire[len(segment):], deflateTailBytes[:])
	}
	c.inflateSrc.Reset(c.inflateWire[:need])
	resetErr := c.inflaterRst.Reset(c.inflateSrc, nil)
	if resetErr != nil {
		return errNoResetter
	}

	_, copyErr := io.CopyBuffer(&c.inflateLimit, c.inflater, c.inflateCopy)
	if copyErr != nil {
		return fmt.Errorf("ws: decompress stream: %w", copyErr)
	}

	return nil
}

// finalBlockBoundary returns the smallest byte offset b in (start, len(src)]
// at which src[start:b] is a complete DEFLATE stream — that is, the flate
// decoder reaches a BFINAL block — or -1 if no final block occurs in
// src[start:]. The flate decoder is the oracle: it returns success exactly
// when a final block is reached (any trailing bytes are ignored) and an error
// otherwise, so the predicate is monotone in the prefix length and a binary
// search pins the first boundary.
func (c *RawConn) finalBlockBoundary(src []byte, start int) int {
	if !c.probeClean(src[start:]) {
		return -1
	}

	low, high := start+1, len(src)
	for low < high {
		middle := (low + high) >> 1
		if c.probeClean(src[start:middle]) {
			high = middle
		} else {
			low = middle + 1
		}
	}

	return low
}

// probeClean reports whether the flate decoder, re-armed on segment, reaches
// a BFINAL block (a complete DEFLATE stream). The decompressed output is
// discarded; only the terminal state of the decode matters. The copy uses the
// per-connection inflateCopy scratch so the probe is allocation-free.
func (c *RawConn) probeClean(segment []byte) bool {
	c.inflateSrc.Reset(segment)
	resetErr := c.inflaterRst.Reset(c.inflateSrc, nil)
	if resetErr != nil {
		return false
	}

	_, err := io.CopyBuffer(io.Discard, c.inflater, c.inflateCopy)

	return err == nil
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
	// pulled counts the bytes readFrame pulled from the stream during the
	// current attempt; readNextFrame uses it to tell a clean failure
	// (zero bytes consumed — safe to retry after a keepalive timeout) from
	// an interrupted frame (bytes already consumed — the connection must
	// fail, because a retry would re-read the remaining payload as a new
	// frame). Read-loop only.
	pulled int
}

// readFrame reads one frame from the connection. A client must mask its
// frames and a server must not, so the peer's frames are masked exactly
// when we are the server.
func (fc *frameCodec) readFrame() (frame, error) {
	fc.pulled = 0
	n, err := io.ReadFull(fc.br, fc.in[:2])
	fc.pulled += n
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
		n, err := io.ReadFull(fc.br, fc.mask[:])
		fc.pulled += n
		if err != nil {
			return nil, fmt.Errorf("ws: read mask key: %w", err)
		}
	}
	payload := make([]byte, size)
	n, readErr := io.ReadFull(fc.br, payload)
	fc.pulled += n
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
		n, err := io.ReadFull(fc.br, fc.in[2:4])
		fc.pulled += n
		if err != nil {
			return 0, fmt.Errorf("ws: read 16-bit length: %w", err)
		}
		size := int64(binary.BigEndian.Uint16(fc.in[2:4]))
		// RFC 6455 §5.2: the payload length MUST use the smallest number
		// of bytes — a 16-bit form below 126 is a malformed frame.
		if size < len16 {
			return 0, fmt.Errorf("%w: non-minimal 16-bit frame length %d", errProtocol, size)
		}

		return size, nil
	case len64:
		n, err := io.ReadFull(fc.br, fc.len8[:])
		fc.pulled += n
		if err != nil {
			return 0, fmt.Errorf("ws: read 64-bit length: %w", err)
		}
		if fc.len8[0] != 0 {
			return 0, fmt.Errorf("%w: frame too large", errProtocol)
		}
		// len8[0] == 0 above, so the value is < 2^63: the conversion
		// below cannot overflow.
		size := int64(binary.BigEndian.Uint64(fc.len8[:])) //nolint:gosec // bounded above
		// RFC 6455 §5.2: a 64-bit form below 2^16 is a malformed frame.
		if size < minLen64 {
			return 0, fmt.Errorf("%w: non-minimal 64-bit frame length %d", errProtocol, size)
		}

		return size, nil
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
	finBit     = 0x80    // frame[0] high bit: final fragment
	rsvMask    = 0x70    // frame[0] reserved bits
	rsv1Bit    = 0x40    // reserved bit 1: permessage-deflate "compressed" (RFC 7692)
	rsv23Mask  = 0x30    // reserved bits 2 and 3, must always be zero
	opcodeMask = 0x0f    // frame[0] low 4 bits: opcode
	maskBit    = 0x80    // frame[1] high bit: payload is masked
	lenMask    = 0x7f    // frame[1] low 7 bits: payload length
	len16      = 126     // 16-bit extended length follows the header
	len64      = 127     // 64-bit extended length follows the header
	minLen64   = 1 << 16 // smallest length that needs the 64-bit form (RFC 6455 §5.2)
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

// ErrNoDeadlineSupport is returned by [Upgrader.SessionOnStream] — and the
// reason for a 501 from the extended-CONNECT branch of [Upgrader.Upgrade] —
// when the upgrader has a nonzero [WithIdleTimeout] or [WithWriteTimeout] but
// the stream cannot enforce read or write deadlines (does not implement
// [DeadlineStream]). The options must be real protections or absent, never
// silently inert: bound liveness in the transport and set both options to
// zero to run a session over such a stream.
var ErrNoDeadlineSupport = errors.New("ws: stream cannot enforce the configured deadline options; " +
	"bound liveness in the transport and set WithIdleTimeout(0) and WithWriteTimeout(0)")

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

// errTransportAbnormalClose is the terminal error recorded when the transport
// ends without a close frame (RFC 6455 §7.1.5): status 1006, which is never
// transmitted on the wire, and deliberately not io.EOF — that is the
// documented clean-close signal, so transport loss stays distinguishable
// from a normal protocol shutdown. Shared by every connection: the value is
// never mutated.
var errTransportAbnormalClose = &CloseError{
	Code:   StatusAbnormalClosure,
	Reason: "connection closed without a close frame",
}

// closeErrFor maps a close code to the terminal error recorded on the
// connection: a normal closure (1000, or an absent status) yields nil,
// everything else yields a *CloseError so callers can see the code and
// reason (e.g. 1001 "going away").
// terminalErr maps the recorded terminal error to what the connection's
// surfaces report: a clean end — a normal closure (1000) in either
// direction, or a close frame without a status — reads as [io.EOF];
// anything else is the recorded error. An abrupt transport loss is never
// io.EOF: it is recorded as the 1006 abnormal closure
// (errTransportAbnormalClose), so [errors.Is] on [io.EOF] distinguishes a
// clean end from transport loss, and [CloseCode] reports 1006 for the
// latter.
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
