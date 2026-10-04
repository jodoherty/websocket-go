# websocket — usage guide

User-facing documentation for the `ws` package. (Moved from `README.md`,
which is reserved for the project owner's hand-written editing.)

A WebSocket (RFC 6455) implementation for Go, stdlib only, designed to slot
into `net/http` — `http.ServeMux`, `http.Handler`, `http.HandlerFunc` —
rather than replace it.

**Requirements:** Go 1.25 or newer — the code uses `errors.AsType`,
`strings.SplitSeq`, and `slices`, which arrived in 1.24–1.25. The
stdlib-only *import* invariant holds on any Go; the language floor is what
it is.

## Design

**The websocket is the second half of an ordinary HTTP request.**

1. **Compose, don't replace.** `ws.Upgrade(w, r)` converts a request to a
   connection; `ws.Handle(fn)` turns a message handler into an
   `http.Handler`. Anything the stdlib ecosystem does with `http.Handler`
   (routing, middleware, logging, timeouts) works unchanged.

2. **Authentication is middleware.** Bearer tokens, sessions, rate limiting,
   and mTLS run in plain HTTP code before the upgrade. Client certificates
   are read with `ws.ClientCert(r)` (wrapping `r.TLS.PeerCertificates`);
   `ws.WithRequireClientCert()` rejects requests that arrived without one.

3. **No callbacks, no pump goroutine.** The goroutine that calls
   `Conn.ReadMessage` *is* the connection's goroutine. A session is:

   ```go
   mux.Handle("/ws/chat", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
       user, err := authenticate(w, r)      // may 401
       if err != nil {
           return
       }
       c, err := up.Upgrade(w, r, ws.WithHandshakeData(user))
       if err != nil {
           return                            // 4xx/5xx already written
       }
       defer c.Close(ws.StatusNormalClosure, "")

       for {
           op, data, err := c.ReadMessage()
           if errors.Is(err, io.EOF) {        // normal close (1000)
               break
           }
           if err != nil {                    // abnormal end or close code
               code, reason, _ := ws.CloseCode(err)
               log.Printf("session ended: code=%d reason=%q err=%v", code, reason, err)
               break
           }
           if werr := c.WriteMessage(op, data); werr != nil {
               // The transport write failed, so the connection is
               // already marked dead with the error recorded — log the
               // reason and let the loop (and the deferred Close) exit.
               log.Printf("session write failed: %v", werr)
               break
           }
       }
       // connection is gone; deferred cleanups run now
   }))
   ```

   or, for the simple cases, just `mux.Handle("/ws/echo", ws.Handle(fn))`.

4. **Close detection, one return.** Every way a connection dies — close
   frame, transport error, keepalive timeout, local `Close()` — funnels into
   the same `ReadMessage` return:

   - normal closure (1000, either direction) or a statusless close frame →
     `(0, nil, io.EOF)` — the clean end; check it with
     `errors.Is(err, io.EOF)`
   - any other close code (including 1001 "going away") → `*ws.CloseError`
     with code and reason
   - frame-level protocol violation (masking, reserved-bit misuse,
     malformed or oversized frame, unknown opcode) → `*ws.CloseError` code
     1002; the peer gets the matching 1002 close frame before the
     transport is torn down (RFC 6455 §7.1.7). Errors found while a
     message is being assembled (fragmentation, size, UTF-8, decompression)
     end the connection the same way but without a close frame
   - resets, timeouts → the error, directly or wrapped

   The keepalive (default 60 s window) detects silently dead peers (crash,
   power loss, NAT expiry): a connection silent for one window is probed
   with a ping sent inline in the read path, and is considered dead if it is
   still silent after a second window. A pong — or any frame — from the
   peer resets the clock, so an idle-but-alive connection is kept alive.
   No background goroutines; `WithIdleTimeout(0)` disables it.

5. **Concurrency rules, minimal.**
   - `WriteMessage` / `Close`: safe from any goroutine.
   - `ReadMessage`: owned by the pumping goroutine; never two at once.
   - Sequential `ReadMessage` calls need no synchronization between them —
     it's one goroutine.
   - Writes are bounded by a per-connection write timeout (default 30 s),
     so a blackholed transport cannot hold the write mutex forever and
     wedge `Close`; `Conn.Closed()` gives a background writer a race-free
     signal to stop. `WithWriteTimeout(0)` restores unbounded writes.
   - A transport-level write failure closes the connection with the
     error recorded — the same verdict the read path gives a failed pong
     or keepalive probe. The write timeout therefore bounds the
     connection, not just one write; validation rejections (bad opcode,
     oversize, non-UTF-8) do not.

6. **One allocation per message.** The frame codec keeps its per-frame
   buffers (header, mask key, masked copy) as per-connection scratch, so the
   steady-state cost of a message is exactly one heap allocation — the
   payload `ReadMessage` returns, which the caller owns. Writes allocate
   nothing. This is pinned by the allocation-budget tests, not just
   benchmarked.

## Usage: good and bad

These are the design properties that stay true no matter how carefully the
rest of the application is written, shown as paired examples.

### Every write error is a signal, not a nuisance

A write succeeding does not prove the peer is alive: a stalled transport
(peer stopped reading, NAT entry expired, link blackholed) absorbs many
writes into the kernel buffer before it starts failing, and the failure
arrives on the write timeout, not on the first lost message. The failure
is also terminal: a transport-level write failure closes the connection
with the error recorded, so later writes fast-fail, `Closed()` turns true
for background writers, and a blocked `ReadMessage` wakes. Even an
unchecked write is therefore bounded by a single write timeout — but the
error is still the only place the application learns *why* the session
ended, and discarding it turns a diagnosable failure into a mystery.

```go
// good: a failed write means the transport is broken — the connection
// is already marked dead; log the reason and let the loop exit.
if err := c.WriteMessage(op, data); err != nil {
    log.Printf("session write failed: %v", err)
    break
}

// bad: the write fails on a stalled transport and the connection dies —
// the failure is bounded, but the application threw away the only
// evidence of why, and the handler reports a bare transport error
// where "peer stopped reading after N messages" would have pointed at
// the real problem.
_ = c.WriteMessage(op, data)
```

### `OpText` is for text; `OpBinary` is for bytes

Text frames must be valid UTF-8 (RFC 6455 §5.6). A write that is not is
refused before it reaches the wire — the connection stays open, but an
unchecked refusal reads exactly like the silent loss above.

```go
// good: raw byte sequences travel as binary; structured data as JSON.
err := c.WriteBinary(protobufBuf)
err = c.WriteJSON(event)

// bad: arbitrary bytes on the text path fail the write; if the error is
// unchecked, the application believes the data was delivered.
c.WriteMessage(OpText, rawBytes)
```

### Teardown is bounded, not instant

`Close` writes a close frame before tearing down the transport, and that
write is bounded by the connection's `WithWriteTimeout` (falling back to a
fixed 5 s when unset). On a stalled transport, `Close` can also queue
behind an in-flight data write, so a handler's `defer c.Close(...)` can
wait on the order of the write timeout before returning.

```go
// good: the write timeout is the staleness budget. A service that wants
// fast teardown of dead sessions sets it to what it can afford to wait;
// the close bound follows it.
c, err := up.Upgrade(w, r, ws.WithWriteTimeout(2*time.Second))

// bad: WithWriteTimeout(0) restores unbounded writes — a blackholed peer
// now pins the read loop (pong write, keepalive probe) and holds the
// write mutex against Close, all indefinitely.
c, err := up.Upgrade(w, r, ws.WithWriteTimeout(0))
```

### A ping is a write, and all writes share one lock

The automatic pong and the keepalive probe take the same write mutex as
the application's data frames, bounded by the same write timeout. A peer
that sends pings but never reads can pin the pumping goroutine until that
bound fires — the bound is the defense, which means the write timeout is
also the per-connection cost an attacker can buy with pings.

```go
// good: keep the write timeout proportional to the number of stalled
// connections you can tolerate at once, and tune WithIdleTimeout to
// match — a keepalive probe cannot get through behind a stalled write,
// so an idle window shorter than the write bound only declares peers
// dead early.

// bad: a 30-minute write timeout for one slow consumer means every
// stalled connection costs a pinned goroutine for 30 minutes.
```

### One pumping goroutine per connection

`ReadMessage` is owned by the goroutine that calls it; that goroutine *is*
the session. Writers may run anywhere, but the reader must not move.

```go
// good: the handler's loop is the reader; background goroutines only
// write, and check c.Closed() before sending.
go func() {
    for msg := range ticker {
        if c.Closed() {
            return
        }
        _ = c.WriteMessage(OpBinary, msg)
    }
}()

// bad: two goroutines calling ReadMessage interleave frame assembly on
// the same scratch buffers; the session desynchronizes in ways that are
// nearly impossible to diagnose.
```

## API

```go
// Server
func NewUpgrader(opts ...Option) *Upgrader
func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, opts ...HandshakeOption) (*Conn, error)
// Handle(fn): on handler return, closes with the *CloseError's code,
// 1000 for a nil return, or 1011 for any other error (the session did
// not end normally).
func (u *Upgrader) Handle(fn func(r *http.Request, c *Conn) error) http.Handler
func Handle(fn func(r *http.Request, c *Conn) error) http.Handler

// Options (shared by server and client where symmetric)
WithCheckOrigin(f)         // default: same-origin when an Origin header is present
WithRequireClientCert()    // mTLS gate, 403 without a verified client cert
WithSubprotocols(...)      // server: select or none (lenient); client: echo is verified
WithMaxMessageSize(n)      // default 16 MiB; non-positive falls back to the default
WithIdleTimeout(d)         // default 60 s window: probe at d, dead at 2d; 0 disables
WithWriteTimeout(d)        // default 30 s write bound; 0 disables; negatives fall back
WithCompression(enabled)   // permessage-deflate (RFC 7692); default true, opt out per upgrader or dial
WithCompressionLevel(l)    // flate level for compression; default flate.DefaultCompression
WithPongHandler(f)         // invoked inline by ReadMessage when a pong arrives; pongs are otherwise invisible
WithPreHandshake(f)        // policy hook before the switch; plain error → fixed 403 "forbidden" body;
                           // *UpgradeError controls status and body
WithHandshakeData(v)       // per-upgrade value, c.HandshakeData()

// Conn
Conn.ReadMessage() (op int, data []byte, err error)
   // a clean end reads as (0, nil, io.EOF); other closes as *CloseError
Conn.WriteMessage(op int, data []byte) error   // the echo form: the op comes off the wire;
                                               // on a closed conn: recorded error, or ErrClosed
Conn.WriteText(s string) error                 // OpText; invalid UTF-8 refused before the wire
Conn.WriteBinary(b []byte) error               // OpBinary, bytes untouched
Conn.WriteJSON(v any) error                    // marshal (off-lock) then OpText
Conn.Ping(payload []byte) error                // application ping (≤125 B); auto-ponged; safe from any goroutine
Conn.Close(code int, reason string) error      // best-effort close frame, bounded write; returns the terminal error
Conn.ID() / Subprotocol() / HandshakeData() / RemoteAddr() / LocalAddr()
Conn.Compressed() bool     // whether permessage-deflate was negotiated on this connection
Conn.SetReadDeadline / SetWriteDeadline
Conn.Closed() bool         // race-free "am I closed?" for background writers

// Sentinels
var ErrClosed  // returned by WriteMessage after a normal closure (1000)
io.EOF       // returned by ReadMessage and Close for a clean end

// Client
func Dial(ctx context.Context, url string, opts ...Option) (*Conn, error)
WithHeader(k, v)           // e.g. Authorization: Bearer ...
WithTLS(cfg) / WithTLSClientCert(cert, key) / WithTLSClientChain(cert, chain, key)  // mTLS
                                                                  // (chain: leaf + intermediates)
WithDialTimeout(d)
```

Protocol details: masking enforced both directions, fragmentation support on
read, control-frame validation, ping/pong handled transparently (auto-pong),
UTF-8 validation on text frames (RFC 6455 §5.6 — a non-UTF-8 text message
fails the connection with 1007, the close Node's ws and browsers use for
exactly this; `WriteMessage(OpText, …)` with invalid UTF-8 is refused before
it reaches the wire), subprotocol negotiation with token validation on
both sides and client-side echo verification (RFC 6455 §1.9 — a client
offer the server cannot echo is refused, the dial fails if the server
selects a token the client never offered, or several at once, and a
server-advertised token that is not a valid token fails its handshake with
400), close-code semantics per RFC
6455, and CR/LF rejection in client request headers and subprotocols. The
single-value handshake headers are single-valued on both sides:
several `Sec-WebSocket-Version` or `Sec-WebSocket-Key` lines fail the
handshake with 400 (server) / fail the dial (client, for a duplicated
`Sec-WebSocket-Accept` on the 101), every `Sec-WebSocket-Protocol` line
shares one token space on both sides, and a `Close` reason that is not
valid UTF-8 is dropped rather than put on the wire (RFC 6455 §5.5).

## Security

The protocol-level protections from the [OWASP WebSocket Security Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
are built in; the rest are application responsibilities, and the seams
below are where they live.

**The library owns (nothing to do):**

- **WSS.** `Dial` uses TLS for `wss://` (`WithTLS` / `WithTLSClientCert`
  for custom roots or mTLS). Serve behind TLS; never put `ws://` in
  production.
- **RFC 6455 core, plus permessage-deflate (RFC 7692).** Version 13 only;
  the only reserved (RSV) bit used is RSV1, and only when permessage-deflate
  is negotiated. Compression is on by default (matching browsers and the
  Node ws client) and is opt-out via `WithCompression(false)` on an upgrader
  or `Dial`; `WithCompressionLevel` tunes the level. The library negotiates
  per-message (no context takeover) compression with a full 15-bit window and
  enforces `MaxMessageSize` on the *decompressed* size, so a high-ratio
  payload cannot inflate unboundedly. See `doc/COMPRESSION.md`.
- **Origin validation on every handshake** (CSWSH). Strict same-origin by
  default — no `CheckOrigin: always true`; override with `WithCheckOrigin`
  as an explicit allowlist, never a denylist.
- **mTLS gate.** `WithRequireClientCert()` rejects before the protocol
  switch; `ClientCert(r)` reads the identity.
- **Message size bound** (DoS). Default 16 MiB; for chat-style traffic the
  cheat sheet's ~64 KiB is a sane cap — set it per endpoint:
  `WithMaxMessageSize(64 << 10)`.
- **Dead-peer detection.** Keepalive ping/kill (`WithIdleTimeout`, default
  60 s) so idle or dead connections do not accumulate.
- **Bounded writes.** A blackholed peer cannot wedge a connection
  (`WithWriteTimeout`, default 30 s) or hold the close open.
- **Close-code hygiene.** Invalid or must-not-set codes received fail the
  connection with 1002 and are never echoed; our own forbidden codes go
  out with an empty payload; a non-UTF-8 close reason is dropped (the
  frame carries the code alone), so only UTF-8 ever goes on the wire.
- **Request hygiene.** Handshake bodies rejected, pipelined bytes rejected,
  client request headers/subprotocols with CR/LF rejected, and
  duplicate single-value handshake headers (Version, Key, Accept) rejected
  on both sides.

**The application owns** (each item below is a cheat-sheet requirement the
library deliberately leaves to you, with the seam where it goes):

*Origin policy — an explicit allowlist, not just same-origin.* The default
is a safe floor; production traffic usually wants a named list:

```go
trusted := map[string]bool{
    "https://app.example.com":   true,
    "https://admin.example.com": true,
}
up := ws.NewUpgrader(ws.WithCheckOrigin(func(r *http.Request) bool {
    if origin := r.Header.Get("Origin"); origin != "" {
        return trusted[origin] // browsers always send Origin
    }
    // No Origin means a programmatic client (browsers cannot omit it).
    // Let its token decide; strict deployments can just return false.
    return r.Header.Get("Authorization") != ""
}))
```

A programmatic client is free to *present* an Origin to receive
browser-equivalent policy treatment: `ws.Dial` sends it via
`ws.WithHeader("Origin", …)`, and the Node `ws` library takes an
`origin` option — that is how the e2e Node interop passes the demo's
default same-origin check.

*Session lifecycle — re-validate, and close on expiry or logout.*
WebSocket sessions outlive ordinary ones, so re-check the session in the
read loop (every 30 minutes is the cheat sheet's figure) and, on logout,
close every connection for that session through a session → `Conn.ID()`
map. Pair with `SameSite=Lax` (or `Strict`) cookies so a cross-site
handshake cannot carry the session at all:

```go
if !sessions.Valid(sessionOf(c)) { // re-validation in the read loop
    return &ws.CloseError{Code: ws.StatusPolicyViolation, Reason: "session expired"}
}
```

*Message-level authorization — a connection is not a grant.* Check the
authorization for each action on each message, and reject with 1008:

```go
if msg.Action == "delete_user" && !user.HasRole("admin") {
    return &ws.CloseError{Code: ws.StatusPolicyViolation, Reason: "forbidden"}
}
```

*Flooding and replay resistance.* Bound the message rate in the read loop
(100 messages/minute is the cheat sheet's starting point) and reject
replayed messages with nonces or timestamps:

```go
if !limiter.Allow(c.ID(), time.Now()) {
    return &ws.CloseError{Code: ws.StatusTryAgainLater, Reason: "rate limited"}
}
```

*Logging.* Log connection start and end (user, IP, origin, close code —
`ws.CloseCode(err)` yields the last) and authorization failures; never
log message payloads or tokens.

*Service tunneling (VNC/SSH/FTP over the socket).* If you tunnel a TCP
service, add authentication and target allowlisting beyond the WebSocket
layer — the VNC example below shows the shape: auth and an explicit
per-user target resolution before the byte bridge.

## Running

```sh
go test ./...        # library unit tests
go vet ./...
make all             # the full gate: strict lint + staticcheck + tests
make coverage        # statement coverage (unit suite)
make branchcov       # branch coverage (cmd/branchcov, unit + e2e merged)
make mcdc            # MC/DC audit (cmd/mcdc: required pairs traced to tests)
make e2e             # Go e2e + Playwright (Firefox and Chromium)
```

### Demo

```sh
go run ./cmd/certgen -dir e2e/certs
DEMO_TOKEN=secret go run ./cmd/demo -addr :8443 -certs e2e/certs
# open https://localhost:8443/ in a browser; console shows the echo test
```

For test harnesses the demo also accepts `:0` (an ephemeral port) and a
`-report host:port` flag: it then binds its listeners and reports the actual
bound addresses back over that callback connection, so the harness can
discover the demo's ports without any fixed value. The Go e2e and the
Playwright global setup use exactly this to run the demo on ephemeral ports.

`/ws/bearer` accepts the token two ways: the `Authorization: Bearer …`
header, or `?token=…` on the URL. The query-param channel exists because
browsers cannot set custom request headers on a `WebSocket` handshake, so
the browser-facing demo (and the Playwright suite) authenticates with
`?token=`; header-based bearer is exercised by the Node interop suite.
`/ws/info` reports the server-side view of a connection (whether
permessage-deflate was negotiated — the browser `WebSocket` API exposes no
such property) and is what the browser compression assertion reads.

### E2E tests

```sh
cd e2e
npm install
npx playwright install chromium firefox   # one-time
npm test                                  # browsers: echo, subprotocols, binary,
                                          # bearer accept/reject, mTLS rejection, close codes
npm run test:go                           # Go client: full mTLS path (cert presented →
                                          # session opens → identity greeting → echo)
npm run test:all                          # both
```

No test relies on a fixed port or a fixed shared path. The Go e2e
(`e2e_test.go`) and the Playwright global setup (`global-setup.ts`) both
build the demo and its throwaway certificates into a fresh temp directory
and start it on ephemeral ports, learning the real addresses from the
demo's `-report` callback (Playwright re-evaluates its config in every
worker, so the ports live in the once-per-run `globalSetup`, which sets
`WS_BASE_URL` for the workers). Repeated or parallel runs cannot collide.

**Why the mTLS positive path is a Go test, not a browser test:** Chromium
and Firefox refuse to present client certificates on connections whose
server certificate they do not trust, and the demo server intentionally
uses a self-signed CA (`ignoreHTTPSErrors` does not lift that restriction
for client-auth connections). The browser suites therefore verify the
mTLS *rejection* path (no cert → 403 before the upgrade); the *positive*
path is driven end-to-end by a real `ws.Dial` client with a real client
certificate against the real demo binary (`e2e/e2e_test.go`).

## Specification references

`doc/` carries the governing spec and reference material:

| Document | Status | Why |
|---|---|---|
| `rfc6455.txt` | **Governing** — fully implemented and vector-pinned | The WebSocket protocol itself |
| `rfc7692.txt` | **Implemented** — permessage-deflate (RFC 7692), on by default | The only extension with universal browser support; design and interop evidence in `doc/COMPRESSION.md` |
| `rfc8307.txt` | Reference only | Defines `/ws://host/.well-known/…` URI conventions; no protocol mechanics, nothing to implement |
| `rfc8441.txt` | Reference only | WebSockets over HTTP/2; Chromium and Firefox support it, but serving it needs HTTP/2 extended-CONNECT, which the Go standard library does not expose — unreachable for a stdlib-only package |
| `rfc9220.txt` | Reference only | WebSockets over HTTP/3; no browser ships it, and QUIC is categorically outside the stdlib-only constraint |

## A VNC-shaped example

Browser VNC client → policy-gated bridge → backing VNC server on `:5900`:

```go
mux.Handle("/vnc", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, err := authenticate(r)                     // bearer or mTLS identity
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    target, err := resolveTarget(user, r)            // allowlist: who may view what
    if err != nil {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    c, err := up.Upgrade(w, r)
    if err != nil {
        return
    }
    defer c.Close(ws.StatusNormalClosure, "")
    if err := bridge(c, target); err != nil {        // two goroutines pumping bytes
        log.Printf("vnc bridge for %s failed: %v", user, err)
    }
}))

func bridge(c *ws.Conn, target string) error {
    vnc, err := net.Dial("tcp", target)
    if err != nil {
        _ = c.Close(ws.StatusServiceUnavailable, "backend unreachable")
        return err
    }
    defer vnc.Close()
    errCh := make(chan error, 2)
    go func() {                                       // browser -> vnc
        for {
            op, data, err := c.ReadMessage()
            if op == 0 || err != nil {
                errCh <- err
                return
            }
            if _, err := vnc.Write(data); err != nil {
                errCh <- err
                return
            }
        }
    }()
    go func() {                                       // vnc -> browser
        buf := make([]byte, 64<<10)
        for {
            n, err := vnc.Read(buf)
            if n > 0 {
                _ = c.WriteMessage(ws.OpBinary, buf[:n])
            }
            if err != nil {
                errCh <- err
                return
            }
        }
    }()
    err := <-errCh
    _ = c.Close(ws.StatusNormalClosure, "")           // unwinds the other pump
    return err
}
```

The server never speaks VNC; it is a policy- and auth-gated byte bridge —
which is exactly the shape this API is built for.
