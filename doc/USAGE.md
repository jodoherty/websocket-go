# websocket — usage guide

User-facing documentation for the `ws` package. (Moved from `README.md`,
which is reserved for the project owner's hand-written editing.)

A WebSocket (RFC 6455) implementation for Go, stdlib only, designed to slot
into `net/http` — `http.ServeMux`, `http.Handler`, `http.HandlerFunc` —
rather than replace it.

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
           if err != nil {
               code, reason, _ := ws.CloseCode(err)
               log.Printf("session ended: code=%d reason=%q err=%v", code, reason, err)
               break
           }
           if op == 0 {                      // normal close (1000)
               break
           }
           _ = c.WriteMessage(op, data)
       }
       // connection is gone; deferred cleanups run now
   }))
   ```

   or, for the simple cases, just `mux.Handle("/ws/echo", ws.Handle(fn))`.

4. **Close detection, one return.** Every way a connection dies — close
   frame, transport error, keepalive timeout, local `Close()` — funnels into
   the same `ReadMessage` return:

   - normal closure (1000) → `(0, nil, nil)`
   - any other close code (including 1001 "going away") → `*ws.CloseError`
     with code and reason
   - resets, timeouts, protocol violations → the error, directly or wrapped

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

6. **One allocation per message.** The frame codec keeps its per-frame
   buffers (header, mask key, masked copy) as per-connection scratch, so the
   steady-state cost of a message is exactly one heap allocation — the
   payload `ReadMessage` returns, which the caller owns. Writes allocate
   nothing. This is pinned by the allocation-budget tests, not just
   benchmarked.

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
WithPreHandshake(f)        // policy hook before the switch; *UpgradeError controls status
WithHandshakeData(v)       // per-upgrade value, c.HandshakeData()

// Conn
Conn.ReadMessage() (op int, data []byte, err error)
Conn.WriteMessage(op int, data []byte) error   // fails on a closed conn: recorded error, or ErrClosed
Conn.Close(code int, reason string) error      // best-effort close frame, bounded write; returns recorded error
Conn.ID() / Subprotocol() / HandshakeData() / RemoteAddr() / LocalAddr()
Conn.Compressed() bool     // whether permessage-deflate was negotiated on this connection
Conn.SetReadDeadline / SetWriteDeadline
Conn.Closed() bool         // race-free "am I closed?" for background writers

// Sentinel
var ErrClosed  // returned by WriteMessage after a normal closure (1000)

// Client
func Dial(ctx context.Context, url string, opts ...Option) (*Conn, error)
WithHeader(k, v)           // e.g. Authorization: Bearer ...
WithTLS(cfg) / WithTLSClientCert(cert, key)   // mTLS
WithDialTimeout(d)
```

Protocol details: masking enforced both directions, fragmentation support on
read, control-frame validation, ping/pong handled transparently (auto-pong),
subprotocol negotiation with client-side echo verification (RFC 6455 §1.9 —
the dial fails if the server selects a token the client never offered, or
several at once), close-code semantics per RFC 6455, and CR/LF rejection in
client request headers and subprotocols.

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
  out with an empty payload.
- **Request hygiene.** Handshake bodies rejected, pipelined bytes rejected,
  and client request headers/subprotocols with CR/LF rejected.

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
| `rfc8441.txt` | Reference only | WebSockets over HTTP/2; no browser ships it, and serving it requires non-stdlib HTTP/2 extended-CONNECT code, which conflicts with the single-file stdlib-only invariant |
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
