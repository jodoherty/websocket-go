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
func (u *Upgrader) Handle(fn func(r *http.Request, c *Conn) error) http.Handler
func Handle(fn func(r *http.Request, c *Conn) error) http.Handler

// Options (shared by server and client where symmetric)
WithCheckOrigin(f)         // default: same-origin when an Origin header is present
WithRequireClientCert()    // mTLS gate, 403 without a verified client cert
WithSubprotocols(...)
WithMaxMessageSize(n)      // default 16 MiB
WithIdleTimeout(d)         // default 60 s window: probe at d, dead at 2d
WithWriteTimeout(d)        // default 30 s write bound; 0 disables
WithPreHandshake(f)        // policy hook before the switch; *UpgradeError controls status
WithHandshakeData(v)       // per-upgrade value, c.HandshakeData()

// Conn
Conn.ReadMessage() (op int, data []byte, err error)
Conn.WriteMessage(op int, data []byte) error   // fails on a closed conn: recorded error, or ErrClosed
Conn.Close(code int, reason string) error      // best-effort close frame, bounded write; returns recorded error
Conn.ID() / Subprotocol() / HandshakeData() / RemoteAddr() / LocalAddr()
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
subprotocol negotiation, close-code semantics per RFC 6455.

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
