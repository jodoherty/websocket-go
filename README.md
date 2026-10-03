# websocket

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

## Repo layout

```
ws/ws.go            the entire library in one file — copy it into an
                    existing project (package ws, stdlib only). Organized
                    in 10 numbered sections, dependency-ordered, with a
                    file map in the package doc.
ws/ws_test.go       unit tests: echo, close codes, keepalive, masking,
                    origin policy, bearer auth, upgrade validation
ws/vectors_test.go  RFC 6455 test vectors (§1.3 accept key, §5.7 frames)
ws/fuzz_test.go     FuzzReadFrame — codec safety fuzz target
ws/keepalive_test.go keepalive probe state machine + timeout classification
ws/keepalive_synctest_test.go keepalive read loop on a fake clock
                    (testing/synctest): exact probe/kill/refresh timelines
ws/longrunning_test.go write-deadline wedge regression + Closed() signal
ws/concurrency_test.go close state machine under concurrent stress (-race)
ws/bench_test.go    codec + round-trip benchmarks
ws/memory_test.go   per-frame allocation budget (testing.AllocsPerRun)
ws/branches_test.go error-branch coverage: malformed frames, control/fragment
                    paths, armIdle ping, write failure paths
ws/branchgaps_test.go pins the individually hard-to-reach error branches
                    (write validation, close-code range, truncated 64-bit
                    length, 3-frame fragment chains, keepalive write paths)
ws/coverage_test.go closes out accessors, option functions, and rejection
                    branches the other suites don't touch (Dial handshake
                    failures, reserved headers, the upgrade guards)
ws/mcdc_test.go     MC/DC test matrix: one subtest per required
                    independence pair, asserting the observable outcome
                    only that decision flip produces
ws/examples_test.go executable documentation: Example functions, compiled
                    and run on every go test with pinned output; also
                    integration tests of Handle, Upgrade, Dial, CloseCode
cmd/demo/       demo TLS server: /ws/echo, /ws/bearer, /ws/mtls, /ws/goodbye, /certinfo
cmd/certgen/    generates the throwaway CA / server / client certificates
cmd/branchcov/  branch-coverage tool: derives per-branch outcomes from a
                count-mode coverage profile (the stdlib has no branch mode)
cmd/mcdc/       MC/DC audit: enumerates every compound decision, computes
                the required independence pairs from the boolean structure,
                and verifies each is traced to an existing test subtest
e2e/            e2e suites:
                ws.spec.ts       Playwright, Firefox + Chromium: echo, subprotocols,
                                 binary, bearer accept/reject, mTLS rejection, close codes
                e2e_test.go      Go: mTLS positive path, and cross-implementation
                                 interop both directions (Node ws client -> Go server,
                                 Go client -> Node ws server)
                interop-node-{client,server}.mjs
.golangci.yml   strictest standard lint config: default: all, documented exclusions
Makefile        the repeatable gate: make lint / staticcheck / all / e2e / fuzz
.github/workflows/ci.yml runs the gate on every push: lint, staticcheck, race tests,
                    fuzz, statement + branch coverage, MC/DC audit, browser e2e
```

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

## Confidence

Layers of evidence, weakest to strongest:

1. **Unit tests** (`go test ./ws`) — internal consistency: round-trips,
   close-code semantics, keepalive, origin policy, auth, upgrade validation.
2. **RFC test vectors** (`ws/vectors_test.go`) — pins the implementation to
   the spec rather than to itself: the §1.3 handshake example and the §5.7
   frame examples (masked/unmasked, fragmented, 256-byte and 64KiB length
   forms) are taken verbatim from the RFC. If both sides of our stack were
   wrong in the same way, these still fail.
3. **Fuzzing** (`go test ./ws -run '' -fuzz FuzzReadFrame -fuzztime 30s`) —
   the frame decoder is hammered with arbitrary byte streams; the invariant
   is "no panic, no infinite loop, frame or error". Two million executions
   pass clean.
4. **Cross-implementation interop** (`e2e/e2e_test.go`) — the strongest
   conformance evidence: Node's `ws` library (a completely separate
   codebase) plays both roles. Node client ↔ Go server verifies echo,
   binary, subprotocols, header-based bearer auth (something browsers can't
   do), 401 rejection, and the 1001 close. Go client ↔ Node server verifies
   the same in reverse, including a custom 4001 close code.
5. **Browser e2e** (`npm test`) — the user-visible surface in two real
   engines: handshakes, origins, tokens, close codes as the browser
   reports them.
6. **Race detector** (`go test -race ./...`) — the concurrency guarantees
   (write/close from any goroutine, single reader) hold under the
   scheduler's stress.
7. **Concurrency stress tests** (`ws/concurrency_test.go`) — the `Conn`
   state machine is hammered from many goroutines against the documented
   contract: N simultaneous `Close` calls must all observe the same
   winner's recorded error; `ReadMessage` racing a local `Close` must
   terminate consistently; many writers racing a `Close` must each get
   either success or the recorded error, never a torn state; and writes
   after close must always fail. Each body runs ~200 iterations under
   `-race`.
8. **Allocation budget** (`ws/memory_test.go`) — pins the per-frame
   allocation cost with `testing.AllocsPerRun` so a regression (an escaped
   buffer, a fresh copy, a stray slice) fails CI instead of quietly raising
   GC pressure on every message. The budget: a `writeFrame` does **zero**
   allocations in steady state (all per-frame buffers are per-connection
   scratch: the header, the random mask key, and the masked copy are
   reused), and a `readFrame` does exactly **one** — the payload, which the
   caller owns and so cannot be pooled.
9. **Benchmarks** (`go test ./ws -run '^$' -bench . -benchmem`) — pin the
   per-message cost so a regression is visible: codec write/read on both
   sides of the masking rule, an end-to-end `WriteMessage`→`ReadMessage`
   round trip over an in-memory pipe, and the handshake accept key. On a
   Ryzen 7600X a 1 KiB round trip is ~1.8 µs (~570 MB/s) with a single
   allocation (the payload), the masked client write is ~420 ns with zero
   allocations, and the accept key is ~130 ns.
10. **Statement coverage** — the library sits at **97% statement coverage**
   when the unit and e2e suites are combined (97% on the unit suite alone).
   The e2e suite (`go test ./e2e -cover -coverpkg=./ws`) adds the TLS
   client path, the mTLS handshake, and the real-network `Dial`; the two
   count-mode profiles are merged (per-block max of the hit counts) for the
   combined number. `make coverage` prints the unit-only figure.
11. **Branch coverage** — `go test -cover` counts statements, not the
   outcomes of a condition, so branch coverage is measured separately with
   `cmd/branchcov`: it walks the package AST and, for every `if`/`for`/
   `switch`/`select`, derives each outcome from the basic-block counts in a
   count-mode profile (an `if`'s false branch is "the header was evaluated
   more times than its body was entered"; a `for`'s entry and exit are the
   header and body block counts; a `switch` gets one outcome per case plus a
   no-match). The library sits at **95.9% branch coverage** (208 of 217
   outcomes). The nine uncovered outcomes are structurally unreachable
   without fault injection: two `crypto/rand.Read` error paths (it does not
   fail), a `resp.Body != nil` guard (the body is never nil from
   `http.ReadResponse`), a race-free state check the mutex makes dead, and
   five mid-handshake write/hijack failures that need a live connection to
   fail at exactly the wrong instant. `make branchcov` reproduces the
   number; `cmd/branchcov` also documents two limits shared with every
   standard-profile tool (operand-level short-circuiting inside a boolean
   expression, and break-versus-condition-false loop exits).
12. **MC/DC** — the strictest decision-criterion level in common use
   (DO-178C, ISO 26262): for every decision with two or more conditions,
   each condition must be shown to *independently* affect the outcome —
   a pair of executions in which only that condition changes, every other
   condition holds, and the decision flips. Go cannot observe this at
   runtime (profiles carry no condition values, and recording them would
   require instrumenting the source, which breaks short-circuit semantics
   — `isReadTimeout`'s second operand reads the variable the first sets),
   so the criterion is held the way DO-178C practice does for languages
   without native support: `cmd/mcdc` statically enumerates every compound
   decision in `ws.go` (each `&&`/`||` expression, nested ones included) and
   computes the required independence pairs from the boolean structure;
   `ws/mcdc_test.go` provides one subtest per pair, each asserting the
   observable outcome that only that decision flip produces. The tool
   re-checks every trace against the live source — a new or changed
   compound condition, a renamed test, or a pair that no longer flips the
   decision fails the gate. Current state: **8 compound decisions, 17
   required pairs, all traced**; the other 94 if/for conditions are
   single-condition (branch-level, no MC/DC requirement). `make mcdc`
   reproduces the audit.

A note on `synctest`: we use it exactly where it fits, and nowhere else.
The keepalive read loop is timing logic — probe at the boundary, kill on
the repeat, reset on activity — so `ws/keepalive_synctest_test.go` drives
it in a bubble with a fake `net.Conn` whose Read blocks on a bubble
channel or a bubble timer: the clock advances *exactly* to each deadline,
and the tests assert a ping fired at the precise boundary instant (0.00 s
of real time, immune to machine load). That works because every blocking
point in the bubble is a channel or timer. The two things `synctest`
cannot model are exactly the two things our other tests avoid it for:
blocking on I/O (real sockets and `net.Pipe` are not durably blocked, so
the clock never advances) and handing a mutex between goroutines (a mutex
waiter is not durably blocked either — which is why the write-wedge
regression test in `longrunning_test.go` uses a channel-gated fake conn
with a short real timer instead). Using `synctest` on the keepalive also
caught a real design bug: the original implementation's ping was
unreachable in the read loop, and `WithIdleTimeout` silently killed idle
connections instead of keeping them alive.

Security-relevant invariants baked into the design: clients must mask
(enforced both directions — RFC §10.3), message size limits (DoS bound),
strict same-origin default, constant-time token comparison in the demo,
TLS-only client-cert trust (verification is the TLS layer's, the library
only checks presence).

## Linting

The library is a single file people drop into their own repos, so it is
held to the strictest standard lint, and held *repeatably*:

```sh
make lint        # golangci-lint with every linter enabled
make staticcheck # staticcheck -checks=all (a second, independent engine)
make all         # lint + staticcheck + tests, the full gate
```

`lint` runs `golangci-lint` with `default: all` — every linter in the
release, not a curated subset. The result on `ws/ws.go`, the `cmd/` tools,
and the test suite is **zero findings**. That forces real refactors (the
frame codec splits into small single-purpose functions, `atomic.Int32`
for the conn state, static error bases wrapped with `%w`, no single-letter
names outside their natural scope) — and that is the point: the file that
gets copied into your project passes your linter config, not fights it.

`.golangci.yml` keeps the exclusion list short and each entry carries its
reason. The whole-repo disables are three linters that conflict with
deliberate choices:

| disabled | why |
|---|---|
| `wsl`, `wsl_v5` | whitespace-cuddle rules are not part of any mainstream strict config; gofmt stays the formatter, and "fixing" cuddles inserts blank lines that hurt readability |
| `exhaustruct` | forces every struct literal to spell out all fields, including meaningful zeros; for option-heavy types (`tls.Config`, `net.Dialer`, `Config`) that is anti-clarity |
| `funcorder` | wants all unexported methods after all exported ones; the file is organized by protocol concern instead, so each method sits with the behavior it belongs to |

Test files (`_test.go`) get a second, documented exclusion rule — test
scaffolding is not the drop-in artifact, and stateful tests (shared ports,
synctest, table-driven literals) make a blanket strict set there noise.

`staticcheck -checks=all` enables every `ST`/`SA`/`S` check, including
several golangci-lint's staticcheck linter does not enable; it is a second
independent opinion on the same code and also passes clean.

Both gates run on every push in CI (`.github/workflows/ci.yml`), alongside
the race-detector test suite, a 10-second fuzz run, and the browser e2e.

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
