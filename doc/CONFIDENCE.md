# Confidence

The layers of test evidence for the `ws` package, weakest to strongest.
(Moved from `README.md`, which is reserved for the project owner's
hand-written editing.)

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
   do), 401 rejection, the 1001 close, **and permessage-deflate in both
   directions** (the negotiated extension is asserted, and a 512 KiB binary
   round-trips compressed). Go client ↔ Node server verifies the same in
   reverse, including a custom 4001 close code and compressed traffic
   (`Conn.Compressed()` asserted). See `doc/COMPRESSION.md` for the details
   the interop forced (header spelling, the decompression tail, the
   compressor's Flush-then-truncate shape).
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
10. **Statement coverage** — the library sits at **98.3% statement
    coverage** when the unit and e2e suites are combined (98.1% on the unit
    suite alone). The e2e suite (`go test ./e2e -cover -coverpkg=./ws`) adds
    the TLS client path, the mTLS handshake, and the real-network `Dial`;
    the two count-mode profiles are merged (per-block max of the hit
    counts) for the combined number. `make coverage` prints the unit-only
    figure.
11. **Branch coverage** — `go test -cover` counts statements, not the
    outcomes of a condition, so branch coverage is measured separately with
    `cmd/branchcov`: it walks the package AST and, for every `if`/`for`/
    `switch`/`select`, derives each outcome from the basic-block counts in a
    count-mode profile (an `if`'s false branch is "the header was evaluated
    more times than its body was entered"; a `for`'s entry and exit are the
    header and body block counts; a `switch` gets one outcome per case plus a
    no-match). The library sits at **94.3% branch coverage** (363 of 385
    outcomes). The uncovered outcomes are error paths that are structurally
    unreachable without fault injection: the `crypto/rand.Read` error paths
    (it does not fail), the flate writer/reader error paths (the encoder and
    decoder do not fail on well-formed input), a guard against an unexpected
    compressor stream tail, a closed-state check the write mutex makes dead,
    and mid-handshake write/hijack failures that need a live connection to
    fail at exactly the wrong instant. `make branchcov` reproduces the number;
    `cmd/branchcov` also documents two limits shared with every
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
    decision fails the gate. Current state: **23 compound decisions, 50
    required pairs, all traced** (the permessage-deflate RSV state machine
    and the extension-negotiation parsing contribute 8 of the decisions);
    the other 164 if/for conditions are single-condition (branch-level, no
    MC/DC requirement). `make mcdc` reproduces the audit.

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
(enforced both directions — RFC §10.3), message size limits (DoS bound —
and, with permessage-deflate, the bound is enforced on the *decompressed*
size during inflate, so a high-ratio payload cannot inflate past it,
failing with 1009), strict same-origin default, constant-time token
comparison in the demo, TLS-only client-cert trust (verification is the
TLS layer's, the library only checks presence), client-side verification
of the server's subprotocol selection (RFC §1.9 — an echoed token must be
one the client offered, and only one; `checkSubprotocolEcho`), the
permessage-deflate RSV state machine (RSV1 is legal only on the first
frame of a negotiated compressed data message; RSV1 on a control or
continuation frame, or RSV1 without the extension, is a 1002 protocol
error; RSV2/RSV3 are always errors), client-side verification of the
server's permessage-deflate response (the extension must be one the client
offered, at most once, and must not demand more of the client's compressor
than it allows), and option limits that fall back to the defaults rather
than degrading (`sanitizeLimits`): non-positive message sizes and negative
timeouts can never silently disable a protection.
