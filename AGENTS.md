# AGENTS.md

Instructions for AI coding agents (and humans) working in this repository.

## README.md is owner-maintained

`README.md` is reserved for the project owner's hand-written editing. Do
not create, edit, or reformat it — not for "improvements", not for sync
with the code, not ever. User-facing documentation lives in `doc/`
instead; when the README's former content changes, update the `doc/`
files, never the README:

- `doc/USAGE.md` — design, API, running the gates and the demo, the
  VNC-shaped example
- `doc/CONFIDENCE.md` — the layers of test evidence and the
  security-relevant invariants
- `doc/LINTING.md` — the lint gate, its exclusions, and why each exists

## The drop-in invariant (most important)

This library is a **single implementation file** — `ws/ws.go` — with
**standard-library-only imports**. Its core property is that it can be
vendored by copying that one file into any existing Go project (under any
module path) and compiling.

Rules that preserve it:

- All implementation code lives in `ws/ws.go`. Do not create new
  non-test `.go` files in `ws/`. New behavior goes into the existing
  section structure (numbered sections in reading order — the high-level
  API first, the internals after; Go does not require declaration order,
  and the section map in the package doc is the index; keep it current).
- Never add an import that is not in the Go standard library.
- Never add a dependency in `go.mod` beyond the module itself.
- `cmd/*` and `e2e/` are tooling and integration tests; they may import
  anything, but nothing in `ws/` may import them or each other.
- Test files (`ws/*_test.go`) are excluded from a vendored copy; put test
  scaffolding there, never in a new implementation file.

If a change genuinely requires a second file, stop and discuss it — the
single-file property is the project's central design commitment.

## Licensing: public domain, no attribution

All code in this repository is released into the public domain under the
Unlicense (see `LICENSE`).

- Never add copyright notices or author attribution anywhere: no
  "Copyright (c) ..." headers, no author name comments, no `@author`
  tags — in implementation files, test files, comments, docs, commit
  messages, or generated tooling.
- `ws/ws.go` carries a short Unlicense notice at the top of the file,
  directly after the package clause (so the package doc comment stays in
  valid position), so the license travels with the file when it is vendored
  by copying (the drop-in property above). Keep that notice, keep it free
  of any attribution, and do not add copyright headers to any other file:
  vendoring this package means copying `ws/ws.go`, and that file alone
  is the unit of distribution.

## Concurrency and allocation invariants

- `Session` is built on `RawConn` by containment (`Session.raw`,
  unexported — never embed): a `Session` must expose exactly the session
  surface and nothing of the raw event/frame API, and no accessor may
  hand the underlying `*RawConn` to callers. One read loop per transport:
  the session's `ReadMessage` is the only reader of its `RawConn`.
  `DialRaw`/`UpgradeRaw`/`HandleRaw` hand the `RawConn` to applications
  that run the protocol policy themselves.
- Protocol compliance lives in `RawConn` and therefore applies in both
  modes: client masking, the close-code table (invalid codes failed with
  1002, never echoed), RFC 6455 §5.6 UTF-8, the message size limit, and
  frame reassembly. `Session` adds policy only: auto-pong, the pong
  handler, the close-to-terminal-error mapping, and keepalive probing.
- The read side is owned by one pumping goroutine in either face:
  `Session.ReadMessage` (or `Session.Drain`, that read side run to its
  terminal) for a session, `RawConn.ReadEvent` (or `RawConn.Drain`) for raw
  mode — and a connection has exactly one of those pumping at once, never
  both, and a loop and its drain are never concurrent. `WriteMessage`,
  `WriteFrame`, `Pong`, and `Shutdown` are safe from any goroutine.
  `Close` is too, and deliberately takes **no** write lock: it only swaps the
  state and closes the transport, so a stalled writer holding `c.mu` can never
  wedge teardown. Nothing outside the pumping goroutine may read.
  Read-side scratch
  (`frameCodec.in/len8/mask`) and write-side scratch (`hdr/rand4/
  maskScratch`) are each owned by exactly one goroutine — do not move
  them without re-deriving that ownership.
- Steady-state cost is **one heap allocation per message** (the returned
  payload). The frame codec reuses per-connection scratch on purpose.
  Allocation-budget tests pin this; if a new code path allocates per
  frame, fix it before shipping.

## Coverage gates — all of them must pass before committing

The gate is the Makefile, run locally (there is no CI). `make gate` runs
the whole set in one command; the individual targets, shown here, are the
same. Do not commit, push, or declare work done until all pass:

```
make lint        # golangci-lint, every linter enabled (.golangci.yml)
make staticcheck # staticcheck -checks=all
make test        # go test ./...
make race        # go test -race ./...
make fuzz        # fuzz targets: the frame codec plus the connection-level
                # protocol state machines, 10 s each
make mut         # mutation gate: every curated security mutation must be
                # killed by the test suite; the gate fails if the environment
                # cannot run the mutants or if every mutant is uncompilable
make bench       # per-message and per-connection cost benchmarks
make mcdc        # MC/DC audit: every compound decision traced to a test
make model       # frame-reassembly machine: model properties + trace fidelity
make close-model # close-handshake machine: model properties + trace fidelity
make deflstream  # DEFLATE stream machine (part 1): the RFC 1951/7692
                # reference classifier self-check; the Go suite replays the
                # exhaustive 1-2 byte table as TestDecompressStreamTable
make deflstate   # DEFLATE stream machine (part 2): the byte-granular
                # streaming state machine self-check (Q1-Q4); the Go
                # suite replays the frame traces as TestMBTDeflState
make deflstate-model # part 2 coarse reachability cross-check (nuXmv)
make branchcov   # per-branch coverage, unit + e2e merged
make coverage    # statement coverage
make multiver    # build + vet + ws unit + Go e2e, all under -race, on
                # go1.25.0 / go1.26.0 / go1.27.1 (browsers only on the
                # default toolchain, via e2e)
make e2e         # Go mTLS + Node `ws` interop both directions + Playwright
```

`e2e` is already in the gate, but run it early and often on protocol or
browser-facing changes: it is the slowest target.

## MC/DC rule (know this before writing any boolean condition)

`cmd/mcdc` statically enumerates **every compound decision** in `ws/` —
including nested sub-decisions (`a && b && c` yields `a && b` as a second
decision) — and `make mcdc` fails unless each condition's independence
pair is traced in `cmd/mcdc/registry.go` to a test subtest that asserts
the observable outcome of the flip.

So: when you write (or rewrite) an `&&`/`||` expression in `ws/ws.go`,
add its registry entry(ies) and the proving subtest in the same change.
Registry `expr` strings must match the source expression exactly (the
gate compares them verbatim); use concatenation to keep lines under the
lll limit rather than paraphrasing. A deleted or reworded condition
orphan its registry entry — remove or update it.

## Lint config is deliberate

`.golangci.yml` enables **every linter** with a short, documented
exclusion list; each exclusion carries a "why". Do not:

- add a `//nolint:` without a reason comment, or
- extend the exclusion list casually — each entry is a judgment call, and
  adding one silently erodes the strictest-standard stance.

The test-file exclusions in `.golangci.yml` are intentionally broad
(short names, table breadth, shared state); keep the implementation file
at the strict set. The full rationale, including the whole-repo linter
disables and their why-each, is in `doc/LINTING.md`.

## RFC 6455 conformance

- `doc/rfc6455.txt` is the reference; `ws/vectors_test.go` pins the
  implementation to the RFC's own test vectors (accept key, frames).
  Keep it pinned: when behavior must deviate, document the deviation in
  the function's doc comment with the section number.
- Protocol violations (bad close codes, 1-byte close payload, malformed
  handshake headers, request bodies on the GET) terminate the connection
  or the handshake with the RFC-mandated status/code. Invalid close
  codes are failed with 1002 and never echoed back.

## Repo layout

```
ws/ws.go            the entire library in one file — copy it into an
                    existing project (package ws, stdlib only). Organized
                    in numbered sections, reading-ordered (high-level API
                    first, internals after), with a file map in the
                    package doc.
ws/ws_test.go       unit tests: echo, close codes, keepalive, masking,
                    origin policy, bearer auth, upgrade validation
ws/vectors_test.go  RFC 6455 test vectors (§1.3 accept key, §5.7 frames)
ws/fuzz_test.go     fuzz targets: FuzzReadFrame (codec safety) plus six
                    connection-level targets — the session read loop in all
                    four state variants (FuzzSessionRead), raw traffic with
                    interleaved legal writes (FuzzRawTraffic), the RFC 7692
                    negotiation parsers (FuzzCompressionParams), subprotocol
                    selection/echo (FuzzSubprotocolNegotiation), the client
                    101-response parser (FuzzHandshakeResponse), and Dial
                    URL→target resolution with CRLF-injection invariants
                    (FuzzDialURL)
ws/keepalive_test.go keepalive probe state machine + timeout classification
ws/keepalive_synctest_test.go keepalive read loop on a fake clock
                    (testing/synctest): exact probe/kill/refresh timelines,
                    plus the stalled-write bounded-write regression
ws/closeframe_test.go Shutdown/Close/Drain: the close-frame write status
                    (nil on a live transport, the write failure on a stalled
                    one, the already-closing refusal, the code rejection),
                    Close as pure non-blocking teardown (abrupt, no frame,
                    never wedged by a stalled writer), that Shutdown leaves
                    the read side live, and Drain: the read side run to its
                    terminal as one call (peer-code delivery, clean-end EOF,
                    ping and data discard, the terminal fast-fail, the
                    abrupt-close clean end)
ws/raw_test.go      the raw API: the ReadEvent contract (control frames are
                    events, no auto-pong, close resolution), the WriteFrame
                    MC/DC matrix (state, control shape, UTF-8, writable set),
                    the DialRaw / UpgradeRaw / HandleRaw server and client faces
ws/dial_test.go       Dial URL→target resolution: default ports, explicit
                    ports, bracketed IPv6 literals
ws/longrunning_test.go write-deadline wedge regression + Closed() signal,
                    transport-write failure failing the connection, Close's
                    write-deadline bound
ws/concurrency_test.go concurrent-stress suite (-race): the close state
                    machine, writer-vs-close, read-vs-close, drain-vs-close,
                    and the reader-goroutine write paths (session auto-pong
                    and raw application pong interleaved with app writes)
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
ws/protocol_test.go  RFC 6455 §4.1 handshake-validation pins and the §7.4
                    close-code rules: unusable codes failed with 1002,
                    must-not-set codes never on the wire, request bodies
                    rejected, client-side subprotocol-echo verification
                    (§1.9)
ws/deflate_test.go   permessage-deflate (RFC 7692): extension negotiation
                    (server offer parsing, client response verification), the
                    RSV1 state machine, compressed round trips (incl. empty
                    and fragmented messages), decompression error branches,
                    and the compressed-path allocation budget
ws/protocolerror_test.go RFC 6455 §7.1.7 at the RawConn level: a frame-level
                    protocol violation is answered with a 1002 close frame
                    before the transport is torn down
ws/utf8_test.go      RFC 6455 §5.6 UTF-8 enforcement on text frames: read
                    and write paths, fragmented messages, the MC/DC pair
ws/writehelpers_test.go WriteText/WriteBinary/WriteJSON wire format and
                    WriteJSON marshal failure
ws/extendedconnect_test.go the extended-CONNECT branch of Upgrade at the
                    unit level: :protocol routing, version-only validation
                    (the handshake key is optional and ignored),
                    subprotocol/extension negotiation, origin policy, the
                    full-duplex requirement, the 501 deadline gate and its
                    waiver, and the SessionOnStream surface (net.Pipe, the
                    DeadlineStream adaptation, the deadline refusal)
ws/handshake_header_limit_test.go the bounded client handshake-response head
                    read (the header-flood defense): a normal response
                    returned whole with the reader left at the first frame,
                    an over-limit header set rejected, an over-long single
                    line rejected, a truncated set rejected
ws/allocbudget_{race,norace}_test.go build-tag split reporting whether the
                    race detector is on: the flate decompression allocation
                    budget (deflate_test.go) is pinned only on the non-race
                    run, because the race instrumentation inflates the
                    flate reader's per-message allocation count
ws/examples_test.go executable documentation: Example functions, compiled
                    and run on every go test with pinned output; also
                    integration tests of Handle, Upgrade, Dial, CloseCode
ws/mbt_test.go     model-based validation runner: replays the committed
                    frame-reassembly traces (ws/testdata/mbt/*.json) against a
                    RawConn. Asserts the MUST outcomes hard and measures the
                    RFC 6455 7.1.7 SHOULD/MAY layer as a counted warning
                    ledger (checked against ws/testdata/mbt/NOTES.json; fail
                    on an unaccepted or stale entry). Data, not generated
                    code — traces come from model/gen/gen_traces.py, the
                    runner is hand-written (doc/STATES.md)
ws/mbt_close_test.go model-based validation runner for the close-handshake
                    machine: replays ws/testdata/closehandshake/*.json against
                    a RawConn, driving each trace in the shape the RFC's §7.1.1
                    example prescribes (Shutdown → read to terminal → Close).
                    Checks the §5.5.1/§7.4 wire rules, the §7.1.5 resolution,
                    and the §7.1.2 close-once-both-sent-and-received SHOULD, as
                    the same warning ledger (ws/testdata/closehandshake/
                    NOTES.json). Currently 0 warnings (doc/CLOSE-HANDSHAKE.md)
ws/mbt_deflate_test.go model-based validation runner for the RSV1 /
                    compressed-message machine: replays
                    ws/testdata/deflate/*.json against a RawConn with
                    permessage-deflate negotiated (doc/DEFLATE-MACHINE.md).
                    Same MUST/SHOULD/MAY contract, same warning ledger
                    (ws/testdata/deflate/NOTES.json); the two accepted
                    entries are the RFC 7692 silences (a failed decompression
                    owes no Close frame the RFC names; a decompressed size
                    overflow likewise)
ws/deflstream_test.go the DEFLATE stream machine replay (part 1, doc/
                    DEFLATE-STREAM.md): every row of the exhaustive 1-2 byte
                    table (ws/testdata/deflstream/oracle.json, 65,792 rows)
                    against the live decompress pipeline; asserts the
                    implementation-layer match and the spec-COMPLETE
                    acceptance, and counts the accepted PREFIX/MALFORMED
                    leniencies against NOTES.json (three MAY:deflate-accept
                    entries)
ws/deflstate_test.go  the DEFLATE state-machine replay (part 2, doc/
                    DEFLATE-STREAM.md): the committed frame traces
                    (ws/testdata/deflstate/, 182 files) against a live
                    compressed RawConn on both sides: delivery asserted
                    byte-for-byte, the terminal close codes (wire-side
                    limit 1002, decompression 1002/1009, text UTF-8
                    1007), and the MAY lenient acceptances counted
                    against NOTES.json (seven accepted IDs)
ws/testdata/mbt/   committed model-based traces (JSON): one per (transition,
                    side); plus NOTES.json, the allowlist of accepted SHOULD/
                    MAY divergences (each with its RFC basis + reason)
ws/testdata/closehandshake/
                    committed close-handshake traces (JSON): one per
                    (state, shape, side) over the RFC's three states and 17
                    close-body shapes; plus NOTES.json (empty: no accepted
                    divergences)
ws/testdata/deflate/
                    committed RSV1 / compressed-message traces (JSON): one per
                    (transition, side) over the 349-state machine; plus
                    NOTES.json (two accepted RFC 7692 silences)
ws/testdata/deflstream/
                    the exhaustive DEFLATE stream table (oracle.json, 65,792
                    rows: every 1-2 byte buffer, implementation layer + RFC
                    7692 spec layer) and NOTES.json (three accepted MAY
                    leniencies: stream-incomplete, padding-nonzero,
                    tail-missing)
ws/testdata/deflstate/
                    committed DEFLATE state-machine traces (JSON): one per
                    (witness state, variant, side) over the 31 coarse
                    (phase, output) classes -- single final frame, split
                    fragment, interleaved ping -- plus the two-stream
                    wire, the bomb, and the text UTF-8 pair; NOTES.json
                    accepts the seven MAY IDs that fire (five
                    deflate-accept shapes + the two close-omitted
                    silences)
cmd/demo/       demo TLS server: /ws/echo, /ws/bearer, /ws/mtls, /ws/goodbye, /certinfo
cmd/certgen/    generates the throwaway CA / server / client certificates
cmd/branchcov/  branch-coverage tool: derives per-branch outcomes from a
                count-mode coverage profile (the stdlib has no branch mode)
cmd/mcdc/       MC/DC audit: enumerates every compound decision, computes
                the required independence pairs from the boolean structure,
                and verifies each is traced to an existing test subtest
cmd/mut/        mutation gate: applies each of 74 curated security-relevant
                one-spot rewrites (operator flips, bound changes, deleted
                guards, constant shifts) to a scratch copy of the ws package
                and requires the full test suite to kill it; a surviving
                non-equivalent mutant is a test gap and fails the gate, and so
                does an environment in which no mutant can run
doc/USAGE.md      user-facing guide: design, API, running, VNC example
doc/CONFIDENCE.md the layers of test evidence and security invariants
doc/LINTING.md    the lint gate and its documented exclusions
doc/rfc6455.txt   the RFC 6455 reference
doc/rfc7692.txt   the RFC 7692 reference (permessage-deflate)
doc/rfc1950.txt   the RFC 1950 reference (DEFLATE format overview)
doc/rfc1951.txt   the RFC 1951 reference (the DEFLATE compressed data format)
doc/rfc3629.txt   the RFC 3629 reference (UTF-8; the shared boundary machine's spec)
doc/rfc8307.txt   the RFC 8307 reference (QUIC)
doc/rfc8441.txt   the RFC 8441 reference (HTTP/2 extended CONNECT)
doc/rfc9220.txt   the RFC 9220 reference (HTTP/3 extended CONNECT)
doc/COMPRESSION.md permessage-deflate design + interop evidence
doc/DEFLATE-STREAM.md the DEFLATE stream machine: part 1 -- the RFC 7692
                    7.2.1 compliant shape, the reference classifier (RFC
                    1951), the exhaustive table, the ledger; part 2 --
                    the byte-granular streaming state machine (13
                    phases, content-agnostic), the Q1-Q5 self-checks,
                    the coarse nuXmv cross-check, the frame traces
doc/STATES.md     the frame-reassembly state machine: the RFC 6455
                    transformation, the shared RFC 3629 boundary machine
                    (P6 projection), trace
                    generation, and the behaviors the model pins
doc/CLOSE-HANDSHAKE.md the close-handshake state machine: the RFC's OPEN/
                    CLOSING/CLOSED states, the Shutdown/read/Close mapping to
                    §7.1.1's worked example, the MUST/SHOULD/MAY table, the
                    properties (P1-P6), and the §7.1.2 finding that drove the
                    Shutdown/Close split
doc/DEFLATE-MACHINE.md the RSV1 / compressed-message state machine: RFC 7692
                    6's framing rules on the reassembly machine, the (wire,
                    decompressed) compressed fragment states, the poisoned
                    states, the target sets over the RFC 7692 silences,
                    the properties (W1-W5, P1-P8, RX), trace generation, and
                    the behaviors the model pins
                h3/             separate module: a real quic-go HTTP/3 extended-
                                CONNECT (RFC 9220) round-trip over SessionOnStream
                                (make e2e-h3)
model/          model-based validation suite (doc/STATES.md): the RFC 6455
                frame-reassembly machine, generated traces, and the nuXmv
                container. Not a Go module (Python + SMV only), so the root
                go.mod stays dependency-free.
                Containerfile    nuXmv 2.2 (FBK tarball, SHA-256 verified)
                gen/utf8bound.py the exact RFC 3629 §3/§4 boundary machine over
                                 fragment boundaries (10 states, the five
                                 narrow acceptance sets), shared by the
                                 reassembly machine and the RSV1 machine;
                                 B1-B7 self-check
                gen/check_utf8props.py the boundary machine's properties
                                 (make utf8-model), pure Python
                gen/common.py    the transition function trans(state, frame):
                                 the single source of truth (46 states incl.
                                 count-0 and the 10 suffixes per text count,
                                 36 frame classes incl. the empty-payload
                                 shapes, the check order, and the RFC
                                 citations); text-fragment UTF-8 delegates to
                                 utf8bound
                gen/gen_model.py emits the SMV model from common.trans (nuXmv
                                 encodes the machine independently for the
                                 reachability cross-check)
                gen/gen_traces.py minimal frame traces by BFS over the machine,
                                 cross-checked against nuXmv, one JSON per
                                 (transition, side) -> ws/testdata/mbt/
                gen/check_props.py model self-consistency (P1/P2/P6
                                 projection/completeness/encoding), pure
                                 Python
                gen/check_traces.py committed-trace <-> model consistency,
                                 pure Python
                gen/closehandshake.py the close-handshake machine: the RFC's
                                 three states over 17 close-body shapes, with
                                 the §5.5.1/§7.1.x citations (independent of
                                 common.py — a different machine)
                gen/gen_closemodel.py emits the close SMV from closehandshake
                                 (includes the `initiate` input: CLOSING is
                                 reached by sending, not only by receiving)
                gen/gen_closetraces.py one JSON per (state, shape, side),
                                 cross-checked against nuXmv -> ws/testdata/
                                 closehandshake/
                gen/check_closeprops.py close-model self-consistency (P1-P6)
                gen/check_closetraces.py close-trace <-> model consistency
                gen/deflate.py   the RSV1 / compressed-message machine
                                 (doc/DEFLATE-MACHINE.md): RFC 7692 6 on top of
                                 RFC 6455 reassembly, at maxMessageSize 6; 349
                                 states (plain FGB/FGT at limit 6, the 14
                                 (wire, decompressed) compressed pairs x the
                                 10 boundary suffixes, the poisoned states,
                                 the pending-41 states), 83 frame classes;
                                 W1-W7 self-check (W6: the part-1
                                 reference matches the implementation's
                                 decompress() on deflate_oracle.json,
                                 every wire the machine can accumulate;
                                 W7: spec-COMPLETE compliant wires
                                 deliver the exact payload)
                gen/deflate_stream.py the DEFLATE stream machine (part 1,
                                 doc/DEFLATE-STREAM.md): the spec reference
                                 classifier for permessage-deflate compressed
                                 data -- flate_decode (RFC 1951: the bit-
                                 packing, the canonical code construction,
                                 the three block types, the fault classes),
                                 impl_decompress (the ws/ws.go decompress
                                 loop with its size-guard ordering), and
                                 spec7692 (the RFC 7692 7.2.1 compliant
                                 shape: stream + truncated empty stored
                                 tail); plus the exhaustive table generator
                gen/check_deflstreamprops.py the stream self-check (A-H):
                                 the RFC's worked examples and tables, the
                                 7.2.1 shape, and exhaustive agreement with
                                 the committed decompression oracle
                gen/deflate_state.py the streaming DEFLATE state machine
                                 (part 2, doc/DEFLATE-STREAM.md): the
                                 byte-granular decoder configuration
                                 machine (13 phases, content-agnostic,
                                 output tracked as a capped count),
                                 total on all states
                gen/check_deflstateprops.py the state-machine
                                 self-check (Q1-Q4): outcome/output
                                 agreement with the reference on every
                                 prefix of the exhaustive table and
                                 every oracle wire, absorption,
                                 prefix-set soundness
                gen/gen_deflstatemodel.py the coarse SMV model (6
                                 phases x capped output) + witness
                                 verification + soundness + the per-pair
                                 nuXmv reachability cross-check (Q5)
                gen/gen_deflstatetraces.py the frame-trace generator:
                                 witness states x frame variants, the
                                 expectations from the reference
                                 classifier, the machine cross-checked
                                 on every wire -> ws/testdata/deflstate/
                gen/deflate_oracle.json the decompression oracle: the
                                 implementation's decompress() on all 1,531
                                 alphabet accumulations up to the limit
                                 (generated by the Go oracle test; the same
                                 code the traces replay against)
                                 implementation's decompress() on all 1,531
                                 alphabet accumulations up to the limit
                                 (generated by the Go oracle test; the same
                                 code the traces replay against)
                gen/gen_defmodel.py emits the RSV1 SMV from deflate.trans
                gen/gen_defltraces.py one JSON per (transition, side),
                                 cross-checked against nuXmv -> ws/testdata/
                                 deflate/
                gen/check_deflprops.py RSV1 model self-consistency (P1/P2/P6
                                 placement/P7/P8 stickiness/RX audit,
                                 completeness/encoding)
                gen/check_defltraces.py RSV1 trace <-> model consistency
e2e/            e2e suites:
                tests/ws.spec.ts   Playwright, Firefox + Chromium: echo, subprotocols,
                                 binary, bearer accept/reject, mTLS rejection,
                                 compression negotiation, close codes
                global-setup.ts    builds the demo, binds it on ephemeral ports,
                                 and records the base URL the browser suite dials
                playwright.config.ts the browser-suite config (chromium + firefox
                                 projects, self-signed-cert tolerance, and the
                                 globalSetup above)
                e2e_test.go      Go: mTLS positive path, and cross-implementation
                                 interop both directions (Node ws client -> Go server,
                                 Go client -> Node ws server)
                interop-node-{client,server}.mjs
                h2/             separate module: a real x/net/http2 extended-CONNECT
                                (RFC 8441) round-trip through Upgrader.Upgrade; runs
                                on the go1.26 toolchain with http2xconnect=1 (make
                                e2e-h2)
                h3/             separate module: a real quic-go HTTP/3 extended-
                                CONNECT (RFC 9220) round-trip over SessionOnStream
                                (make e2e-h3)
.golangci.yml   strictest standard lint config: default: all, documented exclusions
Makefile        the repeatable gate: make gate (the full set) plus the
                    individual lint / staticcheck / test / race / fuzz /
                    mut / bench / mcdc / model / close-model / model-image /
                    mbt-gen / mbt-report / close-mbt-gen / close-report /
                    deflate-model / defl-gen / defl-report / deflstream /
                    deflstream-gen / deflstate / deflstate-model /
                    deflstate-gen / branchcov / coverage / e2e targets
```

## Workflow

1. Read the sections of `ws/ws.go` relevant to the change; the package
   doc's file map is the index.
2. Make the change; add/adjust tests in the matching `ws/*_test.go`
   (internal `package ws` tests may use the unexported helpers such as
   `newTestConn`/`fakeConn`; the external `ws_test` package covers the
   public API).
3. If the change touches a compound decision: update the MC/DC registry
   and add the proving subtest.
4. Run `make gate` — all targets, including e2e.
5. Commit with an imperative subject describing the behavior, not the
   files.
