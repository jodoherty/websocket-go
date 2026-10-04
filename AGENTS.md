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
  `Session.ReadMessage` for a session, `RawConn.ReadEvent` for raw mode —
  and a connection has exactly one of them, never both. `WriteMessage`,
  `WriteFrame`, `Pong`, and `Close` are safe from any goroutine.
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
make fuzz        # frame-codec fuzzer, 10 s
make bench       # per-message and per-connection cost benchmarks
make mcdc        # MC/DC audit: every compound decision traced to a test
make branchcov   # per-branch coverage, unit + e2e merged
make coverage    # statement coverage
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
                    file map in the package doc.
ws/ws_test.go       unit tests: echo, close codes, keepalive, masking,
                    origin policy, bearer auth, upgrade validation
ws/vectors_test.go  RFC 6455 test vectors (§1.3 accept key, §5.7 frames)
ws/fuzz_test.go     FuzzReadFrame — codec safety fuzz target
ws/keepalive_test.go keepalive probe state machine + timeout classification
ws/keepalive_synctest_test.go keepalive read loop on a fake clock
                    (testing/synctest): exact probe/kill/refresh timelines,
                    plus the stalled-write bounded-write regression
ws/raw_test.go      the raw API: the ReadEvent contract (control frames are
                    events, no auto-pong, close resolution), the WriteFrame
                    MC/DC matrix (state, control shape, UTF-8, writable set),
                    the DialRaw / UpgradeRaw / HandleRaw server and client faces
ws/dial_test.go       Dial URL→target resolution: default ports, explicit
                    ports, bracketed IPv6 literals
ws/longrunning_test.go write-deadline wedge regression + Closed() signal,
                    transport-write failure failing the connection, Close's
                    write-deadline bound
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
ws/protocolerror_test.go RFC 6455 §7.1.7 at the Conn level: a frame-level
                    protocol violation is answered with a 1002 close frame
                    before the transport is torn down
ws/utf8_test.go      RFC 6455 §5.6 UTF-8 enforcement on text frames: read
                    and write paths, fragmented messages, the MC/DC pair
ws/writehelpers_test.go WriteText/WriteBinary/WriteJSON wire format and
                    WriteJSON marshal failure
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
doc/USAGE.md      user-facing guide: design, API, running, VNC example
doc/CONFIDENCE.md the layers of test evidence and security invariants
doc/LINTING.md    the lint gate and its documented exclusions
doc/rfc6455.txt   the RFC 6455 reference
doc/rfc7692.txt   the RFC 7692 reference (permessage-deflate)
doc/COMPRESSION.md permessage-deflate design + interop evidence
e2e/            e2e suites:
                ws.spec.ts       Playwright, Firefox + Chromium: echo, subprotocols,
                                 binary, bearer accept/reject, mTLS rejection, close codes
                e2e_test.go      Go: mTLS positive path, and cross-implementation
                                 interop both directions (Node ws client -> Go server,
                                 Go client -> Node ws server)
                interop-node-{client,server}.mjs
.golangci.yml   strictest standard lint config: default: all, documented exclusions
Makefile        the repeatable gate: make gate (the full set) plus the
                    individual lint / staticcheck / test / race / fuzz /
                    bench / mcdc / branchcov / coverage / e2e targets
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
