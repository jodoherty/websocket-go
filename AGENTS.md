# AGENTS.md

Instructions for AI coding agents (and humans) working in this repository.

## The drop-in invariant (most important)

This library is a **single implementation file** — `ws/ws.go` — with
**standard-library-only imports**. Its core property is that it can be
vendored by copying that one file into any existing Go project (under any
module path) and compiling.

Rules that preserve it:

- All implementation code lives in `ws/ws.go`. Do not create new
  non-test `.go` files in `ws/`. New behavior goes into the existing
  section structure (10 numbered sections, top to bottom in dependency
  order; keep the section map in the package doc current).
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
- `ws/ws.go` carries a short Unlicense notice at the top of the file so
  the license travels with the file when it is vendored by copying
  (the drop-in property above). Keep that notice, keep it free of any
  attribution, and do not add copyright headers to any other file:
  vendoring this package means copying `ws/ws.go`, and that file alone
  is the unit of distribution.

## Concurrency and allocation invariants

- `Conn.ReadMessage` is owned by one pumping goroutine; `WriteMessage` and
  `Close` are safe from any goroutine. Read-side scratch
  (`frameCodec.in/len8/mask`) and write-side scratch (`hdr/rand4/
  maskScratch`) are each owned by exactly one goroutine — do not move
  them without re-deriving that ownership.
- Steady-state cost is **one heap allocation per message** (the returned
  payload). The frame codec reuses per-connection scratch on purpose.
  Allocation-budget tests pin this; if a new code path allocates per
  frame, fix it before shipping.

## Coverage gates — all of them must pass before committing

The gate is the Makefile; CI (`.github/workflows/ci.yml`) runs the same
set. Do not commit, push, or declare work done until all pass:

```
make lint        # golangci-lint, every linter enabled (.golangci.yml)
make staticcheck # staticcheck -checks=all
make test        # go test ./...
make race        # go test -race ./ws/ ./e2e/
make mcdc        # MC/DC audit: every compound decision traced to a test
make branchcov   # per-branch coverage, unit + e2e merged
make coverage    # statement coverage
```

For protocol or browser-facing changes also run `make e2e` (Go mTLS +
Node `ws` interop both directions + Playwright).

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
at the strict set.

## RFC 6455 conformance

- `doc/rfc6455.txt` is the reference; `ws/vectors_test.go` pins the
  implementation to the RFC's own test vectors (accept key, frames).
  Keep it pinned: when behavior must deviate, document the deviation in
  the function's doc comment with the section number.
- Protocol violations (bad close codes, 1-byte close payload, malformed
  handshake headers, request bodies on the GET) terminate the connection
  or the handshake with the RFC-mandated status/code. Invalid close
  codes are failed with 1002 and never echoed back.

## Workflow

1. Read the sections of `ws/ws.go` relevant to the change; the package
   doc's file map is the index.
2. Make the change; add/adjust tests in the matching `ws/*_test.go`
   (internal `package ws` tests may use the unexported helpers such as
   `newTestConn`/`fakeConn`; the external `ws_test` package covers the
   public API).
3. If the change touches a compound decision: update the MC/DC registry
   and add the proving subtest.
4. Run the full gate (all `make` targets above, plus `make e2e` for
   protocol changes).
5. Commit with an imperative subject describing the behavior, not the
   files.
