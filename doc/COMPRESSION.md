# permessage-deflate (RFC 7692) — design and interop evidence

Status: **implemented.** `doc/rfc7692.txt` is the spec. Compression is on
by default (`WithCompression(false)` opts out). The sections below are the
design record; the last section records the interop evidence that pins it.

## Why this extension

It is the only WebSocket extension with universal client support: every
major browser has negotiated `permessage-deflate` since ~2015–2016, and
every major client library (Node `ws`, Python `websockets`, Java-WebSocket,
C# System.Net.WebSockets) and proxy (nginx, Caddy, Envoy) supports it.
Browsers send `Sec-WebSocket-Extension: permessage-deflate;
client_max_window_bits` on every connection, so today the library simply
leaves the negotiation unanswered and the traffic stays uncompressed.

The other reference RFCs in `doc/` (8307, 8441, 9220) have no browser
support and conflict with the stdlib-only invariant; they stay
reference-only (see the table in `doc/USAGE.md`).

## Design decisions

1. **Enabled by default, opt-out available.** There are no users of the
   code yet, so the wire behavior change (answering the extension
   negotiation) is not breaking in practice: a peer that never asked for
   compression is never given compressed frames, and RSV1 only appears on
   this connection when both sides negotiated.

2. **Stdlib `compress/flate`, raw streams.** Per RFC 7692 §5.3 a payload
   is a raw deflate stream (no zlib header, no trailer) — exactly what
   `flate.NewWriter` emits and what `flate.NewReader` consumes. No
   third-party dependencies; the drop-in invariant holds.

3. **Per-message contexts in both directions (no context takeover).**
   RFC 7692 §7.2: per-message context is the default; takeover is opt-in.
   so we simply don't offer the takeover parameters and every message
   is compressed/decompressed independently. No cross-message codec state
   → no memory growth, no reset protocol, one fewer set of MC/DC
   decisions.

4. **Window bits: accept the default (15); refuse explicit smaller values
   for that connection.** The stdlib `flate.Writer` always uses a full
   32 KiB window, so honoring `client_max_window_bits=N` for N < 15 would
   require a non-stdlib compressor. If a client requests an explicit
   value < 15, we simply do not answer the extension (the connection
   works uncompressed — exactly what the RFC allows). Measured browser
   traffic never uses an explicit value: Chromium sends the parameter
   without a value (max window = default 15) and Firefox sends no
   parameters at all, so this path is theoretical in browser traffic; it
   is still implemented and tested.

5. **Size guards on the expanded payload.** `WithMaxMessageSize` (default
   16 MiB) bounds the **decompressed** payload; the compressed frame must
   also pass the existing bound before we inflate anything (deflate
   compresses ~1000:1, so the compressed bound alone does not stop a
   decompression bomb — the expanded size is enforced during/after
   inflate and the connection fails with 1009).

6. **Allocation budget holds.** Read side: one heap allocation per
   message as before — the returned (decompressed) payload; the flate
   window (32 KiB) and inflate buffer are per-connection scratch,
   allocated once, reused via `flate.NewReaderReset`. Write side: zero
   allocations — compress into per-connection scratch, single frame
   write. `ws/memory_test.go` gets compressed-path budget subtests
   (warm up the connection, then `AllocsPerRun`).

7. **Control frames stay uncompressed.** Per RFC 7692 §6.2 RSV1 is
   forbidden on control frames (opcodes 0–3) and on continuation frames;
   RSV1 appears only on the first frame of a compressed data message.
   The RSV check in `readFrame` (`rsvMask`) becomes state-aware:
   - RSV2 or RSV3 set → protocol error, 1002 (unchanged);
   - RSV1 set, extension not negotiated → 1002 (today's behavior);
   - RSV1 set, negotiated, first data frame → compressed message;
   - RSV1 set, negotiated, continuation or control frame → 1002 (the
     RFC sets RSV1 only on the first fragment; a later fragment or a
     control frame carrying it is malformed); the compressed flag is
     remembered from the first fragment, so the continuation frames of a
     compressed message arrive with RSV1 cleared.

## API additions

```go
WithCompression(enabled bool)      // default true; opt out per upgrader or dial
WithCompressionLevel(l flate.Level) // default flate.DefaultCompression
```

No new `Conn` accessors. Negotiated parameters live on the connection
internally; tests reach them via the internal `package ws` tests.

## Code layout in `ws/ws.go`

The file stays the single implementation file; new code lands in the
existing section structure, dependency-ordered, and the package doc's
section map is updated:

1. **Handshake section** — extension negotiation:
   - parse `Sec-WebSocket-Extension` (server side): token list per
     extension, parameter parse; an unrecognized extension fails the
     handshake (400) rather than being silently ignored — a conservative
     choice, since this implementation only understands permessage-deflate
     and must not pretend to have agreed an extension it cannot honor;
   - build the response header (server) / request header (client);
   - client-side echo verification, mirroring the existing
     subprotocol-echo rule in `protocol_test.go`: the dial fails if the
     server answers with parameters the client did not allow (window
     bits, context-takeover flags).
2. **Frame codec section** — RSV state machine per the matrix above;
   carry a "message is compressed" flag across fragmented frames.
3. **Message path** — after the last fragment of a compressed message:
   inflate into the per-connection scratch, enforce the expanded size
   bound, return the payload. Write path: deflate into scratch, emit one
   frame with RSV1.
4. **Conn struct** — two scratch sets:
   read side: flate reader + window + inflate buffer (owned by the
   pumping goroutine, same ownership argument as `frameCodec.in`);
   write side: flate writer + output buffer (owned by whichever
   goroutine writes — the write path is already mutex-guarded, so this
   scratch is protected by the existing write lock).

## MC/DC additions

Every new compound decision gets a registry entry with a verbatim `expr`
and a proving subtest, per the MC/DC rule:

- the RSV state machine (each row of the matrix above is one decision
  or sub-decision);
- extension token presence / parameter presence;
- window-bits accept/refuse;
- compressed-size vs expanded-size bounds.

## Test plan

New `ws/deflate_test.go` (internal `package ws`, using `newTestConn`/
`fakeConn`):

- **Handshake:** no header; bare token; each parameter individually and
  combined; explicit `client_max_window_bits` (15 → accepted, <15 →
  refused); unknown extension alongside permessage-deflate (400 — the
  server fails an extension it does not understand, mirroring the
  twice-listed case); permessage-deflate listed twice (400 — the RFC says
  fail).
- **Frame rules:** RSV1 on control frame → 1002; RSV1 on continuation
  → 1002; RSV1 cleared mid-message → 1002; RSV2/3 with the extension
  negotiated → 1002.
- **Round trips (internal conn pair):** text, binary, fragmented
  (RSV1 only on the first fragment), empty-after-inflate edge (a payload
  that inflates to zero bytes is the legal empty message — it round-trips),
  MaxMessageSize enforcement on the
  expanded payload, decompression-bomb-shaped payload (compresses small,
  inflates past the bound → 1009 before the inflate buffer can grow
  unboundedly — the inflate stops at the bound).
- **Options:** `WithCompression(false)` on server and client leaves RSV
  enforcement at today's strictness; `WithCompressionLevel` accepted.
- **Vectors:** RFC 7692 ships no official test vectors; interop is the
  pin (below) plus the internal round trips.

e2e (all must pass before the change ships):

- `e2e/e2e_test.go` + the interop node scripts: Node `ws` client with
  `perMessageDeflate: true` → Go server; Go `Dial` → Node `ws` server
  with `perMessageDeflate: true`. Assert the negotiated extension on
  both sides (Node exposes it via `ws.extensions`).
- Playwright: browsers negotiate permessage-deflate by default, so the
  existing echo tests start exercising the read path automatically;
  add an explicit large-message echo (≥1 MiB) test and a
  MaxMessageSize-guard test so browser-side compression is pinned.
- The demo server (`/ws/echo`) needs no change and becomes a live
  browser proof.

## Rollout order

Each step passes the full gate (`make lint staticcheck test race mcdc
branchcov coverage`, plus `make e2e` for protocol changes):

1. **Negotiation + RSV matrix.** Parse and answer the extension; enforce
   the RSV state machine; still fail any RSV1 frame with 1002 even when
   negotiated (nothing can send one yet). Docs note the feature is
   off-by-construction on the wire.
2. **Read path.** Decompress negotiated messages; server accepts
   browser/client compressed traffic.
3. **Write path (server).** Compress outgoing data messages; internal
   round-trip tests; Node-interop e2e in the client→server direction.
4. **Client offer + echo verification.** `Dial` offers the extension and
   verifies the response; Node-interop e2e in the server→client
   direction.
5. **Hardening + docs.** Compressed allocation-budget tests, MC/DC
   registry complete, `USAGE.md` (replace the "RFC 6455 only, no
   extensions" security bullet; API listing), `CONFIDENCE.md` (new
   invariants: expanded-size bound, RSV state machine, context
   isolation), demo smoke test. Flip the plan status.

## Known limitations (document, don't fix)

- **`compress/flate` is pure Go** — roughly an order of magnitude slower
  than C deflate. Fine for typical message traffic; the VNC-shaped
  tunnel example is the one workload where `WithCompression(false)` or
  `WithCompressionLevel(flate.BestSpeed)` may be the right call, and
  the doc says so.
- **No context takeover**, by decision (item 3): repeated highly
  repetitive frames (e.g. screen streams) compress slightly worse than
  a persistent context would. Revisit only with measured traffic.
- **Window-bits < 15 refused per connection**, by decision (item 4).

## Interop evidence (what pins it)

Three independent, browser-shaped interop paths exercise the codec in both
directions; all run in the e2e gate (`make e2e`):

- **Node `ws` client → Go server** (`e2e/interop-node-client.mjs`, driven by
  `TestInteropNodeClientAgainstGoServer`): the Node client offers
  `permessage-deflate` with `perMessageDeflate: true`; the test asserts the
  negotiated extension is present (`ws.extensions`) and round-trips a 512 KiB
  binary through compression in both directions.
- **Go `Dial` → Node `ws` server** (`TestInteropGoClientAgainstNodeServer`):
  the Go client offers the extension and the Node server accepts it; the test
  asserts `Conn.Compressed()` and round-trips 512 KiB through Node's
  decompressor.
- **Real browsers** (Playwright, Chromium + Firefox): both engines offer
  `permessage-deflate` by default — measured handshakes show Chromium
  sending `permessage-deflate; client_max_window_bits` and Firefox the bare
  token — and the suite *asserts* the negotiation rather than assuming it:
  `/ws/info` reports the server's view (`Conn.Compressed()`), because the
  browser `WebSocket` API exposes no negotiated-extensions property. If a
  browser ever stops offering the extension, the assertion fails instead
  of this evidence line going stale. The echo tests (including a 1 MiB
  binary round-trip) exercise the negotiated read and write paths.

Implementation details the interop forced (all in `ws/ws.go`):

- **Header spelling.** Both RFCs' examples use the plural
  `Sec-WebSocket-Extensions`; the IANA registration is singular. This
  package accepts both spellings on input and sends the RFC plural spelling
  in the offer and the 101 (Node reads only the plural in the response).
- **Decompression tail.** The received payload is a truncated raw DEFLATE
  stream. This implementation appends nine octets — the RFC's
  `00 00 ff ff` *plus* a final BFINAL=1 empty block `01 00 00 ff ff` —
  because real peers (Node, browsers) end their stream with a BFINAL=0
  empty block, and Go's strict `compress/flate` reader would otherwise run
  past it into EOF and report "unexpected EOF".
- **Compression shape.** The compressor uses `flate.Writer.Flush()` (not
  `Close()`) so the stream ends with a BFINAL=0 empty stored block, then the
  trailing four octets are truncated — the exact wire encoding every peer's
  decompressor expects.
