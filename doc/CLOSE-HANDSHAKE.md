# The close-handshake machine

Model-based validation for the WebSocket close handshake — the second machine
in the MBT program, after frame reassembly (`doc/STATES.md`).

Machine: `model/gen/closehandshake.py` · checker: `make close-model` ·
traces: `ws/testdata/closehandshake/` (102, committed) · runner:
`ws/mbt_close_test.go` (`TestMBTCloseHandshake`) · regeneration:
`make close-mbt-gen` (needs podman) · warning count: `make close-report`.

**Current status: 0 warnings.** Every SHOULD and MAY the model states is met;
`NOTES.json` is empty.

## Modeling principle (read this first)

The model is a **faithful, implementation-independent formalization of the
RFC's close-handshake obligations**, derived from RFC 6455 §5.5.1,
§7.1.1–§7.1.7, §7.4, and §8.1 — *not* from `ws.go`. Four consequences:

1. **The implementation is the target, not the source.** Where `ws.go` deviates
   from the RFC, the divergence is a *finding* the suite surfaces (a MUST
   failure, or a counted SHOULD/MAY) — it is never baked into the model as "the
   behavior to pin." This machine found a real one (§7.1.2, below); the fix
   changed the implementation, not the model.
2. **Every RFC obligation is modeled, testable or not.** A SHOULD or MUST the
   MBT cannot directly assert (a timing bound, a write-side rule, a
   transport-level SHOULD) is still in the model, because the model *is* the
   spec. The test is a **documented subset** of the model: we name which rows
   the MBT drives and which are deferred. We never drop an RFC obligation from
   the model because it is inconvenient to test.
3. **Modalities are RFC-derived, not chosen to fit.** A row is MUST, SHOULD, or
   MAY because the RFC says so (with a citation), regardless of what the
   implementation happens to do.
4. **RFC obligations and project conventions are separate.** The RFC governs the
   *wire* (which Close frames are exchanged, which codes may appear) and the
   *resolution* (the code/reason, §7.1.5/§7.1.6). How the implementation
   *reports* a closed connection to the application (`io.EOF` vs. a
   `*CloseError`) is a project convention, not an RFC obligation — pinned by the
   suite, but labeled policy, not MUST/SHOULD/MAY.

## The API is the RFC's example

§7.1.1 gives clean closure as a worked example:

> one would call `shutdown()` with SHUT_WR on the socket, call `recv()` until
> obtaining a return value of 0 indicating that the peer has also performed an
> orderly shutdown, and finally call `close()` on the socket.

One method per step:

| RFC step | method | state effect |
|---|---|---|
| `shutdown(SHUT_WR)` — §7.1.2 *Start the Closing Handshake* | `Shutdown(code, reason)` | `OPEN → CLOSING`; write half closed, read half live |
| `recv()` until 0 | `ReadEvent` / `ReadMessage` to its terminal | `CLOSING → CLOSED` when the peer's Close lands |
| `close()` — §7.1.1 *Close the WebSocket Connection* | `Close()` | transport down; no-op if already down |

There is deliberately **no method that waits for the closing handshake**. Only
reading can complete it (§7.1.5 makes the close code the first Close *received*),
and reading belongs to the pumping goroutine. A blocking `Close` deadlocks the
moment a handler closes from its own goroutine — which is the common case — so
the design makes that deadlock unrepresentable rather than bounding it with a
timeout.

`Close()` without a preceding `Shutdown()` is an abrupt close: no Close frame
goes out and the peer resolves to 1006 (§7.1.5). §7.1.1 permits this ("close the
connection via any means available"), and it is what a bare `defer c.Close()`
does when the application never said goodbye.

## The RFC's state machine

§7.1.1–§7.1.4 define three states, and the implementation now has all three
(`stOpen` / `stClosing` / `stClosed`, ws.go:2223-2227):

| state | RFC | entered when |
|---|---|---|
| `OPEN` | §7.1.1 (Established) | no Close sent or received |
| `CLOSING` | §7.1.3 | *either* sending **or** receiving a Close frame |
| `CLOSED` | §7.1.4 | the underlying transport is closed |

§7.1.4 calls a closure **clean** when the transport closed *after* the closing
handshake completed — i.e. after **both** endpoints exchanged a Close.

**`CLOSING` is transient in the responding case.** Receiving a Close in `OPEN`
starts the handshake (§7.1.3), §5.5.1 requires the answer, and once both frames
are exchanged §5.5.1 says the endpoint "considers the WebSocket connection
closed and MUST close the underlying TCP connection" — which is `CLOSED`. So
`OPEN + valid Close → CLOSED`: `CLOSING` is entered and left inside one step.
`CLOSING` is *observable* only in the initiating case, where this endpoint sent
its Close first and is waiting. The model encodes exactly this.

## The RFC's obligations, by state

**In `OPEN`, on receiving a Close** (§5.5.1, §7.1.5, §7.1.6, §7.1.7):
- If we did not previously send a Close, we **MUST** send a Close in response.
- We **SHOULD** echo the status code we received; **SHOULD** send it as soon as
  practical; **MAY** delay it until the current message is sent.
- The Connection Close Code is the code in the *first* Close received, or
  **1005** if that Close carries no code (§7.1.5). The reason, or empty
  (§7.1.6).
- A Close whose body is invalid is a protocol error → **Fail** (below).

**In `CLOSING`, on receiving the peer's Close** (§5.5.1, §7.1.2):
- The MUST-to-echo does **not** apply (we already sent one); no second Close.
- Once we have **both sent and received** a Close, we **SHOULD** now Close the
  connection (§7.1.2) — and §5.5.1 makes the transport close a MUST at that
  point.

**The Close-frame body** (§5.5.1, §7.4, §8.1):
- If present, the body's first two bytes **MUST** be a 2-byte status code; a
  **1-byte** body cannot hold a code and is invalid.
- The code **MUST** be in 1000–4999 and **not** a must-not-set code
  (1004/1005/1006/1015, §7.4); 0–999 and >4999 are undefined (§7.4.2).
- Any reason **MUST** be valid UTF-8 (§8.1).
- We **MUST NOT** *set* 1004/1005/1006/1015 on the wire (§7.4).

**Fail the connection on an invalid Close** (§7.1.7) — a 1-byte body, an
out-of-range or must-not-set code, or a non-UTF-8 reason:
- **MUST** close and **MUST NOT** continue processing data;
- **SHOULD** send a Close frame with an appropriate code (1002) first; **MAY**
  omit it if the peer is unlikely to process it.

**After sending a Close** (§5.5.1): we **MUST NOT** send any more data frames.
Note the asymmetry the RFC draws: nothing forbids *receiving* after a Close, and
§5.5.1 explicitly lets the peer keep sending until it has sent its own. So
`CLOSING` is write-half-closed, read-fully-open — which is why the write gate in
`ws.go` tests `!= stOpen` while the read gate tests `== stClosed`.

**Transport-level closure** (§7.1.1): the TCP **SHOULD** be closed first by the
server; a client **SHOULD** wait for the server's TCP Close. Below the MBT's
scope (the suite drives `RawConn`, not the socket) — modeled, deferred. It does
shape `closeAfterHandler`, which shuts down and closes without draining: the
handler's read loop has already returned, and §7.1.1 says a *server* "SHOULD
initiate a TCP Close immediately".

## The MUST / SHOULD / MAY layer (RFC-derived)

"MBT?" says whether driving `ReadEvent` can assert the row. "Deferred" rows are
still in the model but validated elsewhere or not assertable here.

| obligation | modality | RFC | MBT? |
|---|---|---|---|
| reject a 1-byte body | MUST (fail) | §5.5.1, §7.1.7 | yes |
| reject an out-of-range code (0–999, >4999) | MUST (fail) | §7.4.2, §7.1.7 | yes |
| reject a must-not-set code received on the wire | MUST (fail) | §7.4, §7.1.7 | yes |
| reject a non-UTF-8 reason | MUST (fail) | §8.1 | yes |
| never *set* 1004/1005/1006/1015 on the wire | MUST NOT | §7.4 | yes |
| MUST NOT send more data frames after a Close | MUST NOT | §5.5.1 | deferred (write side) |
| send a Close in response (when we did not already) | MUST | §5.5.1 | yes |
| echo the status code received | SHOULD | §5.5.1 | yes |
| send the response Close as soon as practical | SHOULD | §5.5.1 | no — timing, noted |
| in `CLOSING`, close once both sent and received | SHOULD | §7.1.2 | yes — **met** |
| resolve to the first Close received | MUST | §7.1.5 | yes |
| on a protocol error, send a Close (1002) before closing | SHOULD | §7.1.7 | yes |
| MAY omit that Close if the peer is unlikely to process it | MAY | §7.1.7 | accepted alternative |
| MAY delay the response Close until the current message is sent | MAY | §5.5.1 | accepted alternative |
| close the TCP first from the server; client waits | SHOULD | §7.1.1 | no — transport, noted |

## The §7.1.2 finding, and what fixed it

The suite was built against an implementation where `Close(code, reason)` sent
the Close frame and closed the transport in one step. So an *initiating*
endpoint never consumed the peer's Close: the next `ReadEvent` returned the
terminal recorded from **our own sent code**, not the peer's. That is a §7.1.2
SHOULD deviation and a §7.1.5 consequence — 30 of the 102 traces warned.

The model kept the RFC's SHOULD regardless, and the implementation was changed to
meet it: the close call was split into `Shutdown` (send, → `CLOSING`) and
`Close` (transport down), with the read path completing the handshake —
`finalizeClose` resolves to the **peer's** code and takes the transport down
when its Close lands. Warnings: 30 → 0.

## Project conventions (pinned, but not RFC modalities)

How the read reports a closed connection (the `RawConn.ReadEvent` terminal):
- `io.EOF` for a normal closure — resolved code 1000, or 1005 (no status).
- `*CloseError{code, reason}` for any other resolved code.
- `*CloseError{1002, reason}` for a protocol failure.

This is reporting policy, documented on `ReadEvent`, pinned for regression — not
an RFC MUST/SHOULD/MAY. The RFC governs the wire and the resolution, not the
in-process error type.

One consequence worth naming: an endpoint that calls `Shutdown` and then `Close`
**without reading** reports a clean end rather than the peer's code, because it
never received one. That is §7.1.5's explicit allowance (endpoints may disagree
on the close code) plus §5.5.1's "no guarantee that the endpoint that has
already sent a Close frame will continue to process data" — not a gap to paper
over with an invented error.

## The MBT-readable decision table

For `OPEN`:

| outcome | wire echo (peer observes) | terminal (project) |
|---|---|---|
| usable code (1000 … 4999, not must-not-set) | `[code, reason]` | `io.EOF` for 1000, else `*CloseError{code, reason}` |
| empty body → 1005 | `` (no code — 1005 is must-not-set) | `io.EOF` |
| violation (1-byte / must-not-set / out-of-range / bad-UTF-8) | `1002` + reason | `*CloseError{1002, reason}` |

For `CLOSING`: no second Close on the wire, and the resolution is the **peer's**
code. For `CLOSED`: absorbing — no reaction at all.

### Close-frame alphabet (one trace class per body shape)

`close-empty`, `close1000`, `close1000r`, `close1001`, `close1002`,
`close1007`, `close1009`, `close3000`, `close4999`, `close1004`, `close1005w`,
`close1006w`, `close1015w`, `close0000`, `close5000`, `close1byte`,
`closebadutf8` — 17 shapes × 3 states × 2 sides = **102 traces**. Reasons are
short, valid UTF-8; a too-long reason is a frame-size violation (the reassembly
machine's concern). Traces use a large `maxMessageSize` so close frames are not
size-rejected — that limit is a harness parameter, not an RFC concept.

### How the runner drives each state

| state | driver |
|---|---|
| `OPEN` | feed the peer's Close; read to terminal |
| `CLOSING` | `Shutdown(initCode)` → feed the peer's Close → read to terminal → `Close()` |
| `CLOSED` | `Shutdown(initCode)` → `Close()` → feed the Close → read (must not react) |

`initCode` is 1000, so an implementation that wrongly resolved to its own sent
code would still be caught: the model expects the *peer's* code.

## Properties (checked by `make close-model`)

- **P1 (wire legitimacy).** Every outcome's wire close code is empty, a usable
  code in 1000–4999, or 1002 — never 1004/1005/1006/1015, never out of range.
- **P2 (resolution legitimacy).** The resolved Connection Close Code follows
  §7.1.5: the received code when present, 1005 when the body is empty.
- **P3 (CLOSED absorbing).** No transition leaves `CLOSED`.
- **P4 (completeness).** Every `(state, shape)` has exactly one defined outcome.
- **P5 (echo consistency).** `OPEN` answers; `CLOSING` never sends a second Close.
- **P6 (invalid → 1002).** Every invalid shape resolves to 1002, never the
  peer's invalid code.

`make close-mbt-gen` additionally cross-checks every `(state, shape)`
transition's reachability against an independent nuXmv encoding of the same
machine; the two encodings must agree or generation fails. Because `CLOSING` is
reached by *initiation* rather than by a frame arriving, the SMV model has an
`initiate` input alongside the peer's free-choice `shape` — without it the
entire initiating half of the handshake would be unmodelled.

## What the MBT tests vs. defers

- **Tests** (drives `RawConn.ReadEvent`): the resolution / echo / wire rows,
  the MUST NOT on the wire, and the §7.1.2 initiating behavior.
- **Defers** (in the model, validated elsewhere or not assertable): the
  write-side MUST NOT (no data after a Close — `closeframe_test.go`), the §5.5.1
  "as soon as practical" timing, the §7.1.1 transport-close SHOULDs, and the two
  MAY alternatives (recorded as accepted, not asserted).

## Implementation mapping

| model concept | `ws.go` |
|---|---|
| `OPEN` / `CLOSING` / `CLOSED` | `stOpen` / `stClosing` / `stClosed` (2223-2227) |
| §7.1.2 Start the Closing Handshake | `Shutdown` (3310) → `sendCloseFrame` (3247) |
| §7.1.1 Close the WebSocket Connection | `Close` (3356) |
| `OPEN` receives a Close | `ReadEvent`, `case OpClose` (2460) |
| resolution | `resolvePeerClose` (2735) |
| echo + complete the handshake | `finalizeClose` (3326) |
| terminal reporting (project) | `closeErrFor` / `terminalErr` (4229 / 4221) |
| must-not-set / usable | `mustNotSetCloseCode` / `usableCloseCode` (2765 / 2777) |
| write half closed in `CLOSING` | write gates test `state != stOpen` |
| read half live in `CLOSING` | read gate tests `state == stClosed` (2430) |
