# The frame-reassembly machine: RFC 6455 → state machine → traces

This is the model-based validation suite for the WebSocket frame-reassembly
path. It transforms the RFC 6455 read path into an explicit state machine,
encodes that machine independently in nuXmv, generates minimal frame traces
from it, and replays the traces against a live `RawConn` in Go. The goal is
to pin the receiver's frame-level behavior — the part that is most
stateful and most likely to harbor correctness bugs — with traces derived
from the RFC, not from observed implementation behavior.

## Pipeline

```
RFC 6455 §5–§7
        │  careful transformation (this document + gen/common.py)
        ▼
   common.py            the transition function trans(state, frame) and
        │               wire_close(state, frame) — single source of truth
        ├──► gen_model.py      → SMV model (nuXmv encoding, IVAR peer)
        ├──► check_props.py    → P1/P2/completeness/encoding (pure Python)
        ├──► gen_traces.py     → minimal frame traces (BFS) + nuXmv
        │                         reachability cross-check → JSON
        ├──► check_traces.py   → trace ↔ model consistency (pure Python)
        ▼
   ws/testdata/mbt/*.json   committed traces
        ▼
   ws/mbt_test.go           replays each trace against a RawConn
```

`common.py` is the one authoritative artifact. The SMV model is *generated*
from it (so the two encodings cannot drift), and the traces are generated
from it. nuXmv plays two roles: an independent re-encoding of the model
(reachability cross-check in `gen_traces.py`) and a property oracle
(`make model` cross-checks reachability; the safety properties are checked
exhaustively in Python because they are properties of the transition
function, not of reachability). The nuXmv 2.2 user manual is included at
`model/doc/nuxmv-user-manual.{pdf,txt}` for reviewer reference.

## The machine

### States

| state | meaning |
|---|---|
| `IDLE` | not in a message |
| `FGB{n}` | accumulating a **binary** fragment, `n` tokens so far (1..3) |
| `FGT{n}` | accumulating a **text** fragment, `n` tokens so far, valid UTF-8 so far |
| `FGT{n}B` | accumulating a text fragment, `n` tokens so far, **not** valid UTF-8 so far |
| `TERM` | terminal (absorbing) |

The message-size limit in the model is 3 tokens (`MAXMSG`), so fragment
counts top out at 3 and any further accumulation overflows. The `B` suffix
on text fragments exists because RFC 6455 §5.6 validates the *whole*
(concatenated) text message, so a fragment must remember whether the bytes
accumulated so far are already broken — a peer can split an invalid UTF-8
sequence across frames to defeat a per-frame check.

### Events (the peer's frame alphabet)

Each event is a symbolic frame; `gen/common.py:encode_frame` gives the
concrete bytes (side-specific masking: a server under test receives masked
frames, a client under test receives unmasked ones, RFC 6455 §5.1).

- well-formed data / continuation: `text1`, `text0`, `text0ff`, `bin0`,
  `bin02`, `cont0`, `cont02`, `cont1`, `cont12`, `contff`, `textbad`
- well-formed controls: `ping`, `ping1`, `pong`
- well-formed closes: `close1000`, `close1000r`, `close3000`, `closeempty`
- close-code faults: `close999` (unusable), `close1005` (must-not-set),
  `close1byte` (one-byte payload), `closebadutf8` (non-UTF-8 reason)
- header / opcode faults: `badop` (reserved opcode), `rsv1` (RSV1 without
  permessage-deflate), `rsv23` (RSV2/3 set), `maskbad` (masking violation),
  `len16nonmin` / `len64nonmin` (non-minimal length form), `ping0`
  (control not FIN), `pingbig` (control payload >125), `big` (frame > limit)
- transport end: `eof`

### Transitions (check order per frame)

Within a single frame the receiver checks, in order: (1) header rules —
RSV2/3, RSV1-without-extension, masking, non-minimal length, control-FIN,
control-size, single-frame size (RFC 6455 §5.2, §5.5, §5.1); then (2) the
message-level rules — continuation-without-start, data-while-in-fragment,
cross-frame size, UTF-8 (RFC 6455 §5.4, §5.5, §5.6); then (3) close
resolution (§5.5.1, §7.4). A frame that trips a header rule never reaches
the message rules. The full transition table is `common.trans`; the
citations live in `common.FAULT_RFC`.

## Conformance layer: MUST / SHOULD / MAY

The RFC (RFC 2119 modalities) does not treat every obligation the same way,
and the model measures them differently, so the suite pins *conformance* —
not merely a behavior snapshot. Every terminal step records the close-frame
outcomes with a modality:

| modality | meaning in the RFC | test behavior |
|---|---|---|
| `must` | MUST / MUST NOT — a hard invariant | fails the test on mismatch |
| `should` | SHOULD — the recommended behavior | silent if met; a MAY-permitted alternative is a counted warning |
| `may` | MAY — a permitted deviation from the SHOULD default | a counted, assessable warning |

The canonical case is §7.1.7 (*Fail the WebSocket Connection*): on a
protocol violation the endpoint **MUST** close the connection and stop
processing data, **SHOULD** send a Close frame with an appropriate status
code, and **MAY** omit that frame "if it believes the other side is unlikely
to be able to receive and process the Close frame, due to the nature of the
error." So a protocol violation has two modeled outcomes — the SHOULD (send
the frame, e.g. 1002/1007) and the MAY (omit it, `wire: none`, a bare
protocol error) — and which one the implementation takes is what the trace
measures. Taking the MAY records a warning; taking the SHOULD is silent.

The MUST layer (a terminal error is returned, no more data is processed,
the delivered events are exactly right, the wire close code is legitimate)
is always asserted hard. Only the SHOULD/MAY layer produces warnings.

### The warning ledger and driving it to zero

Warnings are aggregated by a **stable ID** (one ID per root cause, so a
single code change clears every trace that shares it), checked against
`ws/testdata/mbt/NOTES.json` (the allowlist of *accepted* divergences, each
with its RFC basis and reason), and reported as one countable line
(`make mbt-report`). The suite is currently fully conformant to the SHOULD
layer:

```
MBT-WARNINGS: 0 (fully conformant to the SHOULD layer)
```

The gate is self-enforcing in both directions:

- a warning fires that `NOTES.json` does **not** accept → **fail** (a new,
  unassessed divergence); and
- a `NOTES.json` entry that **no longer** fires → **fail** (stale — the
  divergence was eliminated, so remove the entry).

To **eliminate** a warning: fix the implementation so it takes the SHOULD
outcome (the count drops), then remove the now-stale `NOTES.json` entry (the
build fails until you do, which is the pressure to keep the ledger minimal).
The goal is a ledger that shrinks to empty as the implementation converges
on the SHOULDs — and it is there: the one divergence this layer found
(message-level violations omitting the §7.1.7 SHOULD close frame) is gone,
because `ws.go` now sends the 1002 frame on those violations too.

## Properties

Checked by `make model` (pure Python, no container):

- **P1 — wire close-code legitimacy.** The close code the machine transmits
  is always `0` (no close frame), a usable code in 1000–4999 (1004/1005/
  1006/1015 excluded), or the protocol-error 1002 / invalid-data 1007. An
  unusable or must-not-set peer close code is failed with 1002 and never
  echoed (§7.4). `closeempty` resolves to 1005 but must not set it on the
  wire.
- **P2 — terminal absorbing.** `TERM` never leaves once reached.
- **completeness.** `trans` is a total function over every (state, frame)
  pair — a gap would be a silent omission in the model.
- **encoding round-trip.** each frame encodes to exactly the byte length its
  header claims, on both sides.

`gen_traces.py` additionally cross-checks, with the independent nuXmv
encoding, that every target transition is reachable (and that Python and
SMV agree on reachability).

## Trace generation

For each target transition `(FROM, FRAME)`, `gen_traces.py`:
1. finds the **minimal** frame sequence that fires it by BFS over the
   machine's non-terminal states (BFS ⇒ shortest script);
2. replays it through `trans` to compute the expected `ReadEvent` results
   (message payload reconstructed by concatenating the fragments);
3. cross-checks reachability against nuXmv;
4. emits one JSON trace per side (server, client).

Non-observable transitions (fragment accumulation with no event and no close
frame) get no dedicated trace: they are pinned as *prefixes* of the
completion traces, whose message payload asserts the accumulation was
correct.

## Behaviors the model pins (and why they matter)

These are behaviors the traces pin explicitly — the close-frame policy for
each violation class, the size limit that applies to close frames too, and
the per-fragment UTF-8 rule:

1. **Every protocol violation sends the SHOULD close frame.** Header
   violations (masking, RSV, non-minimal length, control size, single-frame
   size) and close-code violations answer with 1002; UTF-8 violations answer
   with 1007; and message-level violations (continuation-without-start,
   data-frame-while-in-fragment, cross-frame-size-overflow) also answer with
   1002, uniform with the rest — meeting the §7.1.7 SHOULD in every case.
   The model still records the §7.1.7 MAY (omit the frame on a
   state-corrupting error) as a permitted alternative, so the suite would
   warn if the implementation ever regressed to a bare teardown; today it
   takes the SHOULD everywhere, so the warning ledger is empty.
2. **`maxMessageSize` bounds every frame, including close frames.** The
   frame codec rejects any frame whose payload exceeds the limit, so a
   close frame with a reason larger than the limit is rejected with 1002.
   The model's close-with-reason frames are kept within the limit
   (3 bytes) to exercise the reason-echo behavior.
3. **Per-message UTF-8 on fragments.** A text fragment is validated on the
   concatenated payload at completion, not per frame: `FGT1 + contff`
   (0x41 then 0xff) fails with 1007, and a fragment that is already broken
   (`FGT1B`) fails on completion regardless of the final fragment.

## Running it

```
make model        # pure Python: P1/P2/completeness/encoding + trace↔model
make test         # replays the committed traces (in the normal suite)
make mbt-report   # print the MBT warning count (the assessable summary)
make mbt-gen      # regenerate the traces (needs the podman container);
                  # fails if the committed traces would change
make model-image  # build the nuXmv container (only when Containerfile changes)
```

`model`, `mbt-report`, and the MBT test run in the gate without any
container; only regeneration (`mbt-gen`) needs podman. The MBT test also
enforces the `NOTES.json` allowlist (fail on an unaccepted warning or a
stale entry), so `make mbt-report` is the quick way to *see* the count the
gate is enforcing. Regeneration is deterministic: the same model yields
byte-identical traces, which is what the `mbt-gen` idempotency check
enforces.

## Scope and follow-ups

This is the **frame-reassembly** machine only. Deliberately out of scope for
the pilot:

- the **close-handshake** state machine (who owes what, frames after close)
  — RFC 6455 §5.5.1, §7.1.5/7.1.7;
- the **handshake** (§4.x) — a one-shot validation table, already pinned by
  `vectors_test.go` / `protocol_test.go`;
- **permessage-deflate** (RFC 7692) — the RSV1 context and
  context-reset-on-protocol-error rules (a second machine, same trace
  vocabulary);
- **concurrency** — stays the race detector's job; the model is
  per-connection by construction.

The machine is `common.trans`; adding a machine means adding its states,
frame alphabet, transition rows, and (for the close-handshake) a
two-sided nuXmv encoding for the deadlock/liveness properties that a
one-sided trace replay cannot express.
