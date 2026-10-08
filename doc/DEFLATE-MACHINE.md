# The RSV1 / compressed-message machine: RFC 7692 6 → state machine → traces

This is the model-based validation suite for the permessage-deflate
framing path — the RSV1 axis of RFC 7692 on top of the RFC 6455
frame-reassembly rules. It transforms the RFCs into an explicit state
machine, encodes that machine independently in nuXmv, generates minimal
frame traces from it, and replays the traces against a live `RawConn`
with permessage-deflate negotiated. The goal is to pin the receiver's
compressed-message behavior — RSV1 placement, the compressed context,
decompressed UTF-8, decompression failure — with traces derived from the
RFCs, not from observed implementation behavior.

The machine is `model/gen/deflate.py`. It builds on the shared RFC 3629
UTF-8 boundary machine (`model/gen/utf8bound.py`, checked by
`make utf8-model`), which its text fragment states delegate to — the
compressed domain's mid-rune chunks are exactly what make the boundary
machine's narrow acceptance sets live (the reassembly machine's
alphabet reaches only {CLEAN, BROKEN}; this machine reaches all ten).

## Pipeline

```
RFC 7692 6/6.1/6.2 (+ RFC 6455 5, RFC 3629 3-4)
        |  careful transformation (this document + gen/deflate.py)
        v
   deflate.py           the transition function trans(state, frame)
                        + the DEFLATE wire encoding (per-fragment
                        complete-stream form, RFC 7692 7.2.1/7.2.3.5)
        +--> gen_defmodel.py     --> SMV model (nuXmv encoding, IVAR peer;
                                     state-pruned for the nuXmv BDD limit)
        +--> check_deflprops.py  --> W1-W6 wire invariants (self-check in
                        deflate.py), P1/P2/P6/P7/P8/RX, completeness,
                        encoding round-trip (pure Python)
        +--> gen_defltraces.py   --> minimal frame traces (BFS) + nuXmv
                                     reachability cross-check --> JSON
        +--> check_defltraces.py --> trace <-> model consistency (pure
                                     Python)
        v
   ws/testdata/deflate/*.json    committed traces (+ NOTES.json ledger)
        v
   ws/mbt_deflate_test.go        replays each trace against a RawConn
   ws/decompressoracle_test.go   pins the implementation's decompress()
                                 to the committed oracle (W6's Go side)
```

`deflate.py` is the one authoritative artifact. The SMV model is
*generated* from it (so the two encodings cannot drift), and the traces
are generated from it. nuXmv cross-checks reachability independently;
the safety properties are checked exhaustively in Python because they
are properties of the transition function, not of reachability.

## The machine

### What the RFC mandates (the machine's source)

On a connection where a PMCE is in use (RFC 7692 6), RSV1 is the
"Per-Message Compressed" bit:

- **A message is compressed exactly when RSV1 is set on its first
  fragment.** The frames of a compressed message carry compressed data —
  including its continuation frames, whose RSV1 bit is 0 (6.1 forbids
  RSV1 on non-first fragments). The receiver decompresses the
  concatenation of the frames' compressed payloads (6.2) and uses the
  *decompressed* bytes for the message event, with the compressed bit
  unset.
- **RSV1 MUST NOT be set on control frames or on non-first fragments of
  a data message** (6.1); a receiver MUST fail the connection on such a
  frame.
- **Compressed wire bytes are not subject to the original data type's
  constraints** (6.1): a compressed text message's payload may be any
  bytes. After decompression the payload is subject to them again — a
  compressed text message is checked against RFC 6455 5.6 on its
  *decompressed* bytes (1007).
- **Everything else is RFC 6455**: header rules, continuation-without-
  start, data-while-in-fragment, close resolution, and the size policy —
  applied unchanged to compressed traffic, and to the plain (uncompressed)
  domain of a negotiated connection, which this machine carries at its
  own limit instantiation.

### States (349)

| state | meaning |
|---|---|
| `IDLE` | not in a message |
| `TERM` | terminal (absorbing) |
| `FGB{n}` | accumulating a **plain binary** fragment, n wire tokens (0..6) |
| `FGT{n}<S>` | accumulating a **plain text** fragment, n wire tokens, boundary suffix `<S>` = the shared UTF-8 boundary machine's state for the accumulated bytes |
| `CFB{w}_{d}` | accumulating a **compressed binary** fragment: w wire tokens, d DECOMPRESSED tokens; d = 7 is the saturating "already over the limit" mark |
| `CFT{w}_{d}<S>` | accumulating a **compressed text** fragment: w wire tokens, d decompressed tokens, boundary suffix over the DECOMPRESSED bytes |
| `CFB_P{w}` / `CFT_P{w}` | a **poisoned** compressed message at wire w: a non-final frame whose bytes cannot join any DEFLATE stream; only a final frame can end it, and it ends as a decompression failure |
| `CFB_P41_{w}_{d}` / `CFT_P41_{w}_{d}<S>` | a **pending-41** compressed fragment: the current segment starts with the accidental byte `0x41`, which is not a complete stream on its own; the message ending exactly on it decodes to the empty payload, any following byte makes the message undecodable (poison or decompression failure) |

The plain states are named as in the reassembly machine, at this
machine's limit (the project's `maxMessageSize`, instantiated at 6 here,
3 there — the limit is a model parameter, not an RFC constant; the trace
carries it as `maxMessageSize`). The compressed states are the machine's
heart, and they track **two** counts, because the policy bounds **both**
axes: the accumulated WIRE payload (checked per frame while accumulating,
before decompression — a compressed fragment's wire bytes are bounded
exactly like a plain fragment's) and the DECOMPRESSED total (checked at
completion, when it is known). The pair set is exactly the one the
alphabet can accumulate under the wire limit (14 pairs, closed under the
machine's non-fault transitions; every other accumulation is a wire
cross-frame fault), and the text variants carry the shared boundary
machine's state over the decompressed bytes — the compressed domain's
mid-rune chunks are what make the boundary machine's narrow acceptance
sets live (the reassembly machine's alphabet reaches only {CLEAN,
BROKEN}; this machine reaches all ten, and RX pins it).

### Events (the peer's frame alphabet, 83 classes)

Each event is a symbolic frame; `deflate.encode` gives the concrete
bytes (side-specific masking, RFC 6455 5.1). Four families:

- **plain domain**: single-frame messages (`text1`, `text0`, `text4`,
  `bin0`, `bin02`, `bin4`, ...), the empty shapes (`bin0e`, `text0e`,
  `cont0e`, `cont1e`), fragments (`cont0`, `cont02`, `cont1`, `cont12`,
  `contff`), controls, closes, the header faults (`badop`, `rsv23`,
  `maskbad`, `len16nonmin`, `len64nonmin`, `ping0`, `pingbig`, `big7`)
  and `eof` — the reassembly machine's rules at limit 6;
- **compressed single-frame** (RSV1, FIN=1): `ctext1`, `ctexte`,
  `ctextff`, `ctextc2`, `ctexte0`, `ctextp3`, `ctexted`, `ctextf0`,
  `ctextf4`, `ctextp4`, `ctextk2`, `ctextbad`, `ctextbomb`, `cbin1`,
  `cbine`, `cbinbad`, `cbinbomb` — the edge-representative decompressed
  chunks per acceptance set of the shared boundary machine (the K2
  chunk is `\xf4\x80`: F4 + a valid second byte, pending two more —
  `\xf4\x90` would already be BROKEN), the failed-stream class, and the
  LZ77 bomb (7 decompressed tokens in 5 wire bytes);
- **compressed starts** (RSV1, FIN=0) and **compressed continuations**
  (RSV1=0): `ctext0`, `ctext0w`, `ctext0e0`, ..., `ccontA1`,
  `ccontC31`, `ccont891`, `ccontK20`, `ccont1bomb` — the fin=0 starts
  reach every boundary state (including the five narrow hazard states)
  as a live compressed fragment state;
- **RSV1 misuse** (RFC 7692 6.1 MUST NOT): `rsv1ctrl` (RSV1 on a control
  frame), `ccontR` (RSV1 on a continuation frame).

A plain continuation frame in a compressed context is a compressed
continuation: its payload reads as compressed data, and its chunk is
whatever its concrete bytes decode to (the "accidental" semantics, pinned
by the self-check — e.g. `cont1`'s one byte decodes to the empty chunk,
`contff` fails the decompression, and `cont02`'s two bytes leave the
receiver's segment scan a stranded trailing byte — the message is
*poisoned* and can only complete as a decompression failure). The same
wire frame genuinely means different things in the two contexts, and the
machine branches on context exactly as the receiver must.

### Transitions (check order per frame)

Within a single frame the receiver checks, in order (outcome-preserving:
every ordering choice lands both branches on the same terminal outcome):

1. **header rules** — RSV2/3, masking, non-minimal length, control-FIN,
   control-size, single-frame wire size (RFC 6455 5.1/5.2/5.5) → 1002;
2. **transport end** (RFC 6455 7.1.5) → 1006;
3. **controls** — RSV1 on a control frame is the 7692 6.1 violation
   (1002); well-formed controls interleave with fragments, which are
   preserved;
4. **close resolution** (RFC 6455 5.5.1/7.4) — identical in both
   domains;
5. **data / continuation** — RSV1 placement (7692 6.1: RSV1 is legal
   only as the first data frame of a message) before message structure
   (6455 5.4: continuation-without-start, data-while-in-fragment) before
   accumulation and completion. In a compressed context the per-frame
   **wire** check fires before any decompression (a compressed fragment
   grows past the limit exactly as a plain one does → 1002), then the
   frame's stream fate (a failed decompression → {1002, 1007}), and at
   completion the **decompressed** size ({1002, 1009}) and the
   decompressed UTF-8 (1007) — in that order.

A frame that trips a header rule never reaches the message rules.

## Conformance layer: MUST / SHOULD / MAY

Same conformance discipline as the reassembly machine: MUST outcomes are
hard; a SHOULD outcome is the RFC's recommendation; a MAY outcome is a
counted, assessable warning. The RSV1 machine adds one thing the plain
machine does not need — **target sets**. Where the RFC designates the
close code (1002 protocol error, 1007 invalid data, 1000/3000 resolved
closes), the SHOULD is a singleton. Where the RFC is silent, the SHOULD
is the set of candidate codes:

| fault | SHOULD target set | why |
|---|---|---|
| RSV1 on a control frame / non-first fragment | {1002} | 7692 6.1 "Fail the WebSocket Connection" = 6455 7.1.7 generic failure; 1002 is the protocol-error code |
| structure / header / wire-size faults | {1002} | RFC 6455, as in the reassembly machine |
| plain or decompressed UTF-8 on a text message | {1007} | 6455 5.6 + 7.4.2 |
| failed decompression (corrupt or truncated stream) | **{1002, 1007}** | 7692 6.2 is silent on failure; the 7.1.7 SHOULD applies generically with 1002 or 1007 as candidates |
| decompressed size overflow | **{1002, 1009}** | the limit is project policy, not RFC; 1009 "message too big" and 1002 are the candidates |

Each code in the set is its own SHOULD outcome (meeting any one raises no
warning); the 7.1.7 MAY (omit the Close frame) is a counted warning under
a stable ID. The two RFC 7692 silences — a failed decompression and a
decompressed size overflow — are the assessable divergences this machine
tracks (`MAY:decompress-close-omitted`,
`MAY:decompress-size-close-omitted`), accepted in
`ws/testdata/deflate/NOTES.json` with their RFC basis: the
implementation reports those errors directly to the reader and sends no
Close frame, which is the MAY outcome the RFC permits.

## Properties

Checked by `make deflate-model` (pure Python, no container):

- **W1 wire budget** (self-check): every non-fault data frame's wire
  payload fits the limit — a compressed frame that did not would fail at
  the header before its compressed logic, and the class's declared
  behavior would be unreachable.
- **W2 declared chunks**: every dedicated compressed class's concrete
  payload decompresses (per the receiver's decompression semantics:
  segment scan + completion tail) to exactly its declared chunk; the
  fate-"bad" payloads fail.
- **W3 accidental chunks**: the plain continuation classes'
  compressed-context chunks match the pinned expectations (the machine
  cannot drift from the concrete bytes).
- **W4 limit honesty**: the bomb chunk exceeds the limit in decompressed
  tokens and fits it in wire bytes — the decompressed overflow is a real
  alphabet class, not an arithmetic accident.
- **W5 no wire collision**: no two frame classes encode to the same
  bytes on a side (the receiver's interpretation is the machine's
  context branching, not a class distinction).
- **P1 close-code legitimacy**: every code in every target set is a
  usable code in 1000-4999 (1004/1005/1006/1015 excluded).
- **P2 terminal absorbing**: `TERM` never leaves once reached.
- **completeness**: `trans` is a total function over all 349 x 83
  (state, frame) pairs.
- **encoding round-trip**: each frame encodes to exactly the byte length
  its header claims, on both sides.
- **P6 RSV1 placement**: RSV1 is legal exactly on the first data frame
  of a compressed message (from `IDLE`); from every other
  non-terminal state, every RSV1 frame fails the connection.
- **P7 no plain-domain leak**: a plain (RSV1=0) frame in a plain context
  never enters a compressed state.
- **P8 sticky compressed context**: a continuation in a compressed
  context stays in the compressed domain (accumulates or completes),
  never jumping to a plain fragment state.
- **RX reachability audit**: every boundary-machine state is exercised
  by a reachable compressed text fragment state — the RSV1 machine
  reaches the shared boundary machine's FULL state space — and the key
  plain/compressed counts (0..limit, plus the saturating overflow count)
  are reachable.

`gen_defltraces.py` additionally cross-checks, with the independent nuXmv
encoding, that every target transition is reachable (and that Python and
SMV agree).

## Trace generation

For each target transition `(FROM, FRAME)`, `gen_defltraces.py`:
1. finds the **minimal** frame sequence that fires it by BFS over the
   machine's non-terminal states (BFS => shortest script);
2. replays it through `trans` to compute the expected `ReadEvent`
   results — the delivered payload is the concatenation of the
   fragments' wire payloads (plain message) or of their DECOMPRESSED
   chunks (compressed message, RFC 7692 6.2);
3. cross-checks reachability against nuXmv;
4. emits one JSON trace per side (server, client), carrying
   `maxMessageSize` so the concrete replay uses exactly the modeled
   limit.

Non-observable transitions (fragment accumulation with no event and no
close frame) get no dedicated trace: they are pinned as *prefixes* of the
completion traces, whose delivered payload asserts the accumulation was
correct.

## Behaviors the model pins (and why they matter)

1. **RSV1 placement is enforced in both directions.** RSV1 on a control
   frame and on any non-first fragment (whether the message is
   compressed or plain) fails the connection with the SHOULD 1002 close;
   RSV1 on the first data frame is the only legal use. The misuse
   classes fire from every fragment state, not just compressed ones — a
   plain fragment with an RSV1 continuation is 7692 6.1 territory too.
2. **The compressed context is sticky.** A continuation frame in a
   compressed message carries compressed data with RSV1=0 (6.1's
   prohibition is what makes the bit a *message* marker, not a *frame*
   marker): the machine tracks the context in CFB/CFT, and P8 pins that
   a compressed context never bleeds into the plain states.
3. **Decompressed UTF-8, not wire UTF-8.** A compressed text message is
   validated on its decompressed bytes (6.1 puts the payload back under
   the original data type's constraints; 6455 5.6): a message whose wire
   bytes are anything but whose decompressed bytes are not valid UTF-8
   fails with 1007 — and a fragment may legally end mid-rune, with the
   check on the concatenated decompressed message at completion. This is
   the axis the shared boundary machine exists for: every one of its ten
   states, including the overlong/surrogate/max-codepoint hazard states,
   is live in the compressed domain (RX).
4. **Decompression failure is a terminal with an under-specified close.**
   A corrupt or truncated stream fails the connection; the RFC names no
   Close frame for it, so the model offers the SHOULD set {1002, 1007}
   plus the MAY omission, and the ledger records which one the
   implementation takes.
5. **Both size axes are bounded, and they fire in order.** The wire
   total is checked per frame while accumulating (a three-3-byte-block
   compressed message fails on the third frame, 1002, before any
   decompression); the decompressed total is checked at completion (the
   bomb chunk: 7 decompressed tokens in 5 wire bytes — {1002, 1009}).
   A wire fault beats a decompression fault and a decompressed-size
   fault, exactly as the receiver's order of operations requires.
6. **The accidental bytes are modeled byte-exactly.** A plain
   continuation frame in a compressed context reads as compressed data,
   and its concrete bytes pin exact receiver behavior: the two-byte
   `0x41 0x42` strands the segment scan (poison); the single byte
   `0x41` decodes to the empty payload only when the message ends
   exactly on it (the pending-41 states) and poisons the message if any
   byte follows. The pending-41 / poisoned branching is derived from
   the decompression oracle (W6): `emu_decompress` must match the
   implementation's `decompress()` on every wire the machine can
   accumulate (`model/gen/deflate_oracle.json`), so the model cannot
   drift from the receiver's actual decompression.

## Scope and follow-ups

- **The wire-size axis inside compressed fragments**: tracked, not
  abstracted away — the compressed fragment states are the (wire,
  decompressed) pairs the alphabet can accumulate under the limit, and
  the table itself fires the wire cross-frame fault (1002) on overflow.
  The 14-pair set is closed under the non-fault transitions (checked by
  completeness); the plain domains pin the policy for single frames.
- **The DEFLATE stream's internal structure** (bit buffers, block
  headers, the LZ77 window): this machine's compressed frames declare
  their decompressed chunk symbolically, and the wire bytes use the
  RFC 7692 7.2.1/7.2.3.5 per-fragment *complete-stream* fragmentation
  ("for non-final fragments, the removal of 0x00 0x00 0xff 0xff MUST NOT
  be done") — which is what makes the per-frame chunks compose exactly.
  Splitting a stream *mid-block* across frames is the DEFLATE stream
  machine's concern (a follow-up with the same trace vocabulary):
  mid-stream prefixes are unbounded bit-level state, and modeling them
  requires the RFC 1951 machine itself.
- **The LZ77 sliding-window / context-takeover axis (7.1.1)**: the
  window content is unbounded state; the traces run in per-message (no
  context takeover) mode, which the implementation negotiates.
- **The completion tail**: the RFC 7692 7.2.2 prescribes appending four
  octets (00 00 ff ff); real peers additionally end the stream with an
  empty final block, and the implementation (a documented interop
  deviation, see the `ws` package doc) appends nine octets. The trace
  bytes must replay against the implementation, so the machine's fate
  classes are defined against its tail — the failure/success *fate* is
  the RFC-level abstraction; the tail is an encoding detail.

## Running it

```
make deflate-model   # pure Python: W1-W6 + P1/P2/P6/P7/P8/RX/completeness/
                     #   encoding + trace<->model consistency
make test            # replays the committed traces (in the normal suite)
make defl-report     # print the RSV1 MBT warning count (the assessable summary)
make defl-gen        # regenerate the traces (needs the podman container);
                     #                     fails if the committed traces would change
make model-image     # build the nuXmv container (only when Containerfile changes)
```

`deflate-model`, `defl-report`, and the replay run in the gate without any
container; only regeneration (`defl-gen`) needs podman. The replay also
enforces the `NOTES.json` allowlist (fail on an unaccepted warning or a
stale entry), so `make defl-report` is the quick way to *see* the count
the gate is enforcing. Regeneration is deterministic: the same model
yields byte-identical traces, which is what the `defl-gen` idempotency
check enforces.
