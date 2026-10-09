# The DEFLATE stream machine (machine B)

## Part 1: the reference classifier

This is the foundation of the DEFLATE stream machine: the spec-derived
reference for what a permessage-deflate compressed message payload *is*,
built from the RFC texts alone (doc/rfc1951.txt, doc/rfc7692.txt) and
validated against the implementation's observable behavior. The
symbolic state machine (mid-block stream splitting across frames,
nuXmv cross-check, trace replay) builds on it as the follow-up.

## Part 1: the compliant shape (RFC 7692 §7.2.1)

RFC 7692's compression algorithm is:

1. Compress all payload octets with DEFLATE.
2. If the result does not end with an empty stored block (BTYPE=00),
   append one.
3. Remove the tail's 4 octets (the block's LEN/NLEN).

So a compliant compressed message is

    [stream] [tail]

- **[stream]**: a complete RFC 1951 stream — at least one block, the
  final block BFINAL=1, and (per the §7.2.1 MUST) the final block ends
  at a byte boundary via minimal zero padding.
- **[tail]**: the first octet of the truncated empty stored header,
  which starts at that byte boundary: its BFINAL bit (the RFC leaves
  the appended block's BFINAL unspecified, so 0 or 1), the two zero
  BTYPE bits, and zero LEN bits. Exactly one byte: `0x00` or `0x01`
  -- nothing else. (The octet is the header's *first* octet, not a
  mid-octet fragment: the §7.2.1 MUST padding forces the header to
  start on the boundary, so its BFINAL bit is always bit 0 of the
  tail octet.)

Nothing else. The classifier `spec7692` (model/gen/deflate_stream.py)
assigns every buffer one of:

| class     | meaning                                                       |
|-----------|---------------------------------------------------------------|
| complete  | the buffer has exactly that shape                             |
| prefix    | a true prefix of some complete buffer (repairable)            |
| malformed | no continuation can make it complete                          |

The RFCs are silent on what a receiver must do with a prefix or a
malformed buffer (RFC 7692 has no decompression-failure clause, the
same silence the RSV1 machine's NOTES.json records); the
classification is what the conformance ledger reasons about, not a
wire mandate.

## Part 1: the reference classifier (model/gen/deflate_stream.py)

Three layers, in increasing authority:

- **`flate_decode(buf)`** — one DEFLATE stream, read bit by bit.
  RFC 1951 §3.1.1 packing: data elements are packed from the
  least-significant bit of each byte; Huffman codes are read from the
  most-significant bit of the code (fixed 5-bit distance codes are
  therefore bit-reversed on read). Canonical codes per §3.2.1 (the
  bl_count/next_code algorithm); the fixed tables per §3.2.6; length
  and distance ranges per §3.2.5; dynamic table construction per
  §3.2.7 (the 19-order code-length alphabet, repeat codes 16/17/18,
  the one-distance-code and no-distance-code rules, Kraft
  completeness with the zlib single-1-bit-code exception). Status:
  `ok` when a BFINAL block completes (bytes after it are ignored —
  the stream simply ends at the final block), `eof` when the input
  ends first, `corrupt` on a fault outside the defined ranges
  (reserved BTYPE, LEN/NLEN mismatch, a code absent from the block's
  tables, distance codes 30/31, length codes 286/287, a distance past
  the start of the output, an overfull table, a repeat code without a
  previous length). The payload decoded so far is returned on every
  path: the decoder flushes what it has at the fault, and the size
  guard below sees it.
- **`impl_decompress(buf, max_msg)`** — the observable semantics of
  the implementation's decompress loop (ws/ws.go): locate every
  final-block boundary, decode each complete stream (trailing octets
  ignored), decode the last partial segment with the §7.2.1
  completion tail appended, and bound the total output by
  maxMessageSize. The bound is observed at the decoder's flush, so an
  output overflow outranks any fault the stream would have hit later
  (the size guard sees the flushed bytes before the error).
- **`spec7692(buf)`** — the RFC-mandated classification above.

## Part 1: self-check (model/gen/check_deflstreamprops.py)

Container-free; `make deflstream`. Every check derives from the RFC
texts or the implementation's committed oracle:

- **A.** the §3.2.1 worked example: lengths (3,3,3,3,3,2,4,4) yield
  exactly the RFC's code table and next_code values; underfull and
  single-1-bit-code tables.
- **B.** the §3.2.6 fixed tables: the constructed codes match the code
  values the RFC prints (0–143 → 8 bits … 280–287 → 8 bits, distances
  5 bits).
- **C.** stored blocks (§3.2.4): final/non-final, the LEN/NLEN
  complement rule, LEN/NLEN byte alignment after a mid-byte header.
- **D.** fixed blocks (§3.2.5/3.2.6): literal, end-of-block, the
  bit-reversed fixed distance code, a length+distance pair (LZ77
  overlap), mid-byte block end, reserved BTYPE.
- **E.** dynamic blocks (§3.2.7): the 19-order alphabet, repeat
  codes, the one-distance-code rule (a single 1-bit distance code),
  the no-distance-code rule (empty tree, all-literal data), HLIT
  range, a repeat without a previous length.
- **F.** one vector per malformed class.
- **G.** the §7.2.1 compliant shape: the truncated stored header's
  first octet (0x00 or 0x01), the non-compliant tail octets, the MUST
  zero padding, the prefix/malformed boundaries.
- **H.** exhaustive agreement with the implementation's committed
  decompression oracle (model/gen/deflate_oracle.json, 1,531 wires):
  `impl_decompress` must match the implementation's ok/fail and
  payload on every row.

## Part 1: the exhaustive table and the Go replay

`ws/testdata/deflstream/oracle.json` (65,792 rows, `make
deflstream-gen`): every 1- and 2-byte buffer, each row
`[hex, impl status, impl value, spec class, spec value]`.

`TestDecompressStreamTable` (ws/deflstream_test.go) replays the whole
table against the live decompress pipeline, asserting two layers:

- **hard**: the implementation behaves exactly as the table's
  implementation layer claims (status and payload) — a mismatch is a
  model bug or an implementation bug; and every spec-classified
  COMPLETE buffer is accepted with the RFC payload.
- **ledger**: a PREFIX/MALFORMED buffer that is nevertheless accepted
  is a MAY leniency, counted per spec fault and checked against
  `ws/testdata/deflstream/NOTES.json` (the same allowlist mechanism as
  the MBT runners). The current ledger is exactly six accepted
  entries:
  - `MAY:deflate-accept:stream-incomplete` (5,126) — a truncated
    stream the completion tail happens to complete;
  - `MAY:deflate-accept:padding-nonzero` (51) — nonzero bits between
    the final block and the truncated stored header (the padding MUST
    binds the compressor, not the receiver);
  - `MAY:deflate-accept:tail-missing` (1) — a complete byte-aligned
    stream without the §7.2.1 tail octet;
  - `MAY:deflate-accept:lit-badcode` (86),
    `MAY:deflate-accept:dist-too-far` (64),
    `MAY:deflate-accept:dist-reserved` (48) — fixed-block wires the
    RFC's literal table (7-bit codes 32-55) does not define but the
    implementation's canonical table decodes (the documented 3.2.6
    deviation, above).

No COMPLETE buffer exists in the table's 1-2 byte domain (the
minimal compliant buffer is three bytes: the empty fixed final
block, which reaches the byte boundary at bit 10 with zero padding,
plus the tail octet), so the table's spec layer exercises the
prefix/malformed boundary; the oracle cross-check (H) covers the
compliant shape at the RSV1 machine's wire sizes.

## Part 2: the streaming state machine (model/gen/deflate_state.py)

Part 1 decides whole buffers; a compressed message arrives as a
stream of frame payloads, and the receiver decompresses the whole
accumulated wire only on the final frame (the read loop returns a
fragment untouched). The question at the byte level is therefore: *as
bytes arrive, what is the decoder's configuration, and what would the
final-frame decompression do?* The state machine answers it.

**Principle** (the same as machines A and the reassembly machine):
RFC-derived, implementation-independent where the RFC is precise, and
honest about under-specification where it is not. The machine is
byte-granular and content-agnostic: states are decoder
configurations, transitions are single bytes, and the output is
tracked only as a capped length (the size guard is the only
output-sensitive behavior the receiver has).

### The phases

Thirteen phases, named by the decoder position:

  HDR    the 3-bit block header (BFINAL, BTYPE) of the first block.
  SLN    the stored block's LEN field (16 bits).
  SNL    the stored block's NLEN field (16 bits; !LEN).
  SDT    the stored block's LEN data bytes (byte-aligned, RFC 1951
         3.2.4: the header's leftover bits are discarded and the
         data is whole bytes).
  HSYM   symbol data of a fixed- or dynamic-Huffman block: the
         pending code bits, the exact code set, and the per-table
         contexts (for a dynamic block: its code-length table and
         fill progress).
  DCH5   the dynamic header: HLIT/HDIST (5+5 bits).
  DCH4   HCLEN (4 bits).
  DCL    the code-length code table (19 symbols, repeat codes
         16-18; RFC 1951 3.2.7).
  DCT    the code-length data (per-symbol lengths with repeats).
  REP    a repeat code's pending count/distance value.
  DONE   a BFINAL block just closed: the next byte starts the next
         stream (the wire may carry several complete streams; the
         decoder concatenates their output).
  LATCH  a protocol fault: absorbing (the stream is dead).

The HSYM state carries the exact code set as a frozenset of
(value, bits, symbol) triples plus the pending (bits, value);
the derived prefix set, symbol lookup, and table max code length
are cached per exact set. The pending-code discipline matches the
reference decoder's observable timing: a dead prefix is not
declared dead until the table's maximum code length has been read
(a bad code is a fault only when no code can still extend the
pending prefix).

**Content-agnostic**: the machine tracks output as a capped count,
not as bytes. What a symbol *is* matters only through its effect on
the count (literal +1, length+distance +the length) and through the
distance constraint (distance > decoded-so-far is a fault, RFC 1951
3.2.5); the byte values themselves are not part of the state.
This is deliberate: the machine validates the *configuration
transitions*, and the payload content is what the reference
classifier and the Go replay assert.

### Self-check (model/gen/check_deflstateprops.py, in the gate)

Container-free; cross-checks the machine against the part-1
reference on every prefix of every buffer in the committed
exhaustive table (65,792 one- and two-byte buffers) and every
committed decompression-oracle wire (1,531 wires):

  Q1  outcome agreement at every prefix: machine overflow (capped
      output past the limit) <-> implementation size guard;
      machine DONE <-> implementation ok; machine LATCH <->
      implementation corrupt; machine active (pending) <->
      implementation eof (the completion tail did not finish the
      stream). The machine folds the implementation's completion
      tail on the final segment, as the read loop does on the
      final frame.
  Q2  output agreement: on ok, the machine's output length equals
      the implementation's.
  Q3  absorption: LATCH absorbs; DONE starts a new stream on the
      next byte; latching is one-way.
  Q4  prefix-set soundness: every derived exact code set is a valid
      canonical table, its prefix set is closed under extension,
      and no exact code has an extension.

### Coarse reachability cross-check (Q5, make deflstate-model)

The full machine's state space is too large for the nuXmv BDD
engine (the pending-bit configurations explode the frontier), so
the cross-check runs on a coarse model: 6 phases (hdr, stored,
huff, dyn, done, latch) x capped output length (0-7), with the
machine's observed transitions sound against the SMV edges and the
reachability of every (phase, output) pair cross-checked by a
per-pair nuXmv query (G !(phase = p & olen = o) "is false" iff
reachable). One witness byte sequence per pair is verified against
the machine (31 witnesses); the witness bytes are chosen against
the implementation's canonical fixed table, where the 5-bit
pending after a block header constrains which codes the next byte
can extend (an 8-bit literal from a 0b00000 pending is
impossible; the witnesses build the pending deliberately).

### Frame traces and the Go replay (make deflstate, TestMBTDeflState)

The committed traces (ws/testdata/deflstate/, 182 files, generated
by model/gen/gen_deflstatetraces.py) replay against a live RawConn
with permessage-deflate negotiated, on both sides. A trace is a
compressed-frame sequence (the shared wire encoder of the
reassembly machine); the expectations live at the final frame, the
only frame that decompresses:

  * wire-side limit first: the accumulated wire is bounded by
    maxMessageSize before any decompression (RFC 6455 5.5 via
    project policy) -- a compressed message whose wire already
    exceeds the limit fails with the coded 1002 (the MAY bare
    teardown stays modeled; it does not fire).
  * decompression outcomes from the reference: SIZE (the
    decompressed 1009, reachable only under the wire limit
    through repetition codes -- the bomb trace, four wire bytes
    decoding to nine), CORRUPT / EOF (the coded 1002, MAY bare
    teardown: MAY:decompress-close-omitted), OK (the delivered
    payload, asserted byte-for-byte).
  * the ledger: a delivered message from a wire the RFC 7692
    7.2.1 class does not name COMPLETE (truncated, a tail octet
    that is not 0x00/0x01, nonzero padding, a code the RFC's
    literal fixed table does not define) fires
    MAY:deflate-accept:<shape> -- the lenient completion is
    counted, not excused. NOTES.json accepts the seven distinct
    IDs that fire.
  * the fixed-table deviation at payload level: a wire the spec
    class names COMPLETE can still be delivered with a payload the
    spec does not decode -- the done-1 / text-utf8 witness wire
    13 00 00 is the RFC-literal empty stream plus the compliant
    tail (spec payload: empty), while the canonical table reads
    it as a literal and delivers 0x10. That is the 3.2.6
    deviation, not a ledger entry (the ledger counts MAY
    leniencies, and this is the documented table difference);
    the traces pin the implementation's payload through the
    events.

Trace families: every witness state (31 coarse (phase, output)
classes) as a single final frame, split across a non-final and a
final frame (RFC 7692 6.2: the stream need not be whole in any
one fragment), and -- on delivery traces -- with an interleaved
ping; plus the two-stream-in-one-message wire (DONE starting the
next stream: two canonical empty final blocks, 03 00 03 00, whose
RFC-literal reading is a bad code -- lit-badcode on delivery), the
wrong-tail-octet wire that still delivers (13 00 04: the RFC-
literal empty final block plus a tail octet the shape does not
name -- tail-shape), the bomb, and the text-frame UTF-8 validity
pair (RFC 6455 5.6: the decoded payload of a text message is
checked, terminal 1007 when invalid).

The machine's mid-stream state (pending codes, table bytes) is not
observable at the frame level -- no per-frame decompression -- so
the traces pin the frame-level contract (delivery, terminal codes,
the ledger) while the Q1-Q5 checks pin the byte-level machine.

## Running it

```
make deflstream       # part 1 self-check (in the gate)
make test             # TestDecompressStreamTable (65,792 rows) and
                      # TestMBTDeflState (182 traces)
make deflstate        # part 2 self-check Q1-Q4 (in the gate)
make deflstate-model  # the coarse nuXmv cross-check (in the gate)
make deflstream-gen   # regenerate the table; must be deterministic
make deflstate-gen    # regenerate the traces; must be deterministic
make gate             # the whole gate
```

## Scope and follow-ups

- The machine is content-agnostic on purpose: the payload bytes a
  symbol decodes to are asserted by the reference classifier and
  the Go replay, not tracked in the state. A content-carrying
  encoding would multiply the state space by the alphabet with no
  new protocol coverage.
- The dynamic-block table fill (DCT/REP) is modeled at full
  fidelity (per-symbol lengths, repeats, overfull-table faults)
  but its reachable states are only exercised through the oracle
  wires and the cross-check's dyn class; dedicated dynamic-block
  trace families (a dynamic block completing a compressed
  message) are the natural extension of the witness set.
- Longer buffers (3-6 bytes) are covered by the committed
  decompression oracle; extending the exhaustive table to
  3 bytes (16.7M rows) is deliberately not done -- the 1-2 byte
  table already exhausts every state the first frame of a
  compressed message can reach, and Q1 checks every prefix of
  every table buffer.
- The implementation's permissiveness (the accepted ledger
  entries) is pinned by the table and the traces; tightening it
  toward the strict RFC 7692 shape would shrink the ledger, as
  the SHOULD/MAY convergence does in the MBT runners.
