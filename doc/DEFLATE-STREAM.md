# The DEFLATE stream machine (machine B, part 1)

This is the foundation of the DEFLATE stream machine: the spec-derived
reference for what a permessage-deflate compressed message payload *is*,
built from the RFC texts alone (doc/rfc1951.txt, doc/rfc7692.txt) and
validated against the implementation's observable behavior. The
symbolic state machine (mid-block stream splitting across frames,
nuXmv cross-check, trace replay) builds on it as the follow-up.

## The compliant shape (RFC 7692 §7.2.1)

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
- **[tail]**: the truncated empty stored header — the "1" BFINAL bit in
  position q (0 ≤ q ≤ 5, so the three header bits fit in the last
  octet), the two zero BTYPE bits, zero bits to the end of the octet.
  Exactly one byte: `1<<q`.

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

## The reference classifier (model/gen/deflate_stream.py)

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

## Self-check (model/gen/check_deflstreamprops.py)

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
- **G.** the §7.2.1 compliant shape: all six tail alignments, the MUST
  zero padding, the prefix/malformed boundaries.
- **H.** exhaustive agreement with the implementation's committed
  decompression oracle (model/gen/deflate_oracle.json, 1,531 wires):
  `impl_decompress` must match the implementation's ok/fail and
  payload on every row.

## The exhaustive table and the Go replay

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
  the MBT runners). The current ledger is exactly three accepted
  entries:
  - `MAY:deflate-accept:stream-incomplete` (5,312) — a truncated
    stream the completion tail happens to complete;
  - `MAY:deflate-accept:padding-nonzero` (63) — nonzero bits after the
    final block (the padding MUST binds the compressor, not the
    receiver);
  - `MAY:deflate-accept:tail-missing` (1) — a complete byte-aligned
    stream without the §7.2.1 tail byte.

No COMPLETE buffers exist below 6 bytes (a compliant buffer is a
stream of at least one block plus the tail byte), so the table's spec
layer exercises the prefix/malformed boundary; the oracle cross-check
(H) covers the compliant shape at the RSV1 machine's wire sizes.

## Running it

```
make deflstream      # the container-free self-check (in the gate)
make test            # includes TestDecompressStreamTable (65,792 rows)
make deflstream-gen  # regenerate the table; must be deterministic
make gate            # the whole gate
```

## Scope and follow-ups

- The classifier is a **byte-level** authority: it decides whole
  buffers. The symbolic machine (states = decoder configurations,
  frame classes = byte chunks, transitions via the classifier) is the
  next step: it models mid-block stream splitting across frames — the
  RSV1 machine's current empirical oracle (the pending-41 and poison
  states) becomes *derived* from this reference instead of probed.
- The implementation's permissiveness (the three accepted ledger
  entries) is pinned by the table; tightening it toward the strict
  RFC 7692 shape would shrink the ledger, as the SHOULD/MAY
  convergence does in the MBT runners.
- Longer buffers (3–6 bytes) are covered by the committed decompression
  oracle (H); extending the exhaustive table to 3 bytes (16.7M rows)
  is deliberately not done — the 1–2 byte table already exhausts every
  state the first frame of a compressed message can reach.
