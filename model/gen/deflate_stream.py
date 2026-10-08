"""The permessage-deflate data reference (RFC 1951 + RFC 7692 7.2.1).

This is the spec-derived authority for what a compressed WebSocket message
payload may be, built from the RFC texts only (doc/rfc1951.txt,
doc/rfc7692.txt) -- not from the implementation. Three layers, in
increasing authority:

  flate_decode(buf)
      One DEFLATE stream, read bit by bit. RFC 1951 3.1.1 packing: data
      elements are packed from the least-significant bit of each byte;
      Huffman codes are read from the most-significant bit of the code.
      Status is OK exactly when a BFINAL block completes (bytes after it
      are ignored -- the stream simply ends at the final block), EOF when
      the input ends before the final block completes, CORRUPT on a fault
      outside the RFC's defined ranges (reserved BTYPE, LEN/NLEN
      mismatch, a code absent from the block's tables, distance codes
      30/31, length codes 286/287, a distance past the start of the
      output, an overfull table, a repeat code without a previous
      length).

  impl_decompress(buf, max_msg)
      The observable semantics of the implementation's decompress loop
      (ws/ws.go): locate every final-block boundary in the payload,
      decode each complete stream (trailing octets are ignored by the
      decoder), decode the last partial segment with the RFC 7692 7.2.1
      completion tail appended, and bound the total output by
      maxMessageSize. TestDecompressStreamTable asserts the
      implementation actually does this on every row of the exhaustive
      table.

  spec7692(buf)
      The classification the RFCs themselves mandate. RFC 7692 7.2.1's
      compression algorithm: compress the payload; if the result does not
      end with an empty stored block (BTYPE=00), append one; remove the
      tail's 4 octets (the block's LEN/NLEN). The result -- a compliant
      compressed message -- is

          [stream] [tail]

      where [stream] is a complete RFC 1951 stream (at least one block;
      the final block BFINAL=1; and, per the 7.2.1 MUST, the final block
      ends at a byte boundary via minimal zero padding) and [tail] is the
      truncated empty stored header: the "1" BFINAL bit in position q
      (0 <= q <= 5, so the three header bits fit in the last octet), the
      two zero BTYPE bits, and zero bits to the end of the octet --
      exactly one byte, 1<<q. Nothing else.
        complete   buf has exactly that shape.
        prefix     buf is a true prefix of some complete buffer
                   (repairable by adding bytes).
        malformed  no continuation can make buf complete.

The RFCs are silent on what a receiver must do with a prefix or a
malformed buffer (RFC 7692 has no decompression-failure clause, as the
RSV1 machine's NOTES.json records); the classification is what the
conformance ledger reasons about, not a wire mandate.

Self-check (check_deflstreamprops.py): the RFC's own worked examples and
tables (3.2.1 code construction, 3.2.6 fixed codes, 3.2.7 dynamic
construction with the 19-order and repeat codes), the 7.2.1 tail in all
six alignments, every malformed class, and exhaustive agreement of
impl_decompress with the implementation's committed oracle.
"""

import json
import os

# --- Outcome vocabulary ------------------------------------------------------

OK = "ok"
EOF = "eof"
CORRUPT = "corrupt"
SIZE = "size"

COMPLETE = "complete"
PREFIX = "prefix"
MALFORMED = "malformed"

# The RFC 7692 7.2.1 completion tail the implementation appends to the last
# partial segment: it completes the truncated empty stored block so the
# decoder can reach its final block. (ws/ws.go deflateTailBytes.)
TAIL9 = bytes([0x00, 0x00, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0xFF, 0xFF])

# Tail bytes of a compliant 7.2.1 message: 1<<q, q in 0..5.
TAIL_BYTES = {1 << q for q in range(6)}

EOFMARK = -1


class Bits(object):
    def __init__(self, data):
        self.data = data
        self.pos = 0  # bit offset

    def read(self, n):
        """n bits as an integer, the first-read bit being bit 0 (LSB
        order, RFC 1951 3.1.1). EOFMARK when the stream is exhausted."""
        if n == 0:
            return 0
        if self.pos + n > len(self.data) * 8:
            return EOFMARK
        v = 0
        for i in range(n):
            byte = self.data[(self.pos + i) >> 3]
            v |= ((byte >> ((self.pos + i) & 7)) & 1) << i
        self.pos += n
        return v

    def read_huff(self, codes):
        """Walk a code tree bit by bit, the code read from its
        most-significant bit (RFC 1951 3.1.1, 3.2.1). codes maps
        (code_value, length) to symbol. Returns (symbol, None) on a match,
        (EOFMARK, None) when the stream exhausts mid-code, or (None, "bad")
        when no code extends the read prefix (an empty tree faults
        immediately on first use)."""
        if not codes:
            return None, "bad"
        max_len = max(l for _, l in codes)
        code = 0
        for length in range(1, max_len + 1):
            bit = self.read(1)
            if bit == EOFMARK:
                return EOFMARK, None
            code = (code << 1) | bit
            sym = codes.get((code, length))
            if sym is not None:
                return sym, None
        return None, "bad"

    def skip_to_byte(self):
        r = self.pos % 8
        if r:
            self.pos += 8 - r

    def read_bytes(self, n):
        """Up to n stored-block data bytes, from the byte boundary after
        the current bit; fewer when the stream is exhausted mid-block
        (the partial bytes are part of the output at the fault flush)."""
        if self.pos % 8:
            self.skip_to_byte()
        avail = len(self.data) - self.pos // 8
        n = min(n, avail)
        out = self.data[self.pos // 8:self.pos // 8 + n]
        self.pos += n * 8
        return out


# --- Canonical Huffman codes (RFC 1951 3.2.1) --------------------------------

def canonical_codes(lengths):
    """The RFC 1951 3.2.1 algorithm: from per-symbol code lengths, the
    (code_value, length) -> symbol map. Returns None when the lengths do
    not form a complete (Kraft-saturated) code, with the single 1-bit
    degenerate code accepted (the zlib-compatibility exception behind
    3.2.7's one-distance-code rule). An all-zero (empty) table is
    returned as the empty dict: legal only for the distance alphabet,
    where first use faults."""
    count = {}
    for l in lengths:
        if l > 0:
            count[l] = count.get(l, 0) + 1
    if not count:
        return {}
    max_len = max(count)
    min_len = min(count)
    code = 0
    next_code = {}
    for bits in range(min_len, max_len + 1):
        code = (code + count.get(bits - 1, 0)) << 1
        next_code[bits] = code
    total = 0
    for bits in range(1, max_len + 1):
        total = (total + count.get(bits - 1, 0)) << 1
    total += count.get(max_len, 0)
    if total != (1 << max_len) and not (total == 1 and max_len == 1):
        return None
    codes = {}
    for sym, l in enumerate(lengths):
        if l == 0:
            continue
        codes[(next_code[l], l)] = sym
        next_code[l] += 1
    return codes


def fixed_lit_lengths():
    """RFC 1951 3.2.6: 0-143 -> 8 bits, 144-255 -> 9, 256-279 -> 7,
    280-287 -> 8."""
    return [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8


def fixed_dist_lengths():
    """RFC 1951 3.2.6: distance codes 0-31, 5 bits each."""
    return [5] * 32


# --- Length and distance tables (RFC 1951 3.2.5) ------------------------------

# code -> (base, extra_bits)
LENGTHS = {}
for code, first, bits in [
    (257, 3, 0), (258, 4, 0), (259, 5, 0), (260, 6, 0), (261, 7, 0),
    (262, 8, 0), (263, 9, 0), (264, 10, 0), (265, 11, 1), (266, 13, 1),
    (267, 15, 1), (268, 17, 1), (269, 19, 2), (270, 23, 2), (271, 27, 2),
    (272, 31, 2), (273, 35, 3), (274, 43, 3), (275, 51, 3), (276, 59, 3),
    (277, 67, 4), (278, 83, 4), (279, 99, 4), (280, 115, 4), (281, 131, 5),
    (282, 163, 5), (283, 195, 5), (284, 227, 5), (285, 258, 0),
]:
    LENGTHS[code] = (first, bits)

# code -> (base, extra_bits)
DISTANCES = {}
for code, first, bits in [
    (0, 1, 0), (1, 2, 0), (2, 3, 0), (3, 4, 0), (4, 5, 1), (5, 7, 1),
    (6, 9, 2), (7, 13, 2), (8, 17, 3), (9, 25, 3), (10, 33, 4),
    (11, 49, 4), (12, 65, 5), (13, 97, 5), (14, 129, 6), (15, 193, 6),
    (16, 257, 7), (17, 385, 7), (18, 513, 8), (19, 769, 8), (20, 1025, 9),
    (21, 1537, 9), (22, 2049, 10), (23, 3073, 10), (24, 4097, 11),
    (25, 6145, 11), (26, 8193, 12), (27, 12289, 12), (28, 16385, 13),
    (29, 24577, 13),
]:
    DISTANCES[code] = (first, bits)

CODE_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


def read_dynamic_tables(bits):
    """RFC 1951 3.2.7: the (literal/length, distance) code trees of a
    dynamic block. Returns ((lit_codes, dist_codes), None) or
    (None, fault): fault is EOF or a fault name."""
    hlit = bits.read(5)
    if hlit == EOFMARK:
        return None, EOF
    hlit += 257
    if hlit > 286:
        return None, "hlit-range"
    hdist = bits.read(5)
    if hdist == EOFMARK:
        return None, EOF
    hdist += 1
    if hdist > 32:
        return None, "hdist-range"
    hclen = bits.read(4) + 4
    clens = [0] * 19
    for i in range(hclen):
        v = bits.read(3)
        if v == EOFMARK:
            return None, EOF
        clens[CODE_ORDER[i]] = v
    codes = canonical_codes(clens)
    if codes is None:
        return None, "clen-overfull"
    n = hlit + hdist
    lengths = [0] * n
    i = 0
    while i < n:
        sym, err = bits.read_huff(codes)
        if err == "bad":
            return None, "clen-badcode"
        if sym == EOFMARK:
            return None, EOF
        if sym < 16:
            lengths[i] = sym
            i += 1
            continue
        if sym == 16:
            if i == 0:
                return None, "repeat-no-prev"
            extra = bits.read(2)
            if extra == EOFMARK:
                return None, EOF
            rep, val = 3 + extra, lengths[i - 1]
        elif sym == 17:
            extra = bits.read(3)
            if extra == EOFMARK:
                return None, EOF
            rep, val = 3 + extra, 0
        else:  # 18
            extra = bits.read(7)
            if extra == EOFMARK:
                return None, EOF
            rep, val = 11 + extra, 0
        if i + rep > n:
            return None, "repeat-overrun"
        for j in range(rep):
            lengths[i + j] = val
        i += rep
    lit = canonical_codes(lengths[:hlit])
    if lit is None:
        return None, "lit-overfull"
    dist = canonical_codes(lengths[hlit:])
    if dist is None:
        return None, "dist-overfull"
    return (lit, dist), None


def _decode_sym_tables(bits, btype, lit, dist, outbuf):
    """One block's symbol data. lit/dist: the fixed tables for btype 1,
    the dynamic tables for btype 2 (dist may be the empty dict, which
    faults on first use for btype 2). Appends to outbuf. Returns
    (outbuf, status, fault) -- status None on block completion."""
    while True:
        sym, err = bits.read_huff(lit)
        if err == "bad":
            return outbuf, CORRUPT, "lit-badcode"
        if sym == EOFMARK:
            return outbuf, EOF, "eof"
        if sym < 256:
            outbuf.append(sym)
            continue
        if sym == 256:
            return outbuf, None, None
        if sym not in LENGTHS:  # 286, 287: reserved
            return outbuf, CORRUPT, "length-reserved"
        base, extra = LENGTHS[sym]
        if extra:
            v = bits.read(extra)
            if v == EOFMARK:
                return outbuf, EOF, "eof"
            length = base + v
        else:
            length = base
        if btype == 1:
            d5 = bits.read(5)
            if d5 == EOFMARK:
                return outbuf, EOF, "eof"
            dcode = int(format(d5, "05b")[::-1], 2)
            if dcode not in DISTANCES:  # 30, 31: never occur
                return outbuf, CORRUPT, "dist-reserved"
            base, extra = DISTANCES[dcode]
        else:
            if not dist:
                return outbuf, CORRUPT, "dist-empty"
            dsym, derr = bits.read_huff(dist)
            if derr == "bad":
                return outbuf, CORRUPT, "dist-badcode"
            if dsym == EOFMARK:
                return outbuf, EOF, "eof"
            if dsym not in DISTANCES:  # 30, 31: never occur
                return outbuf, CORRUPT, "dist-reserved"
            base, extra = DISTANCES[dsym]
        if extra:
            v = bits.read(extra)
            if v == EOFMARK:
                return outbuf, EOF, "eof"
            distval = base + v
        else:
            distval = base
        if distval > len(outbuf):
            return outbuf, CORRUPT, "dist-too-far"
        # LZ77 copy: `length` bytes from position len-distval, overlapping
        # copies repeat (RFC 1951 3.2.3).
        tail = outbuf[-distval:]
        reps = (length + distval - 1) // distval
        outbuf += (tail * reps)[:length]


def flate_decode(buf):
    """The observable semantics of the reference DEFLATE decoder.
    Returns (status, out, fault): out is the payload decoded so far
    (complete on OK, partial on EOF/CORRUPT -- the decoder flushes what
    it has at the fault, and the size guard below sees it), fault the
    fault name on EOF/CORRUPT, None on OK."""
    bits = Bits(buf)
    out = bytearray()
    lit_fixed = canonical_codes(fixed_lit_lengths())
    dist_fixed = canonical_codes(fixed_dist_lengths())
    while True:
        hdr = bits.read(3)
        if hdr == EOFMARK:
            return EOF, bytes(out), "eof"
        bfinal = hdr & 1
        btype = (hdr >> 1) & 3
        if btype == 3:
            return CORRUPT, bytes(out), "btype-reserved"
        if btype == 0:
            bits.skip_to_byte()
            length = bits.read(16)
            if length == EOFMARK:
                return EOF, bytes(out), "eof"
            nlen = bits.read(16)
            if nlen == EOFMARK:
                return EOF, bytes(out), "eof"
            if nlen != (~length & 0xFFFF):
                return CORRUPT, bytes(out), "len-nlen-mismatch"
            data = bits.read_bytes(length)
            if len(data) < length:
                out += data
                return EOF, bytes(out), "eof"
            out += data
        else:
            if btype == 1:
                lit, dist, fault = lit_fixed, dist_fixed, None
            else:
                tables, fault = read_dynamic_tables(bits)
                if fault:
                    if fault == EOF:
                        return EOF, bytes(out), "eof"
                    return CORRUPT, bytes(out), fault
                lit, dist = tables
            out, status, fault = _decode_sym_tables(bits, btype, lit, dist,
                                                    out)
            if status is not None:
                return status, bytes(out), fault
        if bfinal:
            return OK, bytes(out), None


# --- impl_decompress: the implementation's observable semantics ----------------

def _first_final_boundary(src):
    """Smallest b in 1..len(src) with a complete stream in src[:b], else
    -1. flate_decode(src[:b]) == OK is monotone in b (a final block, once
    present, stays present), so binary search, mirroring ws/ws.go."""
    if flate_decode(src)[0] != OK:
        return -1
    low, high = 1, len(src)
    while low < high:
        mid = (low + high) >> 1
        if flate_decode(src[:mid])[0] == OK:
            high = mid
        else:
            low = mid + 1
    return low


def impl_decompress(buf, max_msg):
    """The decompress loop of ws/ws.go: every final-block boundary yields
    one decoded stream (trailing octets ignored by the decoder); the last
    partial segment is decoded with the 7.2.1 completion tail appended;
    the total output is bounded by max_msg. The bound is observed at the
    decoder's flush: what the decoder has produced when it stops
    (completion or fault) is written to the size guard, so an output
    overflow outranks any fault the stream would have hit later. Returns
    (status, value): value is the payload on OK, the fault name
    otherwise (SIZE on the size guard)."""
    out = bytearray()
    start = 0
    while start < len(buf):
        b = _first_final_boundary(buf[start:])
        if b < 0:
            status, seg, fault = flate_decode(buf[start:] + TAIL9)
            end = len(buf)
        else:
            status, seg, fault = flate_decode(buf[start:start + b] + TAIL9)
            end = start + b
        out += seg
        if len(out) > max_msg:
            return SIZE, "size"
        if status != OK:
            return status, fault
        if b < 0:
            break
        start = end
    return OK, bytes(out)


# --- spec7692: the RFC-mandated classification ---------------------------------

# Stream-scan end states.
ALIGNED = "aligned"      # final block complete, ends on a byte boundary
MIDBYTE = "midbyte"      # final block complete, ends mid-byte (bit pos)
INCOMPLETE = "incomplete"  # the stream itself is truncated
FAULT = "fault"         # unrepairable


def _walk_stream(buf):
    """Walk the RFC 1951 blocks of buf. Returns (end, out, extra, fault):
    end in {ALIGNED, MIDBYTE, INCOMPLETE, FAULT}; out the decompressed
    bytes so far; extra the end bit position for MIDBYTE."""
    bits = Bits(buf)
    out = bytearray()
    lit_fixed = canonical_codes(fixed_lit_lengths())
    dist_fixed = canonical_codes(fixed_dist_lengths())
    while True:
        hdr = bits.read(3)
        if hdr == EOFMARK:
            return INCOMPLETE, out, None, "eof"
        bfinal = hdr & 1
        btype = (hdr >> 1) & 3
        if btype == 3:
            return FAULT, out, None, "btype-reserved"
        if btype == 0:
            bits.skip_to_byte()
            length = bits.read(16)
            if length == EOFMARK:
                return INCOMPLETE, out, None, "eof"
            nlen = bits.read(16)
            if nlen == EOFMARK:
                return INCOMPLETE, out, None, "eof"
            if nlen != (~length & 0xFFFF):
                return FAULT, out, None, "len-nlen-mismatch"
            data = bits.read_bytes(length)
            if len(data) < length:
                out += data
                return INCOMPLETE, out, None, "eof"
            out += data
        else:
            if btype == 1:
                lit, dist, fault = lit_fixed, dist_fixed, None
            else:
                tables, fault = read_dynamic_tables(bits)
                if fault:
                    if fault == EOF:
                        return INCOMPLETE, out, None, "eof"
                    return FAULT, out, None, fault
                lit, dist = tables
            out, status, fault = _decode_sym_tables(bits, btype, lit, dist,
                                                    out)
            if status is not None:
                if status == EOF:
                    return INCOMPLETE, out, None, "eof"
                return FAULT, out, None, fault
        if bfinal:
            if bits.pos % 8 == 0:
                return ALIGNED, out, bits.pos // 8, None
            return MIDBYTE, out, bits.pos, None


def spec7692(buf):
    """Classify a compressed-message payload against RFC 7692 7.2.1.
    Returns (class, out, fault): class in {COMPLETE, PREFIX, MALFORMED},
    out the decompressed payload for COMPLETE, fault the reason otherwise.
    A compliant buffer is [stream][tail]: a byte-aligned (7.2.1 MUST
    padding) complete stream plus exactly one tail byte 1<<q, q in 0..5
    (the truncated empty stored header)."""
    if not buf:
        return PREFIX, None, "empty"
    end, out, bitpos, fault = _walk_stream(buf)
    if end == FAULT:
        return MALFORMED, None, fault
    if end == INCOMPLETE:
        return PREFIX, None, "stream-incomplete"
    if end == MIDBYTE:
        # The 7.2.1 padding is the zero bits from bitpos to the next byte
        # boundary: a compliant buffer has them. Nonzero bits there are
        # not padding -- no compliant buffer can extend this one.
        byte = buf[bitpos // 8]
        pad = byte >> (bitpos % 8)
        if pad:
            return MALFORMED, None, "padding-nonzero"
        rest = buf[bitpos // 8 + 1:]
        if not rest:
            return PREFIX, None, "tail-missing"
        if len(rest) == 1 and rest[0] in TAIL_BYTES:
            return COMPLETE, bytes(out), None
        return MALFORMED, None, "tail-shape"
    # ALIGNED: the stream occupies buf[:bitpos], then the tail.
    rest = buf[bitpos:]
    if not rest:
        return PREFIX, None, "tail-missing"
    if len(rest) == 1 and rest[0] in TAIL_BYTES:
        return COMPLETE, bytes(out), None
    return MALFORMED, None, "tail-shape"


def gen_table(path, max_len, max_msg=6):
    """Write the exhaustive table for all buffers of length 1..max_len:
    each row is [buffer hex, impl status, impl value hex or fault, spec
    class, spec out hex or fault]."""
    rows = []
    for n in range(1, max_len + 1):
        for v in range(1 << (n * 8)):
            buf = v.to_bytes(n, "little")
            status, value = impl_decompress(buf, max_msg)
            impl = status
            implval = value.hex() if status == OK else value
            sclass, sout, sfault = spec7692(buf)
            rows.append([buf.hex(), impl, implval, sclass,
                         sout.hex() if sout is not None else sfault])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"maxLen": max_len, "maxMsg": max_msg, "rows": rows}, f)
    return len(rows)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "gen":
        n = gen_table(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 2,
                      int(sys.argv[4]) if len(sys.argv) > 4 else 6)
        print("deflate stream table: %d rows" % n)
