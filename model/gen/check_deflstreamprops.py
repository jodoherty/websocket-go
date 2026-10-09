"""Self-check for the permessage-deflate data reference
(model/gen/deflate_stream.py).

Every check derives from the RFC texts (doc/rfc1951.txt,
doc/rfc7692.txt) or from the implementation's committed oracle:

  A. RFC 1951 3.2.1 worked example: canonical code construction from the
     lengths (3,3,3,3,3,2,4,4) yields exactly the RFC's code table.
  B. RFC 1951 3.2.6 fixed tables: the codes constructed from the RFC's
     length ranges match the code values the RFC prints.
  C. Stored blocks (3.2.4): final/non-final, the LEN/NLEN complement
     rule, LEN/NLEN starting at the byte boundary after the header.
  D. Fixed blocks (3.2.5/3.2.6): literal, end-of-block, the fixed
     5-bit distance code (bit-reversed), a length+distance pair, mid-byte
     block end (trailing bits ignored).
  E. Dynamic blocks (3.2.7): the 19-order code-length alphabet, repeat
     codes 16/17/18, the one-distance-code (1 bit) and no-distance-code
     (empty tree) rules, HLIT range.
  F. Malformed classes: one vector per fault name.
  G. RFC 7692 7.2.1: the compliant shape [stream][0x00|0x01] (the
     truncated stored header's first octet, BFINAL either way), the
     MUST zero padding, the prefix/malformed boundaries.
  H. The implementation's committed decompression oracle
     (model/gen/deflate_oracle.json): impl_decompress agrees with the
     implementation on every row.

Pure Python, no container. Run: python3 model/gen/check_deflstreamprops.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import deflate_stream as D  # noqa: E402

FAILS = []


def check(name, got, want):
    if got != want:
        FAILS.append("%s: got %r, want %r" % (name, got, want))


def fd(name, buf, status, fault, out=b""):
    """One flate_decode expectation: (status, out, fault)."""
    check(name, D.flate_decode(buf), (status, out, fault))


def bits_writer():
    """A bit writer for constructing test vectors (LSB-first packing,
    RFC 1951 3.1.1; Huffman codes written MSB-first)."""
    state = {"bits": []}

    def wbit(b):
        state["bits"].append(b)

    def wbits(v, n):
        for i in range(n):
            wbit((v >> i) & 1)

    def whuff(code, length):
        for i in range(length - 1, -1, -1):
            wbit((code >> i) & 1)

    def finish():
        while len(state["bits"]) % 8:
            wbit(0)
        out = bytearray()
        for i in range(0, len(state["bits"]), 8):
            b = 0
            for j in range(8):
                b |= state["bits"][i + j] << j
            out.append(b)
        return bytes(out)

    return wbit, wbits, whuff, finish


def stored_block(bfinal, data, btype=0):
    wbit, wbits, _whuff, finish = bits_writer()
    wbit(1 if bfinal else 0)
    wbits(btype, 2)
    wbits(0, 5)  # stored blocks byte-align before LEN (RFC 1951 3.2.4)
    wbits(len(data), 16)
    wbits(~len(data) & 0xFFFF, 16)
    for byte in data:
        wbits(byte, 8)
    return finish()


# The code-length alphabet of the dynamic vectors below: the minimal
# complete tree {17: 1 bit, 1: 2 bits, 18: 2 bits}; canonical codes
# 17 -> 0, 1 -> 10, 18 -> 11. 17 code-length codes are declared (HCLEN
# field value 13 = 17 - 4; the 19-order positions 0..16, the last of
# which is symbol 1).
# Canonical codes: 0 -> 00, 1 -> 01, 2 -> 10 (length 2); 17 -> 110,
# 18 -> 111 (length 3). Kraft: 3/4 + 2/8 = 1.
CL_TREE = {0: (0, 2), 1: (1, 2), 2: (2, 2), 17: (6, 3), 18: (7, 3)}
CL_COUNT = 18


def emit_clen(wbits, whuff, sym, extra=None, nbits=None):
    code, length = CL_TREE[sym]
    whuff(code, length)
    if extra is not None:
        wbits(extra, nbits)


def emit_seq(wbits, whuff, seq):
    """Emit a code-length sequence (258 values) with 17/18 zero repeats;
    nonzero values as literal length symbols (symbol = the value)."""
    i = 0
    while i < len(seq):
        if seq[i] != 0:
            emit_clen(wbits, whuff, seq[i])
            i += 1
            continue
        j = i
        while j < len(seq) and seq[j] == 0:
            j += 1
        run = j - i
        taken = 0
        while run > 0:
            if run >= 11:
                take = min(run, 138)
                emit_clen(wbits, whuff, 18, take - 11, 7)
            elif run >= 3:
                take = run
                emit_clen(wbits, whuff, 17, take - 3, 3)
            else:
                take = run
                for _ in range(take):
                    emit_clen(wbits, whuff, 0)
            run -= take
            taken += take
        i += taken


def dyn_block(bfinal, lit_lengths, dist_lengths, data_syms, hlit=0):
    """Build a dynamic block. lit_lengths/dist_lengths map symbol -> code
    length (0/absent = unused); the literal/length sequence has hlit+257
    values (symbols 0..hlit+256); data_syms is a list of ("lit", byte),
    ("eob", None) or ("copy", (length_code, distance_code)). The
    distance alphabet has exactly one entry (distance 0) -- the 3.2.7
    one-distance-code rule when its length is 1, the no-distance-code
    rule when it is 0."""
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1 if bfinal else 0)
    wbits(2, 2)  # BTYPE=10
    wbits(hlit, 5)  # HLIT: hlit+257 literal/length lengths
    wbits(0, 5)  # HDIST: 1 distance length
    wbits(CL_COUNT - 4, 4)
    for pos in range(CL_COUNT):
        wbits({0: 2, 1: 2, 2: 2, 17: 3, 18: 3}.get(D.CODE_ORDER[pos], 0), 3)
    n = hlit + 257
    seq = [lit_lengths.get(s, 0) for s in range(n)] \
        + [dist_lengths.get(0, 0)]
    emit_seq(wbits, whuff, seq)
    lit = D.canonical_codes([lit_lengths.get(s, 0) for s in range(n)])
    dist = D.canonical_codes([dist_lengths.get(0, 0)])
    for kind, value in data_syms:
        if kind in ("lit", "eob"):
            sym = value if kind == "lit" else 256
            code, length = next((c, l) for (c, l), s in lit.items()
                                if s == sym)
            whuff(code, length)
            continue
        if kind == "len":
            code, length = next((c, l) for (c, l), s in lit.items()
                                if s == value)
            whuff(code, length)
            wbits(0, D.LENGTHS[value][1])
            continue
        if kind == "distbit":
            # One raw distance bit: the 3.2.7 single-code tree's absent
            # pattern.
            wbits(value, 1)
            continue
        lc, dc = value
        code, length = next((c, l) for (c, l), s in lit.items() if s == lc)
        whuff(code, length)
        wbits(0, D.LENGTHS[lc][1])  # minimal length in the range
        if dist:
            code, length = next((c, l) for (c, l), s in dist.items()
                                if s == dc)
            whuff(code, length)
        wbits(0, D.DISTANCES[dc][1])  # minimal distance in the range
        continue
    return finish()


def dyn_header(wbits, hlit_raw, hdist_raw, hclen_raw, clens):
    wbits(2, 2)  # BTYPE=10
    wbits(hlit_raw, 5)
    wbits(hdist_raw, 5)
    wbits(hclen_raw, 4)
    count = 4 + hclen_raw
    for pos in range(count):
        wbits(clens[D.CODE_ORDER[pos]], 3)
    for pos in range(count, 19):
        assert clens[D.CODE_ORDER[pos]] == 0


def main():
    # --- A. RFC 1951 3.2.1 worked example --------------------------------
    lengths = [3, 3, 3, 3, 3, 2, 4, 4]  # A..H
    codes = D.canonical_codes(lengths)
    want = {  # the RFC's table
        "A": (2, 3), "B": (3, 3), "C": (4, 3), "D": (5, 3),
        "E": (6, 3), "F": (0, 2), "G": (14, 4), "H": (15, 4),
    }
    for i, (sym, (code, length)) in enumerate(want.items()):
        check("A.%s" % sym, codes.get((code, length)), i)
    check("A.count", len(codes), 8)
    # The RFC's next_code values: N=1 -> 0, N=2 -> 0, N=3 -> 2, N=4 -> 14.
    count = {}
    for l in lengths:
        count[l] = count.get(l, 0) + 1
    code = 0
    for bits in range(1, 5):
        code = (code + count.get(bits - 1, 0)) << 1
        check("A.nextcode[%d]" % bits, code, {1: 0, 2: 0, 3: 2, 4: 14}[bits])
    # An incomplete (underfull) table is rejected; the single 1-bit code
    # is the accepted degenerate case.
    check("A.underfull", D.canonical_codes([0, 0, 2, 0]), None)
    check("A.single-bit", D.canonical_codes([1]), {(0, 1): 0})

    # --- B. Fixed tables (RFC 1951 3.2.6) --------------------------------
    # The RFC's literal table, as 3.2.6 prints it (the spec layer):
    lit = D.RFC_FIXED_LIT
    check("B.rfc-lit0", lit.get((0b00110000, 8)), 0)
    check("B.rfc-lit143", lit.get((0b10111111, 8)), 143)
    check("B.rfc-lit144", lit.get((0b110010000, 9)), 144)
    check("B.rfc-lit255", lit.get((0b111111111, 9)), 255)
    check("B.rfc-eob", lit.get((0b0100000, 7)), 256)
    check("B.rfc-lit279", lit.get((0b0110111, 7)), 279)
    check("B.rfc-lit280", lit.get((0b11000000, 8)), 280)
    check("B.rfc-lit287", lit.get((0b11000111, 8)), 287)
    check("B.rfc-lit-count", len(lit), 288)
    # 7-bit codes below 32 are not EOB/length codes in the RFC table
    # (they are prefixes of the 8-bit literals or dead), and the 24
    # EOB/length codes occupy 32-55, leaving 56-63 unused:
    check("B.rfc-eob-gap", lit.get((0, 7)), None)
    check("B.rfc-gap31", lit.get((31, 7)), None)
    check("B.rfc-gap63", lit.get((63, 7)), None)
    # The implementation's decoder walks the canonical construction
    # over the same code lengths (a documented deviation from the
    # literal table: the 24 seven-bit codes 0-23 become symbols
    # 256-279):
    impl = D.canonical_codes(D.fixed_lit_lengths())
    check("B.impl-eob", impl.get((0, 7)), 256)
    check("B.impl-lit279", impl.get((23, 7)), 279)
    check("B.impl-lit-count", len(impl), 288)
    dist = D.canonical_codes(D.fixed_dist_lengths())
    check("B.dist-count", len(dist), 32)
    check("B.dist0", dist.get((0, 5)), 0)
    check("B.dist31", dist.get((31, 5)), 31)

    # --- C. Stored blocks (RFC 1951 3.2.4) --------------------------------
    fd("C.stored-final", stored_block(True, b"A"), D.OK, None, out=b"A")
    fd("C.stored-nonfinal", stored_block(False, b"A"), D.EOF, "eof", out=b"A")
    # A second stored block whose header starts mid-byte (5 bits into a
    # byte, after a non-final empty stored block): the LEN/NLEN still
    # start at the next byte boundary.
    wbit, wbits, _whuff, finish = bits_writer()
    wbit(0)  # non-final
    wbits(0, 2)
    wbits(0, 5)
    wbits(0, 16)
    wbits(0xFFFF, 16)  # empty stored block: 40 bits, ends mid-byte
    wbit(1)  # the next header starts at bit 5
    wbits(0, 2)
    wbits(0, 5)  # skip the rest of the byte
    wbits(1, 16)
    wbits(0xFFFE, 16)
    wbits(0x41, 8)
    fd("C.stored-midheader", finish(), D.OK, None, out=b"A")
    # LEN/NLEN mismatch.
    wbit, wbits, _whuff, finish = bits_writer()
    wbit(1)
    wbits(0, 2)
    wbits(0, 5)
    wbits(1, 16)
    wbits(0xFFFD, 16)  # not the complement of 1
    fd("C.nlen", finish(), D.CORRUPT, "len-nlen-mismatch")
    # Truncated data: LEN says two bytes, one is present.
    wbit, wbits, _whuff, finish = bits_writer()
    wbit(1)
    wbits(0, 2)
    wbits(0, 5)
    wbits(2, 16)
    wbits(0xFFFD, 16)
    wbits(0x41, 8)
    fd("C.trunc", finish(), D.EOF, "eof", out=b"A")

    # --- D. Fixed blocks (implementation table: canonical) --------------------------------------------------
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    wbits(1, 2)  # BTYPE=01
    code, length = next((c, l) for (c, l), s in impl.items() if s == 65)
    whuff(code, length)
    whuff(0, 7)  # end-of-block
    buf = finish()
    fd("D.fixed-literal", buf, D.OK, None, out=b"A")
    fd("D.fixed-short1", buf[:1], D.EOF, "eof")
    fd("D.fixed-midbyte", buf[:3], D.OK, None, out=b"A")
    # Empty final fixed block: header (3 bits) + EOF (7 bits).
    fd("D.fixed-empty", bytes([0x03, 0x00]), D.OK, None)
    # A length+distance pair: literal A, then copy length 3 distance 1.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    wbits(1, 2)
    code, length = next((c, l) for (c, l), s in impl.items() if s == 65)
    whuff(code, length)
    c257, l257 = next((c, l) for (c, l), s in impl.items() if s == 257)
    whuff(c257, l257)  # length 257: 3, no extra
    d5 = int(format(0, "05b")[::-1], 2)
    wbits(d5, 5)  # fixed distance code 0: distance 1, no extra
    whuff(0, 7)
    fd("D.fixed-copy2", finish(), D.OK, None, out=b"AAAA")
    # A length code with no output yet: distance cannot exceed the start.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    wbits(1, 2)
    whuff(c257, l257)
    wbits(d5, 5)
    whuff(0, 7)
    fd("D.dist-too-far", finish(), D.CORRUPT, "dist-too-far")
    # Reserved BTYPE.
    fd("D.btype11", bytes([0b00000110]), D.CORRUPT, "btype-reserved")

    # --- E. Dynamic blocks (RFC 1951 3.2.7) -------------------------------
    check("E.code-order", D.CODE_ORDER,
          [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15])
    # Literal 'A' + EOF, no distance codes (the 3.2.7 zero-bit rule).
    fd("E.dyn-literal",
       dyn_block(True, {65: 1, 256: 1}, {}, [("lit", 65), ("eob", None)]),
       D.OK, None, out=b"A")
    # The one-distance-code rule: a single 1-bit distance code.
    fd("E.dyn-one-dist",
       dyn_block(True, {65: 1, 256: 2, 257: 2}, {0: 1},
                 [("lit", 65), ("copy", (257, 0)), ("eob", None)], hlit=1),
       D.OK, None, out=b"AAAA")
    # The same single-code tree rejects the absent bit pattern.
    fd("E.dyn-dist-badbit",
       dyn_block(True, {65: 1, 256: 2, 257: 2}, {0: 1},
                 [("lit", 65), ("len", 257), ("distbit", 1),
                  ("eob", None)], hlit=1),
       D.CORRUPT, "dist-badcode", out=b"A")
    # A length code with an empty distance tree faults.
    fd("E.dyn-dist-empty",
       dyn_block(True, {65: 1, 256: 2, 257: 2}, {},
                 [("lit", 65), ("copy", (257, 0)), ("eob", None)], hlit=1),
       D.CORRUPT, "dist-empty", out=b"A")
    # HLIT out of the RFC's range (257-286).
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    dyn_header(wbits, 30, 0, 14, [0] * 19)  # 257+30 = 287 > 286
    fd("E.hlit-range", finish(), D.CORRUPT, "hlit-range")
    # A repeat code without a previous length.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    dyn_header(wbits, 0, 0, 14, _clen_only(16))
    c16 = D.canonical_codes(_clen_only(16))
    code16, len16 = next((c, l) for (c, l), s in c16.items() if s == 16)
    whuff(code16, len16)
    fd("E.repeat-no-prev", finish(), D.CORRUPT, "repeat-no-prev")

    # --- F. Malformed classes: one vector per fault name --------------------
    fd("F.btype-reserved", bytes([0b00000110]), D.CORRUPT, "btype-reserved")
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    wbits(0, 2)
    wbits(0, 5)
    wbits(1, 16)
    wbits(0xFFFD, 16)
    wbits(0x41, 8)
    fd("F.len-nlen", finish(), D.CORRUPT, "len-nlen-mismatch")
    fd("F.eof", b"\x01", D.EOF, "eof")
    # Reserved length codes 286/287 exist only in the fixed table
    # (3.2.6: they "participate in the code construction"); decoding one
    # faults. 286 = 11000000 + 6.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    wbits(1, 2)  # fixed
    whuff(0b11000110, 8)
    fd("F.length-reserved", finish(), D.CORRUPT, "length-reserved")
    # Reserved distance codes 30/31 exist only in the fixed 5-bit
    # distance alphabet. 30 = 11110, read MSB-first.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    wbits(1, 2)  # fixed
    c65, l65 = next((c, l) for (c, l), s in lit.items() if s == 65)
    whuff(c65, l65)
    whuff(0b0000001, 7)  # length code 257: length 3, no extra
    wbits(int(format(30, "05b")[::-1], 2), 5)  # distance code 30
    whuff(0, 7)
    fd("F.dist-reserved", finish(), D.CORRUPT, "dist-reserved", out=b"A")
    # A bad literal code: a single-code literal tree, absent bit pattern.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    dyn_header(wbits, 0, 0, 14, _clen_vec({0: 2, 1: 2, 2: 2, 17: 3, 18: 3}))
    seq = [0] * 65 + [1] + [0] * 192
    emit_seq(wbits, whuff, seq)
    wbits(1, 1)  # the single-code tree's absent bit
    fd("F.lit-badcode", finish(), D.CORRUPT, "lit-badcode")
    # An overfull literal table (three 1-bit codes) and an incomplete
    # distance table (the one-code rule accepts only a single 1-bit code).
    check("F.lit-overfull", D.canonical_codes([0] * 65 + [1] + [0] * 190
                                              + [1] + [0] * 5 + [1]), None)
    check("F.dist-underfull", D.canonical_codes([1, 2] + [0] * 30), None)
    # A distance past the start of the output.
    fd("F.dist-too-far",
       dyn_block(True, {257: 1, 256: 1}, {0: 1},
                 [("copy", (257, 0)), ("eob", None)], hlit=1),
       D.CORRUPT, "dist-too-far")
    # A bad code in the code-length alphabet itself.
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    dyn_header(wbits, 0, 0, 14, _clen_only(17))
    wbits(1, 1)  # the first code-length symbol: the absent bit
    fd("F.clen-badcode", finish(), D.CORRUPT, "clen-badcode")
    # A repeat that overruns the code-length sequence (138 + 131 > 258).
    wbit, wbits, whuff, finish = bits_writer()
    wbit(1)
    dyn_header(wbits, 0, 0, 14, _clen_vec({0: 2, 1: 2, 2: 2, 17: 3, 18: 3}))
    emit_clen(wbits, whuff, 18, 127, 7)  # 138 zeros
    emit_clen(wbits, whuff, 18, 120, 7)  # 131 zeros

    fd("F.repeat-overrun", finish(), D.CORRUPT, "repeat-overrun")

    # --- G. RFC 7692 7.2.1: the compliant shape ----------------------------
    stream = stored_block(True, b"A")  # 6 bytes, byte-aligned
    # The truncated empty stored header starts at the byte boundary
    # (the 7.2.1 MUST zero padding), so its first octet is its BFINAL
    # bit alone: 0x00 or 0x01 are compliant; anything else (a BTYPE or
    # LEN bit set, or the old "1<<q, q in 1..5" mid-octet shapes the
    # header could not occupy) is not.
    check("G.tail-q0", D.spec7692(stream + bytes([0x01])),
          (D.COMPLETE, b"A", None))
    check("G.tail-zero", D.spec7692(stream + bytes([0x00])),
          (D.COMPLETE, b"A", None))
    for q in range(1, 6):
        check("G.tail-q%d" % q, D.spec7692(stream + bytes([1 << q])),
              (D.MALFORMED, None, "tail-shape"))
    check("G.tail-q6", D.spec7692(stream + bytes([0x40])),
          (D.MALFORMED, None, "tail-shape"))
    check("G.tail-missing", D.spec7692(stream),
          (D.PREFIX, None, "tail-missing"))
    check("G.tail-extra", D.spec7692(stream + bytes([0x01, 0x00])),
          (D.MALFORMED, None, "tail-shape"))
    # Mid-byte final block with the MUST zero padding, then the tail.
    # The spec layer walks the RFC literal table: the EOB is the
    # 7-bit code 32 (0100000) -- header (1, 1, 0) plus code bits
    # (0, 1, 0, 0, 0) make byte 0 = 0x13, and the code's last two
    # bits (0, 0) land in byte 1, so the empty final fixed block is
    # 0x13 0x00, ending at bit 10, mid-byte.
    check("G.padding-nonzero", D.spec7692(bytes([0x13, 0x3C])),
          (D.MALFORMED, None, "padding-nonzero"))
    check("G.midbyte-complete", D.spec7692(bytes([0x13, 0x00, 0x01])),
          (D.COMPLETE, b"", None))
    check("G.midbyte-prefix", D.spec7692(bytes([0x13, 0x00])),
          (D.PREFIX, None, "tail-missing"))
    # The same buffer under the implementation's canonical table
    # (EOB = 7-bit code 0) is the 0x03 0x00 shape: the implementation
    # decodes it; the spec layer (above) does not -- the documented
    # 3.2.6 deviation, pinned by the exhaustive table's ledger.
    check("G.impl-canonical-empty", D.flate_decode(bytes([0x03, 0x00])),
          (D.OK, b"", None))
    check("G.spec-rejects-canonical", D.spec7692(bytes([0x03, 0x00])),
          (D.MALFORMED, None, "lit-badcode"))

    # --- H. The implementation's committed oracle --------------------------
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "deflate_oracle.json")) as f:
        oracle = json_load(f)
    bad = 0
    for row in oracle:
        buf = bytes.fromhex(row["wire"])
        status, value = D.impl_decompress(buf, 1 << 20)
        if row["ok"]:
            if status != D.OK or value != bytes.fromhex(row["out"]):
                bad += 1
                if bad <= 5:
                    print("H.oracle mismatch ok: %s -> %r %r"
                          % (row["wire"], status, value))
        else:
            if status == D.OK:
                bad += 1
                if bad <= 5:
                    print("H.oracle mismatch fail: %s -> ok %r"
                          % (row["wire"], value))
    check("H.oracle", bad, 0)

    if FAILS:
        for f in FAILS:
            print("FAIL", f)
        print("deflate stream self-check FAILED (%d)" % len(FAILS))
        sys.exit(1)
    print("deflate stream self-check: A-H pass (%d oracle rows)"
          % len(oracle))


def _clen_only(sym):
    cl = [0] * 19
    cl[sym] = 1
    return cl


def _clen_vec(vec):
    return [vec.get(i, 0) for i in range(19)]


def json_load(f):
    import json
    return json.load(f)


if __name__ == "__main__":
    main()
