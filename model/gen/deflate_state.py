"""The streaming DEFLATE state machine (machine B, part 2; doc/
DEFLATE-STREAM.md).

A byte-granular, content-agnostic state machine for one DEFLATE stream
-- the permessage-deflate compressed payload (RFC 1951) at
maxMessageSize 6, the RSV1 machine's limit. Every state determines the
receiver's behavior for every future byte: the decoder configuration
(the block being read, the pending bits, the code tables in use, the
output length capped at 7) and nothing else. The payload's byte content
is not in the state: the machine classifies (fault timing, size
overflow, completion), and the byte-level reference
(deflate_stream.flate_decode) supplies the payload content at
delivery. That split is what keeps the state space finite -- a pending
code is a prefix of a table code (tables have at most 286 codes of at
most 15 bits), the dynamic header fields are at most 16 bits, and the
output length is capped by the message limit.

Bit order (RFC 1951 3.1.1): data elements are packed from the
least-significant bit of each byte. A pending Huffman code is read
MSB-first (the first bit received is the code's most significant bit);
non-Huffman fields (stored-block LEN/NLEN, the dynamic header, the
code-length values, the extra bits) are read LSB-first.

States are tuples; the first element is the phase tag:

  (0, o, b, v)                        block header, b bits accumulated
                                      (v the running value)
  (1, bf, o, b, v)                    stored block: the 16-bit LEN
                                      field, b bits in, LSB-first
  (2, bf, o, ln, b, v)                stored block: the 16-bit NLEN
                                      field
  (3, bf, o, ln, k)                   stored block: data, k of ln
                                      bytes consumed (byte-aligned; the
                                      data bits do not feed the stream)
  (4, bf, o, exl, exd, tbl, pml,
                                      pb, pv, xb, xbase, xval)
                                      huffman symbol data: tbl 0 =
                                      literal/length table, 1 =
                                      distance table; exl/exd the
                                      exact code sets (frozensets of
                                      (bits, value, symbol)); pml the
                                      pending copy length (0 = none);
                                      (pb, pv) the pending code (pb =
                                      0 means none pending); (xb,
                                      xbase, xval) the extra bits (xb =
                                      0 means none due, xbase the
                                      code's base, xval the running
                                      extra value)
  (5, bf, o, f, b, v, hlit)           dynamic header: 5-bit field f
                                      (0 = HLIT, 1 = HDIST)
  (6, bf, o, b, v, hlit, hdist)       dynamic header: the 4-bit HCLEN
  (7, bf, o, f, b, v, vals, hlit,
                                      hdist, hclen)
                                      code-length values, 3 bits each,
                                      f values in, vals the values
                                      collected so far
  (8, bf, o, clx, pb, pv, fc)         code-length tree symbols:
                                      pending (pb, pv) in tree clx
                                      (pb = 0 means waiting for the
                                      next symbol); fc the table-fill
                                      context = (tbl, cnt, lit, dist,
                                      last, has, hlit, hdist) -- tbl
                                      0 = filling the lit/length
                                      table, 1 = the distance table;
                                      cnt entries filled; lit/dist
                                      the length tuples so far;
                                      last/has the previous length
                                      for repeat code 16
  (9, bf, o, rep, xb, xval, clx, fc)  repeat-code extra bits (rep in
                                      16/17/18, xval the running
                                      value)
  (11, o)                             stream complete (a BFINAL block
                                      closed); trailing bytes ignored
  (12, o)                             fault latched (o = the output
                                      the decoder had produced when it
                                      failed)

The output length o counts payload bytes toward the message limit and
is capped at MAXMSG + 1: at MAXMSG + 1 the size guard has tripped, and
no further input can change the outcome, so the cap loses nothing.

Fault names match the byte-level reference's (deflate_stream) so a
latched state names the RFC 1951 condition that produced it:
btype-reserved, len-nlen-mismatch, badcode, length-reserved,
dist-reserved, dist-empty, dist-too-far, hlit-range, hdist-range,
clen-overfull, clen-badcode, repeat-no-prev, repeat-overrun,
lit-overfull, dist-overfull, size.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deflate_stream as D
import deflate

MAXMSG = deflate.MAXMSG
CAP = MAXMSG + 1

HDR = 0
SLN = 1
SNL = 2
SDT = 3
HSYM = 4
DCH5 = 5
DCH4 = 6
DCL = 7
DCT = 8
REP = 9
DONE = 11
LATCH = 12


def _exact_sets(lengths):
    """The exact code set (frozenset of (bits, value, symbol)) for a
    canonical table; None when the lengths are overfull (the Kraft
    sum exceeds capacity, the single 1-bit code excepted), the empty
    frozenset for the all-zero table (legal only as the distance
    table, where first use faults)."""
    count = {}
    for l in lengths:
        if l > 0:
            count[l] = count.get(l, 0) + 1
    if not count:
        return frozenset()
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
    ex = set()
    for sym, l in enumerate(lengths):
        if l == 0:
            continue
        ex.add((next_code[l], l, sym))
        next_code[l] += 1
    return frozenset(ex)


FIXED_LIT = _exact_sets(D.fixed_lit_lengths())
FIXED_DIST = _exact_sets(D.fixed_dist_lengths())

# Derived per exact code set: the prefix set ((bits, value) of every
# prefix of every code), the symbol lookup ((bits, value) -> symbol),
# and the table's maximum code length (the decoder faults on a bad
# code only after reading maxlen bits -- a dead prefix is not
# declared dead until then, matching the reference decoder's
# observable timing).
_DERIVED = {}


def _derived(ex):
    if ex not in _DERIVED:
        pf = set()
        syms = {}
        mlen = 0
        for value, bits, sym in ex:
            syms[(bits, value)] = sym
            mlen = max(mlen, bits)
            for k in range(1, bits + 1):
                pf.add((k, value >> (bits - k)))
        _DERIVED[ex] = (frozenset(pf), syms, mlen)
    return _DERIVED[ex]


def _cap(o, delta):
    return min(o + delta, CAP)


def _latch(o):
    return (LATCH, o)


def _finish_block(bf, o):
    if o > MAXMSG:
        # The size guard fires at the segment flush: a block that
        # closes over the limit fails the message before any further
        # byte is read.
        return _latch(o)
    if bf:
        return (DONE, o)
    return (HDR, o, 0, 0)


def _huff_start(bf, o, exl, exd, tbl, pml):
    """A pending code read in table tbl; an empty table (the
    one-distance-code rule's empty distance table) faults before
    reading it."""
    ex = exl if tbl == 0 else exd
    if len(ex) == 0:
        return _latch(o)
    return (HSYM, bf, o, exl, exd, tbl, pml, 0, 0, 0, 0, 0)


def _match_dist(sym, o, exl, exd, bf, pml):
    if sym > 29:  # 30, 31: never occur
        return _latch(o)
    base, extra = D.DISTANCES[sym]
    if extra == 0:
        return _apply_dist(base, o, exl, exd, bf, pml)
    return (HSYM, bf, o, exl, exd, 1, pml, 0, 0, extra, base, 0)


def _apply_dist(dist, o, exl, exd, bf, pml):
    if dist > o:
        return _latch(o)
    o2 = _cap(o, pml)
    if o2 > MAXMSG:
        return _latch(o2)
    return (HSYM, bf, o2, exl, exd, 0, 0, 0, 0, 0, 0, 0)


def _fill(fc, val, count):
    """Apply one code length (or a repeat's run) to the fill context
    fc = (tbl, cnt, lit, dist, last, has, hlit, hdist). Returns
    ('done', fc) when both tables complete, ('fault',) on an overrun,
    ('more', fc) otherwise."""
    tbl, cnt, lit, dist, last, has, hlit, hdist = fc
    litn = 257 + hlit
    distn = 1 + hdist
    lens = lit if tbl == 0 else dist
    if cnt + count > (litn if tbl == 0 else distn):
        return ("fault",)
    lens = lens[:cnt] + (val,) * count + lens[cnt + count:]
    cnt += count
    if tbl == 0:
        lit, dist = lens, dist
    else:
        lit, dist = lit, lens
    if cnt == (litn if tbl == 0 else distn):
        if tbl == 0:
            return ("more", (1, 0, lit, dist, val, True, hlit,
                             hdist))
        return ("done", (1, cnt, lit, dist, val, True, hlit, hdist))
    return ("more", (tbl, cnt, lit, dist, val, True, hlit, hdist))


def _tables_done(bf, o, fc):
    """Both tables filled: build the exact code sets and start the
    symbol data."""
    tbl, cnt, lit, dist, last, has, hlit, hdist = fc
    if len(lit) != 257 + hlit or len(dist) != 1 + hdist:
        return _latch(o)
    exl = _exact_sets(list(lit))
    if exl is None:
        return _latch(o)
    exd = _exact_sets(list(dist))
    if exd is None:
        return _latch(o)
    return _huff_start(bf, o, exl, exd, 0, 0)


def step(state, byte):
    """One input byte (8 bits, LSB first per RFC 1951 3.1.1). Total on
    every state: LATCH absorbs input; DONE (a BFINAL block just
    closed) starts a new stream on the next byte, the output length
    carried (the implementation's size guard is cumulative over the
    segment loop)."""
    st = state
    if st[0] == LATCH:
        return st
    if st[0] == DONE:
        st = (HDR, st[1], 0, 0)
    i = 0
    while i < 8:
        st, i = _step_bit(st, byte, i)
        if st[0] == LATCH:
            break
        if st[0] == DONE:
            # The block closed: the rest of this byte (if any) is
            # padding, discarded; the next byte starts the next
            # stream (or ends the input, in which case DONE is the
            # end state).
            break
    return st


def _step_bit(st, byte, i):
    """Consume one bit (or finish a byte-aligned field); return
    (new state, next bit index)."""
    bit = (byte >> i) & 1
    i += 1
    phase = st[0]
    if phase == HDR:
        _, o, b, v = st
        v = v | (bit << b)
        b += 1
        if b < 3:
            return (HDR, o, b, v), i
        btype = (v >> 1) & 3
        bf = v & 1
        if btype == 3:
            return _latch(o), i
        if btype == 0:
            # Stored blocks are byte-oriented (3.2.4): the LEN field
            # starts at the byte boundary after the header, so the
            # header's leftover bits are skipped.
            return (SLN, bf, o, 0, 0), 8
        if btype == 1:
            return _huff_start(bf, o, FIXED_LIT, FIXED_DIST, 0, 0), i
        return (DCH5, bf, o, 0, 0, 0, None), i
    if phase == SLN:
        _, bf, o, b, v = st
        v = v | (bit << b)
        b += 1
        if b < 16:
            return (SLN, bf, o, b, v), i
        return (SNL, bf, o, v, 0, 0), i
    if phase == SNL:
        _, bf, o, ln, b, v = st
        v = v | (bit << b)
        b += 1
        if b < 16:
            return (SNL, bf, o, ln, b, v), i
        if v != (~ln & 0xFFFF):
            return _latch(o), i
        if ln == 0:
            return _finish_block(bf, o), i
        return (SDT, bf, o, ln, 0), i
    if phase == SDT:
        _, bf, o, ln, k = st
        # The data is byte-aligned (3.2.4) and its bits do not feed
        # the bit stream: a data byte is consumed whole.
        if k == ln:
            return _finish_block(bf, o), i
        if i >= 8:
            return st, i
        o2 = _cap(o, 1)
        if o2 > MAXMSG:
            return _latch(o2), 8
        k += 1
        if k == ln:
            return _finish_block(bf, o2), 8
        return (SDT, bf, o2, ln, k), 8
    if phase == HSYM:
        return _step_hsym(st, bit, i)
    if phase == DCH5:
        _, bf, o, f, b, v, hlit = st
        v = v | (bit << b)
        b += 1
        if b < 5:
            return (DCH5, bf, o, f, b, v, hlit), i
        if f == 0:
            return _dyn_field(bf, o, 0, v), i
        return _dyn_field(bf, o, 1, v, hlit), i
    if phase == DCH4:
        _, bf, o, b, v, hlit, hdist = st
        v = v | (bit << b)
        b += 1
        if b < 4:
            return (DCH4, bf, o, b, v, hlit, hdist), i
        return _dyn_field(bf, o, 2, v, hlit, hdist), i
    if phase == DCL:
        _, bf, o, f, b, v, vals, hlit, hdist, hclen = st
        v = v | (bit << b)
        b += 1
        if b < 3:
            return (DCL, bf, o, f, b, v, vals, hlit, hdist, hclen), i
        vals = vals + (v,)
        if f + 1 < hclen:
            return (DCL, bf, o, f + 1, 0, 0, vals, hlit, hdist,
                    hclen), i
        clens = [0] * 19
        for j, val in enumerate(vals):
            clens[D.CODE_ORDER[j]] = val
        ex = _exact_sets(clens)
        if ex is None:
            return _latch(o), i
        return (DCT, bf, o, ex, 0, 0,
                (0, 0, (), (), 0, False, hlit, hdist)), i
    if phase == DCT:
        return _step_dct(st, bit, i)
    if phase == REP:
        _, bf, o, rep, xb, xval, clx, fc = st
        xval = xval | (bit << (xb - 1))
        xb -= 1
        if xb > 0:
            return (REP, bf, o, rep, xb, xval, clx, fc), i
        val = fc[4] if rep == 16 else 0
        count = (2 if rep == 16 else 3 if rep == 17 else 11) + xval
        res = _fill(fc, val, count)
        if res[0] == "fault":
            return _latch(o), i
        if res[0] == "done":
            return _tables_done(bf, o, res[1]), i
        return (DCT, bf, o, clx, 0, 0, res[1]), i
    raise AssertionError("unreachable phase %r" % phase)


def _dyn_field(bf, o, f, v, hlit=None, hdist=None):
    """A completed dynamic header field (5, 5, or 4 bits)."""
    if f == 0:
        if v + 257 > 286:
            return _latch(o)
        return (DCH5, bf, o, 1, 0, 0, v)
    if f == 1:
        if v + 1 > 32:
            return _latch(o)
        return (DCH4, bf, o, 0, 0, hlit, v)
    return (DCL, bf, o, 0, 0, 0, (), hlit, hdist, v + 4)


def _step_hsym(st, bit, i):
    _, bf, o, exl, exd, tbl, pml, pb, pv, xb, xbase, xval = st
    if xb > 0:
        xval = xval | (bit << (xb - 1))
        xb -= 1
        if xb > 0:
            return (HSYM, bf, o, exl, exd, tbl, pml, 0, 0, xb,
                    xbase, xval), i
        if tbl == 0:
            return _huff_start(bf, o, exl, exd, 1, xbase + xval), i
        return _apply_dist(xbase + xval, o, exl, exd, bf, pml), i
    if pb == 0:
        return (HSYM, bf, o, exl, exd, tbl, pml, 1, bit, 0, 0,
                0), i
    pv2 = (pv << 1) | bit  # MSB-first: the first bit is the code's MSB
    pb2 = pb + 1
    ex = exl if tbl == 0 else exd
    _pf, syms, mlen = _derived(ex)
    if (pb2, pv2) in syms:  # an exact code
        sym = syms[(pb2, pv2)]
        if tbl == 0:
            if sym > 285:  # 286, 287: reserved
                return _latch(o), i
            if sym < 256:
                o2 = _cap(o, 1)
                if o2 > MAXMSG:
                    return _latch(o2), i
                return (HSYM, bf, o2, exl, exd, 0, 0, 0, 0, 0,
                        0, 0), i
            if sym == 256:
                return _finish_block(bf, o), i
            base, extra = D.LENGTHS[sym]
            if extra == 0:
                return _huff_start(bf, o, exl, exd, 1, base), i
            return (HSYM, bf, o, exl, exd, 0, 0, 0, 0, extra,
                    base, 0), i
        return _match_dist(sym, o, exl, exd, bf, pml), i
    if pb2 >= mlen:  # no code this long extends the prefix
        return _latch(o), i
    return (HSYM, bf, o, exl, exd, tbl, pml, pb2, pv2, 0, 0,
            0), i


def _step_dct(st, bit, i):
    _, bf, o, clx, pb, pv, fc = st
    if pb == 0:
        return (DCT, bf, o, clx, 1, bit, fc), i
    pv2 = (pv << 1) | bit
    pb2 = pb + 1
    _pf, syms, mlen = _derived(clx)
    if (pb2, pv2) in syms:
        sym = syms[(pb2, pv2)]
        tbl, cnt, lit, dist, last, has, hlit, hdist = fc
        if sym < 16:
            res = _fill(fc, sym, 1)
            if res[0] == "fault":
                return _latch(o), i
            if res[0] == "done":
                return _tables_done(bf, o, res[1]), i
            return (DCT, bf, o, clx, 0, 0, res[1]), i
        if sym == 16:
            if not has:
                return _latch(o), i
            return (REP, bf, o, 16, 2, 0, clx, fc), i
        if sym == 17:
            return (REP, bf, o, 17, 3, 0, clx, fc), i
        return (REP, bf, o, 18, 7, 0, clx, fc), i
    if pb2 >= mlen:  # no code this long extends the prefix
        return _latch(o), i
    return (DCT, bf, o, clx, pb2, pv2, fc), i


def initial():
    return (HDR, 0, 0, 0)


def coarse(state):
    """The coarse phase for the nuXmv cross-check: the decoder's
    region, independent of the pending-bit configuration."""
    p = state[0]
    if p == HDR:
        return "hdr"
    if p in (SLN, SNL, SDT):
        return "stored"
    if p == HSYM:
        return "huff"
    if p in (DCH5, DCH4, DCL, DCT, REP):
        return "dyn"
    if p == DONE:
        return "done"
    return "latch"


def out_len(state):
    """The capped output length a state carries."""
    if state[0] == HDR or state[0] in (DONE, LATCH):
        return state[1]
    return state[2]


def latched(state):
    return state[0] == LATCH


def done(state):
    return state[0] == DONE
