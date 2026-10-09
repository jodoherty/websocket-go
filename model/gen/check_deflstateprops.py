"""The streaming DEFLATE state machine's self-check (machine B,
part 2; doc/DEFLATE-STREAM.md).

Container-free. The machine (deflate_state) is cross-checked against
the byte-level implementation model (deflate_stream.impl_decompress)
on every prefix of every buffer in the committed exhaustive table
(all 65,792 one- and two-byte buffers) and every committed
decompression-oracle wire. At each prefix p the machine folds the
wire plus the implementation's completion tail (the implementation
decodes the accumulated wire with the tail on the final segment on
every call, fin or not) and compares:

  Q1  outcome agreement:
        machine overflow (capped output MAXMSG + 1)
            <-> implementation size guard;
        machine end state complete
            <-> implementation ok;
        machine end state latched
            <-> implementation corrupt;
        machine end state active (pending)
            <-> implementation eof (the tail did not complete the
               stream).
  Q2  output agreement: when the implementation is ok, the
      machine's output length equals the implementation's.
  Q3  absorption: LATCH absorbs; DONE transitions to a new stream on
      the next byte, and latching is one-way.
  Q4  prefix-set soundness: every derived exact code set is a valid
      canonical table, its prefix set is closed under extension, and
      no exact code has an extension.

Q5 (coarse reachability against the independent nuXmv encoding)
lives in the Makefile target deflstate-model. Run directly:
python3 check_deflstateprops.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deflate_stream as D  # noqa: E402
import deflate_state as S  # noqa: E402
import gen_deflstatemodel as G  # noqa: E402

FAILS = []
D_MAX = 6

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))


def load_table():
    path = os.path.join(ROOT, "ws", "testdata", "deflstream",
                        "oracle.json")
    with open(path) as fh:
        tbl = json.load(fh)
    return [bytes.fromhex(row[0]) for row in tbl["rows"]]


def load_oracle():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "deflate_oracle.json")
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        rows = json.load(fh)
    return [bytes.fromhex(row["wire"]) for row in rows]


with_tail = G.with_tail


def prefix_check(buf):
    """Q1-Q2 over every prefix of one buffer."""
    st = S.initial()
    for n in range(1, len(buf) + 1):
        st = S.step(st, buf[n - 1])
        status, value = D.impl_decompress(buf[:n], D_MAX)
        m = with_tail(st)
        mo = S.out_len(m)
        overflow = mo > D_MAX
        if overflow != (status == D.SIZE):
            FAILS.append("Q1: %s[:%d]: machine overflow=%s, "
                         "impl=%s" % (buf.hex(), n, overflow, status))
            return
        end = S.done(m)
        latched = S.latched(m) and not overflow
        if end != (status == D.OK):
            FAILS.append("Q1: %s[:%d]: machine done=%s, impl ok=%s"
                         % (buf.hex(), n, end, status == D.OK))
            return
        if latched != (status == D.CORRUPT):
            FAILS.append("Q1: %s[:%d]: machine latched=%s, "
                         "impl=%s" % (buf.hex(), n, latched, status))
            return
        if not end and not overflow and not latched and status != D.EOF:
            FAILS.append("Q1: %s[:%d]: machine pending, impl=%s"
                         % (buf.hex(), n, status))
            return
        if end and mo != len(value):
            FAILS.append("Q2: %s[:%d]: machine o=%d, impl out=%d"
                         % (buf.hex(), n, mo, len(value)))
            return


def absorption_check(rnd):
    """Q3: LATCH absorbs; DONE starts a new stream; latching is
    one-way."""
    st = S.initial()
    for _ in range(20000):
        st2 = S.step(st, rnd.randrange(256))
        if S.latched(st):
            if st2 != st:
                FAILS.append("Q3: a latched state does not absorb")
                return
        elif S.latched(st2) and S.done(st) and S.out_len(st2) <= D_MAX:
            FAILS.append("Q3: a just-completed stream latched "
                         "without an overflow")
            return
        st = st2


def check_sound(name, ex):
    """Q4: the derived prefix set and symbol map of one table."""
    pf, syms, _mlen = S._derived(ex)
    for value, bits, _sym in ex:
        if (bits, value) not in pf:
            FAILS.append("Q4: %s: code missing from prefix set"
                         % name)
            return
        for k in range(1, bits):
            if (k, value >> (bits - k)) not in pf:
                FAILS.append("Q4: %s: prefix not closed under "
                             "extension" % name)
                return
    for bits, value in pf:
        if (bits, value) in syms and (bits + 1, value << 1) in pf:
            FAILS.append("Q4: %s: exact code with an extension"
                         % name)
            return


def main():
    bufs = load_table()
    oracles = load_oracle()
    for buf in bufs:
        prefix_check(buf)
    for buf in oracles:
        prefix_check(buf)

    rnd = random.Random(7692)
    absorption_check(rnd)

    for name, ex in (("fixed-lit", S.FIXED_LIT),
                     ("fixed-dist", S.FIXED_DIST)):
        check_sound(name, ex)
    st = S.initial()
    for _ in range(30000):
        st = S.step(st, rnd.randrange(256))
    derived = list(S._DERIVED.keys())
    for ex in derived:
        check_sound("derived-%d" % len(ex), ex)

    if FAILS:
        for f in FAILS[:20]:
            print("FAIL", f)
        if len(FAILS) > 20:
            print("... %d more" % (len(FAILS) - 20))
        sys.exit(1)
    print("deflate stream state self-check: Q1-Q4 pass (%d table "
          "buffers, %d oracle wires, %d derived tables sound)"
          % (len(bufs), len(oracles), len(derived)))


if __name__ == "__main__":
    main()
