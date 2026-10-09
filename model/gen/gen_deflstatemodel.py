"""The coarse DEFLATE stream machine (machine B, part 2, Q5): an
independent nuXmv encoding of the byte machine's phase region, for
the reachability cross-check (doc/DEFLATE-STREAM.md).

The byte machine (deflate_state) carries the pending-bit
configuration in its states, so its concrete state space is too
large for exhaustive Python exploration; the coarse abstraction
(phase x capped output length, 48 pairs) is small enough to
cross-check against nuXmv. Both directions are established
concretely:

  machine -> SMV  every machine-reachable coarse state has a
                  witness byte sequence (WITNESSES below), and the
                  observed machine transitions (the byte
                  successors of the witness states and their path
                  prefixes) are all SMV edges.
  SMV -> machine  nuXmv computes the encoding's reachable set per
                  pair; it must equal exactly the witness set (the
                  overflow-only-to-latch guard keeps the spurious
                  active-with-overflow pairs out).

The machine's states are observed at byte boundaries (one step per
byte); a block header needs at most 3 bits, so it is never pending
at a byte boundary: the hdr phase is the initial state only, and a
done/hdr byte jumps straight into the block the header names.

Emit + cross-check: python3 gen_deflstatemodel.py
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deflate_state as S  # noqa: E402
import deflate_stream as D  # noqa: E402

CONTAINER = os.environ.get("MBT_IMAGE", "websocket-go-model:latest")

PHASES = ["hdr", "stored", "huff", "dyn", "done", "latch"]
IDX = {p: i for i, p in enumerate(PHASES)}

# Coarse transitions at the byte boundary (sound per edge):
#   hdr    the initial state only: the first byte's header names
#          the block (stored/huff/dyn) or faults (reserved BTYPE).
#   stored LEN/NLEN/data; a block ends at a byte boundary into the
#          next block's header (stored/huff/dyn) or the complete
#          state (done); a NLEN mismatch or an overflow faults.
#   huff   symbol data; a block ends (mid-byte padding or at a
#          boundary) into stored/huff/dyn or done; faults latch.
#   dyn    header fields, code-length tree, table fill; completes
#          into huff (the block's symbol data) or faults.
#   done   a BFINAL block just closed: the next byte starts the
#          next stream, whose header names stored/huff/dyn or
#          faults; no byte returns to done.
#   latch  absorbing.
EDGES = {
    "hdr": ["stored", "huff", "dyn", "latch"],
    "stored": ["stored", "huff", "dyn", "done", "latch"],
    "huff": ["stored", "huff", "dyn", "done", "latch"],
    "dyn": ["huff", "dyn", "latch"],
    "done": ["stored", "huff", "dyn", "latch"],
    "latch": ["latch"],
}

WITNESS_STATES = (
    [("hdr", 0)]
    + [("stored", o) for o in range(7)]
    + [("huff", o) for o in range(7)]
    + [("dyn", o) for o in range(7)]
    + [("done", o) for o in range(7)]
    + [("latch", o) for o in range(8)]
)

SMV = """MODULE main

VAR
  phase : 0..5;
  olen : 0..7;

IVAR
  ib : 0..255;
  d : 0..6;

ASSIGN
  init(phase) := 0;
  init(olen)  := 0;

  next(phase) := case
    phase = 0 : { 1, 2, 3, 5 };
    phase = 1 : { 1, 2, 3, 4, 5 };
    phase = 2 : { 1, 2, 3, 4, 5 };
    phase = 3 : { 2, 3, 5 };
    phase = 4 : { 1, 2, 3, 5 };
    TRUE      : 5;
  esac;

  next(olen) := case
    (olen = 6) & ((phase = 1) | (phase = 2) | (phase = 3))
    & (next(phase) = 5) : 7;
    (phase = 3 | next(phase) = 3) : olen;
    (olen + d <= 6) : olen + d;
    TRUE : olen;
  esac;
"""


def with_tail(state):
    """Fold the implementation's completion tail through the machine --
    the implementation decodes the accumulated wire with the tail on
    the final segment on every call. Once a segment is complete or
    faulted, the remaining tail bytes are trailing data the decoder
    ignores."""
    st = state
    for b in D.TAIL9:
        if st[0] in (S.DONE, S.LATCH):
            break
        st = S.step(st, b)
    return st


def run(path):
    """Fold one byte sequence through the machine; return the list
    of (state, coarse class, output length) after each byte."""
    st = S.initial()
    out = []
    for b in path:
        st = S.step(st, b)
        out.append((st, S.coarse(st), S.out_len(st)))
    return out


def witnesses():
    """A witness byte sequence per witness state. Bytes are chosen
    against the implementation's fixed table (canonical: EOB =
    7-bit code 0; literal 0x50 = 8-bit code 128 = 0b10000000, one
    per byte as 0x01, leaving no pending bits)."""
    w = {}
    w[("hdr", 0)] = ()
    # stored-o: a stored block (bf = 0) mid-data after o data
    # bytes; o = 0: the header alone (LEN pending).
    for o in range(7):
        if o == 0:
            w[("stored", o)] = (0x40,)
            continue
        ln = 8
        w[("stored", o)] = (0x40, 0x00, ln, 0xFF, ln ^ 0xFF) + \
            (0x00,) * o
    # huff-o: o fixed-table literals (0x10 each), no pending left
    # beyond the carried 5 bits. The header 0x12 leaves the
    # 5-bit pending 0b10000, which every 0x10 byte extends through
    # an 8-bit literal (code 128, symbol 0x50) and back.
    w[("huff", 0)] = (0x12,)
    for o in range(1, 7):
        w[("huff", o)] = (0x12,) + (0x10,) * o
    # dyn-o: the dynamic header field pending; o = 0 from the start,
    # o >= 1 behind a completed stream (the size guard is
    # cumulative over the segment loop).
    w[("dyn", 0)] = (0x04,)
    for o in range(1, 7):
        w[("dyn", o)] = ((0x13,) + (0x10,) * (o - 1) + (0x00, 0x00)
                         if o > 0 else (0x03, 0x00)) + (0x04,)
        if o == 1:
            w[("dyn", 1)] = (0x13, 0x00, 0x00, 0x04)
    # done-o: a final block (header 0x13, bf = 1). done-0: the EOB
    # from the 0b00000 pending (0x03 leaves it) takes two bits of
    # one byte. done-o: o-1 literals, one literal (0x00) that
    # resets the pending to 0b00000, then the EOB byte.
    w[("done", 0)] = (0x03, 0x00)
    for o in range(1, 7):
        w[("done", o)] = (0x13,) + (0x10,) * (o - 1) + (0x00, 0x00)
    # latch-o: o = 0: a reserved BTYPE; o >= 1: o literals, then
    # length code 257 (7-bit code 1, no extra) and the reserved
    # fixed distance code 30 (5 bits 11110).
    w[("latch", 0)] = (0x06,)
    for o in range(1, 7):
        w[("latch", o)] = (0x12,) + (0x10,) * (o - 1) + (0x00, 0x7E)
    # latch-7: seven stored data bytes (the size guard).
    ln = 7
    w[("latch", 7)] = (0x40, 0x00, ln, 0xFF, ln ^ 0xFF) + \
        (0x00,) * 7
    return w


def main():
    w = witnesses()
    observed = set()
    for (p, o), path in sorted(w.items(), key=repr):
        trace = run(path)
        last = (trace[-1][1], trace[-1][2]) if trace else ("hdr", 0)
        if last != (p, o):
            sys.exit("FAIL: witness for %r ends in %r (path %s)"
                     % ((p, o), last, bytes(path).hex()))
        st = S.initial()
        for b in path:
            st2 = S.step(st, b)
            observed.add((S.coarse(st), S.coarse(st2),
                          S.out_len(st) <= S.out_len(st2)))
            st = st2
        for b in range(256):
            st2 = S.step(st, b)
            observed.add((S.coarse(st), S.coarse(st2),
                          S.out_len(st) <= S.out_len(st2)))
    print("machine: %d witness states verified, %d observed "
          "transition kinds" % (len(w), len(observed)))
    for p in PHASES:
        os_ = sorted(o for (ph, o) in w if ph == p)
        print("  %-7s o in %s" % (p, os_))
    for (a, b, m) in sorted(observed):
        if b not in EDGES[a] or not m:
            sys.exit("FAIL: observed machine transition %s -> %s "
                     "(o monotone=%s) is not an SMV edge" % (a, b, m))
    print("coarse soundness: observed machine transitions subset "
          "of the SMV edges")

    print("cross-checking coarse reachability with nuXmv ...",
          file=sys.stderr)
    reach = crosscheck()
    for pair, r in sorted(reach.items()):
        want = pair in w
        if r != want:
            sys.exit("model disagreement: %r reachable in nuXmv=%s, "
                     "witnessed in the machine=%s" % (pair, r, want))
    print("coarse reachability: nuXmv agrees on all %d pairs"
          % len(reach))


def crosscheck():
    """The SMV encoding's reachable set, per (phase, o) pair."""
    pairs = sorted(set(WITNESS_STATES) |
                   {(p, o) for p in PHASES for o in range(8)})
    models = tempfile.mkdtemp(prefix="deflstate_xc_")
    for p, o in pairs:
        prop = SMV + "LTLSPEC G ! (phase = %d & olen = %d);\n" % (
            IDX[p], o)
        with open(os.path.join(models, "%s_%d.smv" % (p, o)), "w") as fh:
            fh.write(prop)
    script = ("for f in /src/models/*.smv; do "
              "printf 'check_ltl\\nexit\\n' | nuXmv \"$f\" > \"$f.out\" "
              "2>&1; done")
    proc = subprocess.run(
        ["podman", "run", "--rm", "-v", models + ":/src/models:Z",
         CONTAINER, "sh", "-c", script],
        capture_output=True)
    missing = []
    for p, o in pairs:
        if not os.path.exists(os.path.join(models,
                                           "%s_%d.smv.out" % (p, o))):
            missing.append((p, o))
    if missing:
        sys.exit("nuXmv cross-check failed to run (missing output "
                 "for %d pairs): %s" % (len(missing), proc.stderr.decode()))
    result = {}
    for p, o in pairs:
        raw = open(os.path.join(models, "%s_%d.smv.out" % (p, o))).read()
        # reachable iff G !(phase & o) is violated ("is false").
        result[(p, o)] = "is false" in raw
    return result


if __name__ == "__main__":
    main()
