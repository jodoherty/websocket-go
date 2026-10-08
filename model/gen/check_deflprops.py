"""Model self-consistency checks for the RSV1 / compressed-message machine
(pure Python).

Run by `make deflate-model`, after the shared boundary machine's own
properties (make utf8-model) and the machine's wire self-check
(deflate.self_check). These validate the transition function
(deflate.trans) independent of the implementation:

  P1  the close code the machine SHOULD transmit is always legitimate --
      every code in every target set is a usable code in 1000-4999
      (1004/1005/1006/1015 excluded). The under-specified decompression
      cases are target SETS ({1002, 1007} failed decompression, {1002,
      1009} decompressed size overflow); every member must be legitimate.
  P2  TERM is absorbing: once terminal, the state never leaves it.
  CX  completeness: every (state, frame) pair has a defined transition
      (the table is a total function -- a gap would be a silent omission).
  CF  the concrete encoding round-trips: each frame encodes to the byte
      length its header claims, on both sides.
  P6  RSV1 placement (RFC 7692 6.1): RSV1 is legal exactly on the first
      data frame of a compressed message (from IDLE); from every other
      non-terminal state, every RSV1 frame fails the connection.
  P7  no plain-domain leak: a plain (RSV1=0) frame in a plain context
      (IDLE or a plain fragment state) never enters a compressed state.
  P8  sticky compressed context: a continuation in a compressed context
      (including a poisoned one) stays in the compressed domain
      (accumulates or completes), never jumping to a plain fragment
      state.
  RX  reachability audit: the reachable set is exactly the one the
      alphabet can build under the wire limit -- the plain counts, the
      plain text projection {CLEAN, BROKEN}, and every compressed
      (wire, decompressed) pair / pending-41 / poisoned state, each with
      its boundary suffixes (the compressed domain reaches the shared
      boundary machine's narrow acceptance sets; the plain domain's
      projection is {CLEAN, BROKEN}, as in the reassembly machine).

A failure here means the model (and therefore the traces it generates) is
wrong; fix deflate.py, regenerate the traces, and re-run.
"""

import sys
from collections import deque

import deflate as D
import utf8bound as U


def main():
    failures = []

    # P1: wire close-code legitimacy over every (state, frame) pair --
    # every code in every target set.
    for s in D.STATES:
        for f in D.FRAME_NAMES:
            for code in D.should_close(s, f):
                if not (1000 <= code <= 4999):
                    failures.append("P1: (%s, %s) close code %d outside 1000-4999" % (s, f, code))
                if code in (1004, 1005, 1006, 1015):
                    failures.append("P1: (%s, %s) close code %d is must-not-set" % (s, f, code))

    # P2: TERM absorbing.
    for f in D.FRAME_NAMES:
        to, _, _, _ = D.trans(D.TERM, f)
        if to != D.TERM:
            failures.append("P2: TERM + %s -> %s" % (f, to))

    # CX: completeness of the transition table.
    for s in D.STATES:
        for f in D.FRAME_NAMES:
            try:
                to, emits, rfc, fault = D.trans(s, f)
            except Exception as e:  # noqa: BLE001 - a table gap is the failure
                failures.append("CX: (%s, %s) raised %r" % (s, f, e))
                continue
            if to not in D.STATES:
                failures.append("CX: (%s, %s) -> %r not a state" % (s, f, to))
            for e in emits:
                if e["t"] not in ("event", "terminal"):
                    failures.append("CX: (%s, %s) emit %r has no kind" % (s, f, e))

    # CF: concrete encoding length round-trip.
    for f in D.FRAME_NAMES:
        fr = D.FRAMES[f]
        if fr["op"] == -1:
            continue
        for side in ("server", "client"):
            b = D.encode(f, side)
            form = fr["lenform"]
            if form == "short":
                claimed = b[1] & 0x7F
                off = 2
            elif form == "16":
                claimed = int.from_bytes(b[2:4], "big")
                off = 4
            else:
                claimed = int.from_bytes(b[2:10], "big")
                off = 10
            masked = b[1] & 0x80 != 0
            if masked:
                off += 4
            if len(b) != off + claimed:
                failures.append("CF: encode(%s, %s) len %d != header %d" % (f, side, len(b), off + claimed))

    # P6: RSV1 placement (RFC 7692 6.1): RSV1 is legal exactly on the first
    # data frame of a compressed message. From IDLE an RSV1 data frame must
    # never trip an RSV1-placement fault (it may still complete with its
    # own fault -- dec-utf8, dec-size, decompress-fail); from every other
    # non-terminal state, every RSV1 frame fails the connection.
    rsv1_starts = [n for n in D.FRAME_NAMES
                   if D.FRAMES[n]["rsv1"] == 1 and D.FRAMES[n]["op"] in (1, 2)]
    rsv1_ctrl = ["rsv1ctrl"]
    rsv1_cont = ["ccontR"]
    for f in rsv1_starts:
        _, _, _, fault = D.trans(D.IDLE, f)
        if fault in ("rsv1-nonfirst", "rsv1-control"):
            failures.append("P6: IDLE + %s (RSV1 start) tripped placement fault %s" % (f, fault))
    for s in D.STATES:
        if s in (D.IDLE, D.TERM):
            continue
        for f in rsv1_starts + rsv1_ctrl + rsv1_cont:
            to, _, _, _ = D.trans(s, f)
            if to != D.TERM:
                failures.append("P6: %s + %s (RSV1) -> %s, want TERM" % (s, f, to))

    # P7: no plain-domain leak.
    plain_frames = [n for n in D.FRAME_NAMES if D.FRAMES[n]["rsv1"] == 0 and D.FRAMES[n]["op"] in (0, 1, 2)]
    for s in ([D.IDLE] + D.FGB + D.FGT):
        for f in plain_frames:
            to, _, _, _ = D.trans(s, f)
            if to in D.CFB or to in D.CFT:
                failures.append("P7: %s + %s (plain frame) -> %s (a compressed state)" % (s, f, to))

    # P8: sticky compressed context (including the poisoned and
    # pending-41 states).
    cont_frames = [n for n in D.FRAME_NAMES if D.FRAMES[n]["rsv1"] == 0 and D.FRAMES[n]["op"] == 0]
    for s in D.CFB + D.CFT + D.POISON_STATES + D.P41_STATES:
        for f in cont_frames:
            to, _, _, _ = D.trans(s, f)
            if (to in D.FGB or to in D.FGT):
                failures.append("P8: %s + %s (continuation) -> %s (a plain state)" % (s, f, to))

    # RX: reachability audit. Every boundary-machine state is exercised by
    # a reachable compressed text fragment state -- the RSV1 machine
    # reaches the shared boundary machine's FULL state space (the
    # compressed domain's mid-rune chunks are what make the narrow
    # acceptance sets live, unlike the reassembly machine's alphabet,
    # whose reachable projection is exactly {CLEAN, BROKEN}).
    seen = {D.IDLE}
    stack = [D.IDLE]
    while stack:
        s = stack.pop()
        for f in D.FRAME_NAMES:
            to = D.trans(s, f)[0]
            if to == D.TERM or to in seen:
                continue
            seen.add(to)
            stack.append(to)
    # RX: reachability audit. The reachable set is exactly the one the
    # alphabet can build under the wire limit -- pinned below, state by
    # state, with the boundary suffixes each (wire, decompressed) pair
    # reaches.
    #
    # Plain domain: every count 0..MAXMSG in binary, and the text counts
    # reach exactly the projection {CLEAN, BROKEN} (BROKEN from count 1
    # up -- an empty fragment cannot be broken): the plain alphabet has
    # no lead-byte start frames, so the boundary machine's narrow pending
    # states are unreachable here (as in the reassembly machine, whose
    # P6 pins the same projection).
    for n in range(D.MAXMSG + 1):
        if ("FGB%d" % n) not in seen:
            failures.append("RX: FGB%d unreachable" % n)
    for s in D.FGT:
        m = s[3:]
        count, sfx = m[0], m[1:]
        want = (sfx == "" and 0 <= int(count) <= D.MAXMSG) or (sfx == "B" and 1 <= int(count) <= D.MAXMSG)
        if (s in seen) != want:
            failures.append("RX: FGT %s reachability wrong" % s)
    #
    # Compressed domain: the pairs the alphabet cannot build (no 4-byte
    # binary start, no 1-byte two-token frame, no decompressed count 3+ in
    # a 6-byte wire budget) are in the table for totality (their
    # transitions must still be defined) but unreachable.
    cfb_want = {"CFB2_0", "CFB3_1", "CFB5_1", "CFB5_7", "CFB6_2"}
    cft_want = {
        "CFT2_0": ("",),
        "CFT3_1": ("", "B", "W", "E0", "P3", "ED", "F0", "P4", "F4"),
        "CFT4_2": ("K2",),
        "CFT5_1": ("", "B", "W"),
        "CFT5_7": ("",),
        "CFT6_2": ("", "B", "W", "K2"),
    }
    for s in D.CFB:
        if (s in seen) != (s in cfb_want):
            failures.append("RX: CFB %s reachability wrong" % s)
    for s in D.CFT:
        mode, w, d, boundary = D.cparse_frag(s)
        want = D.C.BOUND_SUFFIX[boundary] in cft_want.get("CFT%d_%d" % (w, d), ())
        if (s in seen) != want:
            failures.append("RX: CFT %s reachability wrong" % s)
    #
    # The pending-41 and poisoned states: reachable exactly as the wire
    # budget allows (the 1-byte 0x41 from a reachable pair; the 2-byte
    # poison frame or a 0x41-in-pending from the right wire counts).
    p41b_want = {(3, 0), (4, 1), (6, 1), (6, 7)}
    p41t_want = {
        "3_0": ("",),
        "4_1": ("", "B", "W", "E0", "P3", "ED", "F0", "P4", "F4"),
        "5_2": ("K2",),
        "6_1": ("", "B", "W"),
        "6_7": ("",),
    }
    for s in D.P41_STATES:
        mode, w, d, boundary = D.cparse_p41(s)
        if mode == "binary":
            want = (w, d) in p41b_want
        else:
            want = D.C.BOUND_SUFFIX[boundary] in p41t_want.get("%d_%d" % (w, d), ())
        if (s in seen) != want:
            failures.append("RX: P41 %s reachability wrong" % s)
    for s in D.POISON_STATES:
        if s not in seen:
            failures.append("RX: %s unreachable" % s)

    if failures:
        for line in failures:
            print("FAIL", line, file=sys.stderr)
        sys.exit("deflate model check failed (%d)" % len(failures))
    print("deflate model check: P1, P2, P6, P7, P8, RX, completeness, encoding all pass "
          "(%d states x %d frames, %d reachable)" % (len(D.STATES), len(D.FRAME_NAMES), len(seen)))


if __name__ == "__main__":
    main()
