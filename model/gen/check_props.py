"""Model self-consistency checks (the proof layer), pure Python.

Run by `make model`. These validate the frame-reassembly transition function
(common.trans) independent of the implementation, on top of the shared UTF-8
boundary machine (utf8bound.py, checked by check_utf8props.py):

  P1  the close code the machine transmits is always legitimate -- 0 (no
      close frame), a usable code in 1000-4999 (1004/1005/1006/1015 excluded)
      resolved for a well-formed close, or the protocol-error 1002 /
      invalid-data 1007. An unusable or must-not-set peer code is never
      echoed onto the wire.
  P2  TERM is absorbing: once terminal, the state never leaves it.
  CX  completeness: every (state, frame) pair has a defined transition
      (the table is a total function -- a gap would be a silent omission).
  CF  the concrete encoding round-trips: each frame encodes to the byte
      length its header claims, on both sides.
  P6  projection: over this machine's alphabet, the boundary states reachable
      in text fragments are exactly {CLEAN, BROKEN} -- the legacy two-state
      B dimension is pinned as a sound projection of the shared boundary
      machine. Extending the alphabet with lead-byte payloads (mid-rune
      fragment ends) must extend this property deliberately, not silently.

A failure here means the model (and therefore the traces it generates) is
wrong; fix common.py, regenerate the traces, and re-run.
"""

import sys

import common as C
import utf8bound as U

MUST_NOT_SET = {1004, 1005, 1006, 1015}


def legitimate_wire_code(code):
    if code == 0:
        return True
    if code in (1002, 1007):
        return True
    if 1000 <= code <= 4999 and code not in MUST_NOT_SET:
        return True
    return False


def main():
    failures = []

    # CX: completeness.
    for s in C.STATES:
        for f in C.FRAME_NAMES:
            try:
                to, emits, rfc, fault = C.trans(s, f)
            except Exception as e:  # noqa: BLE001 - a gap must fail loudly
                failures.append("CX: trans(%s, %s) raised %r" % (s, f, e))
                continue
            if to not in C.STATES:
                failures.append("CX: trans(%s, %s) -> %r not a state" % (s, f, to))

    # P2: TERM absorbing.
    for f in C.FRAME_NAMES:
        to, _, _, _ = C.trans(C.TERM, f)
        if to != C.TERM:
            failures.append("P2: TERM + %s -> %s (not absorbing)" % (f, to))

    # P1: wire close code legitimacy (the SHOULD code, over every pair).
    for s in C.STATES:
        for f in C.FRAME_NAMES:
            wc = C.should_close(s, f)
            if not legitimate_wire_code(wc):
                failures.append("P1: should_close(%s, %s) = %d (illegitimate)" % (s, f, wc))

    # P1b: an unusable / must-not-set peer close code is failed with 1002,
    # never echoed.
    for f in ("close999", "close1005"):
        wc = C.should_close(C.IDLE, f)
        if wc != 1002:
            failures.append("P1b: should_close(IDLE, %s) = %d, want 1002" % (f, wc))
    # closeempty resolves 1005 but MUST NOT set it on the wire.
    if C.should_close(C.IDLE, "closeempty") != 0:
        failures.append("P1b: should_close(IDLE, closeempty) != 0 (1005 must not be set)")

    # P1c: every terminal close-frame outcome is legitimate -- the SHOULD
    # code or a MAY omission (no frame / empty frame), never an illegal code.
    for s in C.STATES:
        for f in C.FRAME_NAMES:
            for o in C.terminal_outcomes(s, f):
                w = o["wire"]
                if w["kind"] == "coded" and not legitimate_wire_code(w["code"]):
                    failures.append("P1c: terminal_outcomes(%s, %s) coded wire %d illegitimate" % (s, f, w["code"]))

    # CF: concrete encoding length round-trip.
    for f in C.FRAME_NAMES:
        if f == "eof":
            continue
        for side in ("server", "client"):
            b = C.encode_frame(f, side)
            # header claims a payload length; the frame must carry exactly it.
            form = C.FRAMES[f]["lenform"]
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

    # P6: projection -- over this alphabet, the boundary states reachable in
    # text fragments are exactly {CLEAN, BROKEN}: no fragment state can hold
    # a mid-rune pending boundary, so the legacy two-state B dimension (the
    # old FGT..B names) is a sound projection of the shared boundary machine.
    seen = {C.IDLE}
    stack = [C.IDLE]
    while stack:
        s = stack.pop()
        for f in C.FRAME_NAMES:
            to = C.trans(s, f)[0]
            if to == C.TERM or to in seen:
                continue
            seen.add(to)
            stack.append(to)
    bounds = set()
    for s in seen:
        if s in C.FGT:
            bounds.add(C.frag_boundary(s))
    if bounds != {U.CLEAN, U.BROKEN}:
        failures.append("P6: reachable text boundaries %r, want {CLEAN, BROKEN} "
                        "(alphabet extension needs a deliberate property update)" % sorted(bounds))

    if failures:
        for line in failures:
            print("FAIL", line, file=sys.stderr)
        sys.exit("model check failed (%d)" % len(failures))
    print("model check: P1, P2, P6, completeness, encoding all pass "
          "(%d states x %d frames)" % (len(C.STATES), len(C.FRAME_NAMES)))


if __name__ == "__main__":
    main()
