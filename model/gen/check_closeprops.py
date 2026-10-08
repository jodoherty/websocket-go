"""Close-handshake model self-consistency checks, pure Python.

Run by `make close-props` (and `make model`). These validate the
close-handshake transition function (closehandshake.outcomes / close_trans)
independent of the implementation:

  P1  wire legitimacy: every outcome's wire close code is legitimate -- none,
      empty, or a usable code in 1000-4999 (1004/1005/1006/1015 excluded),
      never a must-not-set code, never an out-of-range code, never the peer's
      invalid code echoed onto the wire.
  P2  resolution legitimacy: every expected resolution is a usable code, or the
      7.1.5 no-status 1005, or the 7.1.7 protocol-error 1002 -- never a
      must-not-set or out-of-range code.
  P3  closed absorbing: CLOSED + shape stays CLOSED and sends no Close frame.
  P4  completeness: every (state, shape) has at least one defined outcome.
  P5  echo consistency: for OPEN on a well-formed Close, the expected wire
      echoes the received code (or is empty for 1005), and never carries a
      must-not-set code.

A failure here means the model (and the traces it generates) is wrong; fix
closehandshake.py, regenerate the traces, and re-run.
"""

import sys

import closehandshake as C


def legitimate_wire_code(code):
    if code is None:
        return True
    if code in (C.CODE_PROTOCOL, 1007):
        return True
    if C.CLOSE_MIN <= code <= C.CLOSE_MAX and code not in C.MUST_NOT_SET:
        return True
    return False


def legitimate_resolution(code):
    if code is None:
        return True
    if code in (C.CODE_NO_STATUS, C.CODE_PROTOCOL):
        return True
    if C.CLOSE_MIN <= code <= C.CLOSE_MAX and code not in C.MUST_NOT_SET:
        return True
    return False


def main():
    failures = []

    for s in C.STATES:
        for f in C.FRAME_NAMES:
            # P4: completeness -- a defined transition with >= 1 outcome.
            to, outs, _ = C.close_trans(s, f)
            if to not in C.STATES:
                failures.append("P4: close_trans(%s, %s) -> %r not a state" % (s, f, to))
            if not outs:
                failures.append("P4: close_trans(%s, %s) has no outcome" % (s, f))

            # P1: wire legitimacy, over every modeled outcome.
            for o in outs:
                if o["wire"] == "coded" and not legitimate_wire_code(o["code"]):
                    failures.append(
                        "P1: outcome(%s, %s) wire code %r illegitimate" % (s, f, o["code"]))
                if o["wire"] not in ("none", "empty", "coded"):
                    failures.append("P1: outcome(%s, %s) unknown wire %r" % (s, f, o["wire"]))

            # P2: resolution legitimacy.
            if not legitimate_resolution(C.resolution(s, f)):
                failures.append("P2: resolution(%s, %s) = %r illegitimate" % (s, f, C.resolution(s, f)))

            # P3: CLOSED absorbing.
            if s == C.CLOSED:
                if to != C.CLOSED:
                    failures.append("P3: CLOSED + %s -> %s (not absorbing)" % (f, to))
                for o in outs:
                    if o["wire"] != "none":
                        failures.append("P3: CLOSED + %s sends wire %r (expected none)" % (f, o["wire"]))

            # P5: OPEN on a well-formed Close echoes the received code (or is
            # empty for 1005), never a must-not-set code.
            if s == C.OPEN and C.classify(f)[0] == "valid":
                code = C.classify(f)[1]
                w = C.wire_expected(C.OPEN, f)
                if code == C.CODE_NO_STATUS:
                    if w["kind"] != "empty":
                        failures.append("P5: OPEN + %s expected empty wire, got %r" % (f, w["kind"]))
                else:
                    if w["kind"] != "coded" or w["code"] != code:
                        failures.append("P5: OPEN + %s expected coded %d, got %r" % (f, code, w))

            # The MUST NOT: an invalid Close is never echoed. The wire, if any,
            # is 1002 (or absent) -- never the peer's invalid code.
            if s == C.OPEN and C.classify(f)[0] == "invalid":
                bad = C.classify(f)
                if bad[1] == "mustnotset" or bad[1] == "range":
                    peer_code = int.from_bytes(C.CLOSE_FRAMES[f][:2], "big")
                    for o in outs:
                        if o["wire"] == "coded" and o["code"] == peer_code:
                            failures.append("P1: OPEN + %s echoes the peer's invalid code %d" % (f, peer_code))

    # P6: the invalid Close resolves to 1002, never the peer's invalid code.
    for f in C.FRAME_NAMES:
        if C.classify(f)[0] == "invalid":
            if C.resolution(C.OPEN, f) != C.CODE_PROTOCOL:
                failures.append("P6: OPEN + %s resolution %d != 1002" % (f, C.resolution(C.OPEN, f)))

    if failures:
        for line in failures:
            print("FAIL", line, file=sys.stderr)
        sys.exit("close model check failed (%d)" % len(failures))
    print("close model check: P1-P6 pass (%d states x %d shapes)"
          % (len(C.STATES), len(C.FRAME_NAMES)))


if __name__ == "__main__":
    main()
