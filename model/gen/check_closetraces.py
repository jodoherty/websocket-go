"""Close-handshake trace <-> model consistency check, pure Python.

Run by `make close-model`. Verifies that every committed trace in
ws/testdata/closehandshake/ is a faithful artifact of the model:

  * each frame's concrete bytes match the model's encoding for exactly one
    close-body shape on that side (no hand-edited or stale bytes);
  * the recorded state/shape/initCode match a defined transition;
  * replaying the (state, shape) through closehandshake reproduces the
    recorded expected outcomes, resolution, and disposition.

This catches hand-edited traces and model drift (closehandshake.py changed
without a regeneration). It needs no container -- only the model and the
traces.
"""

import json
import os
import sys

import closehandshake as C


def frame_lookup(side):
    """Map concrete bytes (hex) -> close-body shape, for one side."""
    m = {}
    for f in C.FRAME_NAMES:
        m[C.encode_close(f, side).hex()] = f
    return m


def check_trace(tr):
    """Replay a trace through the model; return (ok, message)."""
    side = tr["side"]
    state = tr["state"]
    if state not in C.STATES:
        return False, "state %r not a model state" % state
    lookup = frame_lookup(side)
    if len(tr["frames"]) != 1:
        return False, "want exactly 1 frame, got %d" % len(tr["frames"])
    h = tr["frames"][0]
    if h not in lookup:
        return False, "frame %x not a model close frame on %s" % (int(h, 16), side)
    shape = lookup[h]
    if shape != tr["shape"]:
        return False, "frame decodes to %s, trace says %s" % (shape, tr["shape"])
    # initCode is set exactly for CLOSING/CLOSED.
    if (tr["initCode"] is None) != (state == C.OPEN):
        return False, "initCode presence does not match state %s" % state

    a = C.close_assertions(state, shape)
    if tr["resolution"] != a["resolution"]:
        return False, "resolution %r != model %r" % (tr["resolution"], a["resolution"])
    if tr["disposition"] != a["disposition"]:
        return False, "disposition %r != model %r" % (tr["disposition"], a["disposition"])
    if tr["outcomes"] != a["outcomes"]:
        return False, "outcomes %r != model %r" % (tr["outcomes"], a["outcomes"])
    return True, ""


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    trace_dir = os.path.join(root, "ws", "testdata", "closehandshake")
    if not os.path.isdir(trace_dir):
        sys.exit("trace dir %s not found" % trace_dir)

    failures = []
    count = 0
    for name in sorted(os.listdir(trace_dir)):
        if not name.endswith(".json") or name == "NOTES.json":
            continue
        count += 1
        with open(os.path.join(trace_dir, name)) as fh:
            tr = json.load(fh)
        ok, msg = check_trace(tr)
        if not ok:
            failures.append("%s: %s" % (tr["id"], msg))

    if failures:
        for line in failures:
            print("FAIL", line, file=sys.stderr)
        sys.exit("close trace check failed (%d of %d)" % (len(failures), count))
    print("close trace check: %d traces consistent with the model" % count)


if __name__ == "__main__":
    main()
