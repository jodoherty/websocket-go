"""Trace <-> model consistency check, pure Python.

Run by `make model`. Verifies that every committed trace in ws/testdata/mbt/
is a faithful artifact of the model:

  * each frame's concrete bytes match the model's encoding for exactly one
    frame class on that side (no hand-edited or stale bytes);
  * replaying the frame classes through common.trans reproduces the recorded
    expected ReadEvent results;
  * the recorded wireClose matches the model's transmitted close code.

This catches hand-edited traces and model drift (common.py changed without a
regeneration). It needs no container -- only the model and the traces.
"""

import json
import os
import sys

import common as C


def frame_lookup(side):
    """Map concrete bytes (hex) -> frame class name, for one side."""
    m = {}
    for f in C.FRAME_NAMES:
        m[C.encode_frame(f, side).hex()] = f
    return m


def check_trace(tr):
    """Replay a trace through the model; return (ok, message)."""
    side = tr["side"]
    lookup = frame_lookup(side)
    frames = []
    for h in tr["frames"]:
        if h not in lookup:
            return False, "frame %x not a model frame on %s" % (int(h, 16), side)
        frames.append(lookup[h])
    a = C.trace_assertions(frames)
    if a["events"] != tr.get("events"):
        return False, "events %r != recorded %r" % (a["events"], tr.get("events"))
    if a["terminal"] != tr.get("terminal"):
        return False, "terminal %r != recorded %r" % (a["terminal"], tr.get("terminal"))
    return True, ""


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    trace_dir = os.path.join(root, "ws", "testdata", "mbt")
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
        sys.exit("trace check failed (%d of %d)" % (len(failures), count))
    print("trace check: %d traces consistent with the model" % count)


if __name__ == "__main__":
    main()
