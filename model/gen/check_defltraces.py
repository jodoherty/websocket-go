"""Trace <-> model consistency check for the RSV1 / compressed-message
machine, pure Python.

Run by `make deflate-model`. Verifies that every committed trace in
ws/testdata/deflate/ is a faithful artifact of the model:

  * each frame's concrete bytes match the model's encoding for exactly one
    frame class on that side (no hand-edited or stale bytes; W5 in
    deflate.self_check guarantees the lookup is unambiguous);
  * replaying the frame classes through deflate.trans reproduces the
    recorded expected ReadEvent results (the delivered payload is the
    decompressed concatenation for compressed messages);
  * the recorded terminal outcomes match the model's.

This catches hand-edited traces and model drift (deflate.py changed
without a regeneration). It needs no container -- only the model and the
traces.
"""

import json
import os
import sys

import deflate as D


def frame_lookup(side):
    """Map concrete bytes (hex) -> frame class name, for one side.
    W5 (deflate.self_check) guarantees no two classes collide, so the
    lookup is unambiguous."""
    m = {}
    for f in D.FRAME_NAMES:
        m[D.encode(f, side).hex()] = f
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
    a = D.trace_assertions(frames)
    if a["events"] != tr.get("events"):
        return False, "events %r != recorded %r" % (a["events"], tr.get("events"))
    if a["terminal"] != tr.get("terminal"):
        return False, "terminal %r != recorded %r" % (a["terminal"], tr.get("terminal"))
    return True, ""


def main():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    trace_dir = os.path.join(root, "ws", "testdata", "deflate")
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
        sys.exit("deflate trace check failed (%d of %d)" % (len(failures), count))
    print("deflate trace check: %d traces consistent with the model" % count)


if __name__ == "__main__":
    main()
