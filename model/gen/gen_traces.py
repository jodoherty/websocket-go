"""Generate minimal trace artifacts from the frame-reassembly machine.

For each target transition (FROM, FRAME):
  1. compute the minimal frame sequence that fires the transition by BFS over
     the machine's non-terminal states (common.trans is the transition
     function, so the traces are derived from the formal model);
  2. replay the sequence through common.trans to compute the expected
     ReadEvent results (message payload reconstructed);
  3. cross-check reachability against the independent nuXmv encoding of the
     same model: the property G !( (prev_asm=FROM) & (fr=FRAME) ) must be
     violated (the transition must be reachable), else the two encodings
     disagree and generation fails;
  4. encode each frame to concrete bytes for both sides; emit one JSON trace
     per side.

The JSON traces are committed to ws/testdata/mbt/ and replayed by
ws/mbt_test.go. Regeneration is deterministic; `make mbt-gen` fails if the
committed traces would change.
"""

import json
import os
import subprocess
import sys
import tempfile
from collections import deque

import common as C
import gen_model as M

CONTAINER = os.environ.get("MBT_IMAGE", "websocket-go-model:latest")


def targets():
    """The observable (FROM, FRAME) transitions to generate traces for.

    Every frame from IDLE (all single-frame behaviors), plus the meaningful
    fragment-state transitions. Non-observable fragment-accumulation steps
    are filtered out (they are pinned as prefixes of the completion traces).
    """
    t = [(C.IDLE, f) for f in C.FRAME_NAMES]
    frag = [
        ("FGB1", ["cont0", "cont1", "cont02", "cont12", "ping", "pong", "text1", "bin0", "close1000", "close999"]),
        ("FGB2", ["cont1", "cont02", "cont0", "close1000"]),
        ("FGB3", ["cont0", "cont1"]),
        ("FGT1", ["cont0", "cont1", "contff", "cont12", "ping", "text1"]),
        ("FGT2", ["cont0", "contff", "cont1"]),
        ("FGT3", ["cont0", "cont1"]),
        ("FGT1B", ["cont0", "cont1", "contff"]),
        ("FGT2B", ["cont1", "cont0"]),
        ("FGT3B", ["cont1"]),
    ]
    for s, frames in frag:
        for f in frames:
            t.append((s, f))
    return [p for p in t if is_observable(p[0], p[1])]


def tid_of(from_state, frame):
    return "T_%s_%s" % (from_state, frame)


def minimal_prefix(from_state):
    """The shortest frame sequence that drives the machine from IDLE to
    from_state (staying non-terminal), or None if unreachable."""
    if from_state == C.IDLE:
        return []
    if from_state == C.TERM:
        return None
    parent = {C.IDLE: None}
    q = deque([C.IDLE])
    while q:
        s = q.popleft()
        if s == from_state:
            break
        for f in C.FRAME_NAMES:
            to, _, _, _ = C.trans(s, f)
            if to == C.TERM or to not in C.STATES:
                continue
            if to in parent:
                continue
            parent[to] = (s, f)
            q.append(to)
    if from_state not in parent:
        return None
    path = []
    cur = from_state
    while parent[cur] is not None:
        prev, f = parent[cur]
        path.append(f)
        cur = prev
    path.reverse()
    return path


def frames_for(from_state, frame):
    """Minimal frame sequence that fires the transition (from_state, frame)."""
    prefix = minimal_prefix(from_state)
    if prefix is None:
        return None
    return prefix + [frame]


def is_observable(from_state, frame):
    """A transition is observable if it yields a ReadEvent result or the
    machine SHOULD transmit a close frame. Non-observable fragment
    accumulation transitions are still exercised (and their accumulation is
    pinned) as prefixes of the completion traces, so they need no dedicated
    trace."""
    _, emits, _, _ = C.trans(from_state, frame)
    if emits:
        return True
    return C.should_close(from_state, frame) != 0


def citations(frames):
    state = C.IDLE
    out = []
    for f in frames:
        _, _, rfc, _ = C.trans(state, f)
        if rfc and rfc != "terminal-absorbing" and rfc not in out:
            out.append(rfc)
        state = C.trans(state, f)[0]
        if state == C.TERM:
            break
    return out


def build_trace(tid, from_state, frame, frames, side):
    a = C.trace_assertions(frames)
    return {
        "id": "%s_%s" % (tid, side),
        "machine": "reassembly",
        "side": side,
        "maxMessageSize": C.MAXMSG,
        "fromState": from_state,
        "frame": frame,
        "desc": "transition (%s, %s); frames: %s" % (from_state, frame, ", ".join(frames)),
        "rfc": citations(frames),
        "frames": [C.encode_frame(f, side).hex() for f in frames],
        "events": a["events"],
        "terminal": a["terminal"],
    }


def crosscheck_reachability(targets_):
    """Verify, with the independent nuXmv encoding, that every target
    transition is reachable. Returns {tid: reachable_bool}."""
    models = tempfile.mkdtemp(prefix="mbt_xc_")
    for from_state, frame in targets_:
        name = tid_of(from_state, frame)
        with open(os.path.join(models, name + ".smv"), "w") as fh:
            fh.write(M.emit_model() + "\n" + M.emit_target_property(from_state, frame))
    script = "for f in /src/models/*.smv; do printf 'check_ltl\\nexit\\n' | nuXmv \"$f\" > \"$f.out\" 2>&1; done"
    proc = subprocess.run(
        ["podman", "run", "--rm", "-v", models + ":/src/models:Z", CONTAINER, "sh", "-c", script],
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit("nuXmv cross-check failed to run: %s" % proc.stderr.decode())
    result = {}
    for from_state, frame in targets_:
        name = tid_of(from_state, frame)
        out = os.path.join(models, name + ".smv.out")
        raw = open(out).read() if os.path.exists(out) else ""
        # reachable iff the property G!(hit) is violated ("is false").
        result[name] = "is false" in raw
    return result


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    targets_ = targets()

    print("cross-checking reachability with nuXmv ...", file=sys.stderr)
    reach = crosscheck_reachability(targets_)

    count = 0
    for from_state, frame in targets_:
        name = tid_of(from_state, frame)
        frames = frames_for(from_state, frame)
        if frames is None:
            if reach.get(name, False):
                sys.exit("model disagreement: (%s,%s) unreachable in Python but reachable in nuXmv" % (from_state, frame))
            print("SKIP %s: unreachable" % name, file=sys.stderr)
            continue
        if not reach.get(name, True):
            sys.exit("model disagreement: (%s,%s) reachable in Python but unreachable in nuXmv" % (from_state, frame))
        for side in ("server", "client"):
            tr = build_trace(name, from_state, frame, frames, side)
            with open(os.path.join(outdir, tr["id"] + ".json"), "w") as fh:
                json.dump(tr, fh, indent=2, sort_keys=True)
                fh.write("\n")
            count += 1
    print("generated %d traces" % count, file=sys.stderr)


if __name__ == "__main__":
    main()
