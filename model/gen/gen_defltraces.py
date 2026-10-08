"""Generate minimal trace artifacts from the RSV1 / compressed-message
machine.

For each target transition (FROM, FRAME):
  1. compute the minimal frame sequence that fires the transition by BFS
     over the machine's non-terminal states (deflate.trans is the
     transition function, so the traces are derived from the formal
     model);
  2. replay the sequence through deflate.trans to compute the expected
     ReadEvent results (message payload reconstructed: plain messages
     carry the concatenation of their frames' payloads, compressed
     messages the concatenation of their frames' DECOMPRESSED chunks);
  3. cross-check reachability against the independent nuXmv encoding of
     the same model: the property G !( (prev_asm=FROM) & (fr=FRAME) )
     must be violated (the transition must be reachable), else the two
     encodings disagree and generation fails;
  4. encode each frame to concrete bytes for both sides; emit one JSON
     trace per side.

The JSON traces are committed to ws/testdata/deflate/ and replayed by
ws/mbt_deflate_test.go. Regeneration is deterministic; `make defl-gen`
fails if the committed traces would change.
"""

import json
import os
import subprocess
import sys
import tempfile
from collections import deque

import deflate as D
import gen_defmodel as M

CONTAINER = os.environ.get("MBT_IMAGE", "websocket-go-model:latest")


def targets():
    """The observable (FROM, FRAME) transitions to generate traces for.

    Every frame from IDLE (all single-frame behaviors: plain messages,
    compressed messages, every fault class, eof), plus the meaningful
    fragment-state transitions in both domains. Non-observable
    fragment-accumulation steps are filtered out (they are pinned as
    prefixes of the completion traces).
    """
    t = [(D.IDLE, f) for f in D.FRAME_NAMES]
    frag = [
        # Plain domain (limit 6): the count axis and the UTF-8 axis.
        ("FGB0", ["cont0", "cont1", "cont02", "cont12", "cont0e", "cont1e", "ping", "pong", "text1", "bin0", "close1000", "close999"]),
        ("FGB1", ["cont0", "cont1", "cont02", "cont12", "cont0e", "cont1e", "ping", "pong", "text1", "bin0", "close1000", "close999"]),
        ("FGB2", ["cont1", "cont02", "cont0", "cont0e", "cont1e", "close1000"]),
        ("FGB3", ["cont0", "cont1", "cont0e", "cont1e"]),
        ("FGB4", ["cont1", "cont0", "cont0e"]),
        ("FGB5", ["cont0", "cont1"]),
        ("FGB6", ["cont0", "cont1"]),
        ("FGT0", ["cont0", "cont1", "contff", "cont12", "cont0e", "cont1e", "ping", "text1"]),
        ("FGT1", ["cont0", "cont1", "contff", "cont12", "cont0e", "cont1e", "ping", "text1"]),
        ("FGT2", ["cont0", "contff", "cont1", "cont0e", "cont1e"]),
        ("FGT3", ["cont0", "cont1", "cont0e", "cont1e"]),
        ("FGT4", ["cont0", "cont1", "cont0e"]),
        ("FGT5", ["cont0", "cont1"]),
        ("FGT6", ["cont0", "cont1"]),
        ("FGT1B", ["cont0", "cont1", "contff", "cont0e", "cont1e"]),
        ("FGT2B", ["cont1", "cont0", "cont0e", "cont1e"]),
        ("FGT1W", ["cont1", "contff", "cont0e"]),
        ("FGT1E0", ["cont1", "contff"]),
        # Compressed domain: completion (delivery, decompressed UTF-8,
        # decompression failure, decompressed size), the WIRE cross-frame
        # fault (per-frame, before decompression), RSV1 placement, the
        # accidental plain-continuation semantics (including the poison
        # path via cont02), and context control. State names are the
        # (wire, decompressed) pairs.
        ("CFB2_0", ["cont1e", "cont1", "ccontA1", "ccontAB1", "ccont1bomb", "contff", "cont02", "cont0", "ping", "pong", "close1000", "ctext1", "rsv1ctrl", "ccontR"]),
        ("CFB3_1", ["cont1", "cont1e", "ccontA1", "ccontAB1", "ccont1bomb", "contff", "cont02", "cont0"]),
        ("CFB5_1", ["cont1", "cont1e", "ccontA1", "contff"]),
        ("CFB5_7", ["cont1", "cont1e", "ccontA1", "contff", "cont0"]),
        ("CFB6_2", ["cont1", "cont1e", "contff"]),
        ("CFB_P4", ["cont1e", "cont1", "contff", "ccontA1", "cont0"]),
        ("CFB_P5", ["cont1e", "cont1", "cont0"]),
        ("CFB_P6", ["cont1e", "cont1", "contff"]),
        ("CFB_P41_3_0", ["cont1e", "cont1", "ccontA1", "cont0"]),
        ("CFB_P41_4_1", ["cont1e", "cont1", "cont02", "ccontA1"]),
        ("CFB_P41_6_1", ["cont1e", "cont1"]),
        ("CFB_P41_6_7", ["cont1e", "cont1"]),
        ("CFT2_0", ["cont1e", "cont1", "ccontA1", "ccontAB1", "ccontC31", "ccont891", "ccont1bomb", "contff", "cont02", "cont0", "ping", "ctext1", "rsv1ctrl", "ccontR"]),
        ("CFT3_1", ["cont1", "cont1e", "ccontA1", "ccontC31", "ccont891", "ccontAB1", "ccont1bomb", "contff", "cont02", "cont0"]),
        ("CFT3_1W", ["ccont891", "ccontC31", "ccontA1", "contff", "cont0"]),
        ("CFT3_1E0", ["ccont891", "ccontA1", "contff"]),
        ("CFT3_1P3", ["ccontA1", "ccontC31", "contff"]),
        ("CFT3_1ED", ["ccont891", "ccontA1", "contff"]),
        ("CFT3_1F0", ["ccont891", "ccontA1", "contff"]),
        ("CFT3_1F4", ["ccont891", "ccontA1", "contff"]),
        ("CFT4_2K2", ["cont1", "cont1e", "ccontA1", "contff"]),
        ("CFT5_1", ["cont1", "ccontA1", "contff"]),
        ("CFT5_1B", ["cont1", "contff", "ccontA1"]),
        ("CFT5_1W", ["cont1", "contff", "ccontA1"]),
        ("CFT5_7", ["cont1", "cont1e", "ccontA1", "contff"]),
        ("CFT6_2", ["cont1", "cont1e", "ccontA1"]),
        ("CFT6_2B", ["cont1", "cont1e"]),
        ("CFT6_2W", ["cont1", "cont1e"]),
        ("CFT6_2K2", ["cont1", "cont1e"]),
        ("CFT_P4", ["cont1e", "cont1", "cont0", "ccontA1"]),
        ("CFT_P5", ["cont1e", "cont1"]),
        ("CFT_P6", ["cont1e", "cont1"]),
        ("CFT_P41_3_0", ["cont1e", "cont1", "ccontA1"]),
        ("CFT_P41_4_1W", ["cont1e", "cont1", "ccontA1"]),
        ("CFT_P41_4_1B", ["cont1e", "cont1"]),
        ("CFT_P41_5_2K2", ["cont1e", "cont1"]),
        ("CFT_P41_6_1W", ["cont1e", "cont1"]),
        ("CFT_P41_6_1", ["cont1e", "cont1"]),
        ("CFT_P41_6_7", ["cont1e", "cont1"]),
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
    if from_state == D.IDLE:
        return []
    if from_state == D.TERM:
        return None
    parent = {D.IDLE: None}
    q = deque([D.IDLE])
    while q:
        s = q.popleft()
        if s == from_state:
            break
        for f in D.FRAME_NAMES:
            to, _, _, _ = D.trans(s, f)
            if to == D.TERM or to not in D.STATES:
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
    accumulation transitions are still exercised (and their accumulation
    is pinned) as prefixes of the completion traces, so they need no
    dedicated trace."""
    _, emits, _, _ = D.trans(from_state, frame)
    if emits:
        return True
    return D.should_close(from_state, frame) != frozenset()


def citations(frames):
    state = D.IDLE
    out = []
    for f in frames:
        _, _, rfc, _ = D.trans(state, f)
        if rfc and rfc != "terminal-absorbing" and rfc not in out:
            out.append(rfc)
        state = D.trans(state, f)[0]
        if state == D.TERM:
            break
    return out


def build_trace(tid, from_state, frame, frames, side):
    a = D.trace_assertions(frames)
    return {
        "id": "%s_%s" % (tid, side),
        "machine": "rsv1",
        "side": side,
        "maxMessageSize": D.MAXMSG,
        "fromState": from_state,
        "frame": frame,
        "desc": "transition (%s, %s); frames: %s" % (from_state, frame, ", ".join(frames)),
        "rfc": citations(frames),
        "frames": [D.encode(f, side).hex() for f in frames],
        "events": a["events"],
        "terminal": a["terminal"],
    }


def reachable_closure(targets_):
    """The reachable states plus their one-step closure: the state space
    the cross-check model needs (see gen_defmodel.emit_model for why the
    full table is pruned and why the pruning is sound in both
    directions)."""
    reach = {D.IDLE}
    stack = [D.IDLE]
    while stack:
        s = stack.pop()
        for f in D.FRAME_NAMES:
            to = D.trans(s, f)[0]
            if to == D.TERM or to in reach:
                continue
            reach.add(to)
            stack.append(to)
    closure = set(reach) | {D.TERM}
    for s in reach:
        for f in D.FRAME_NAMES:
            closure.add(D.trans(s, f)[0])
    return [s for s in D.STATES if s in closure]


def crosscheck_reachability(targets_):
    """Verify, with the independent nuXmv encoding, that every target
    transition is reachable. Returns {tid: reachable_bool}."""
    states = reachable_closure(targets_)
    models = tempfile.mkdtemp(prefix="defl_xc_")
    for from_state, frame in targets_:
        name = tid_of(from_state, frame)
        with open(os.path.join(models, name + ".smv"), "w") as fh:
            fh.write(M.emit_model(states) + "\n" + M.emit_target_property(from_state, frame))
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
