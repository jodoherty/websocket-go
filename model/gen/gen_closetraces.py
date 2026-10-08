"""Generate minimal close-handshake trace artifacts from the machine.

For each target transition (STATE, SHAPE) over the three RFC states (OPEN,
CLOSING, CLOSED) and all 17 body shapes:
  1. cross-check reachability against the independent nuXmv encoding of the
     same model: the property G !( (prev_state=STATE) & (shape=SHAPE) ) must be
     violated (the transition must be reachable), else the two encodings
     disagree and generation fails;
  2. encode the peer's Close frame to concrete bytes for both sides;
  3. emit one JSON trace per side, carrying the model's expected outcomes
     (the MUST/SHOULD/MAY wire, the resolution, the disposition).

OPEN traces start on a live connection. CLOSING and CLOSED traces first close
with initCode (a write, reaching the RFC's CLOSING/CLOSED state), then feed the
peer's Close. The JSON traces are committed to ws/testdata/closehandshake/ and
replayed by ws/mbt_close_test.go. Regeneration is deterministic;
`make close-mbt-gen` fails if the committed traces would change.
"""

import json
import os
import subprocess
import sys
import tempfile

import closehandshake as C
import gen_closemodel as M

CONTAINER = os.environ.get("MBT_IMAGE", "websocket-go-model:latest")

# The code we initiate the closing handshake with for CLOSING / CLOSED traces:
# a normal 1000, so the implementation's own sent code (what it resolves to if
# it does not read the peer's Close) is a clean, normal value.
INIT_CODE = 1000


def targets():
    """Every (state, shape) transition, over the three RFC states."""
    return [(s, f) for s in C.STATES for f in C.FRAME_NAMES]


def tid_of(state, shape):
    return "T_%s_%s" % (state, shape)


def citations(state, shape):
    _, _, rfc = C.close_trans(state, shape)
    return [rfc] if rfc and rfc != "terminal-absorbing" else []


def build_trace(tid, state, shape, side):
    a = C.close_assertions(state, shape)
    init = None if state == C.OPEN else INIT_CODE
    return {
        "id": "%s_%s" % (tid, side),
        "machine": "closehandshake",
        "side": side,
        "state": state,
        "shape": shape,
        "initCode": init,
        "desc": "transition (%s, %s)" % (state, shape),
        "rfc": citations(state, shape),
        "frames": [C.encode_close(shape, side).hex()],
        "resolution": a["resolution"],
        "disposition": a["disposition"],
        "outcomes": a["outcomes"],
    }


def crosscheck_reachability(targets_):
    """Verify, with the independent nuXmv encoding, that every target
    transition is reachable. Returns {tid: reachable_bool}."""
    models = tempfile.mkdtemp(prefix="close_xc_")
    for state, shape in targets_:
        name = tid_of(state, shape)
        with open(os.path.join(models, name + ".smv"), "w") as fh:
            fh.write(M.emit_model() + "\n" + M.emit_target_property(state, shape))
    script = "for f in /src/models/*.smv; do printf 'check_ltl\\nexit\\n' | nuXmv \"$f\" > \"$f.out\" 2>&1; done"
    proc = subprocess.run(
        ["podman", "run", "--rm", "-v", models + ":/src/models:Z", CONTAINER, "sh", "-c", script],
        capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit("nuXmv cross-check failed to run: %s" % proc.stderr.decode())
    result = {}
    for state, shape in targets_:
        name = tid_of(state, shape)
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
    for state, shape in targets_:
        name = tid_of(state, shape)
        if not reach.get(name, True):
            sys.exit("model disagreement: (%s,%s) not reachable in nuXmv" % (state, shape))
        for side in ("server", "client"):
            tr = build_trace(name, state, shape, side)
            with open(os.path.join(outdir, tr["id"] + ".json"), "w") as fh:
                json.dump(tr, fh, indent=2, sort_keys=True)
                fh.write("\n")
            count += 1
    print("generated %d traces" % count, file=sys.stderr)


if __name__ == "__main__":
    main()
