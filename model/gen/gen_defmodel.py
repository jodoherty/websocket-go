"""Emit the nuXmv (SMV) model of the RSV1 / compressed-message machine.

Derived entirely from deflate.trans, so the formal model and the
expected-outcome annotations on the traces share one source of truth
(same pattern as gen_model.py for the reassembly machine).

State variables (VAR):
  asm       machine state after the last processed frame
  prev_asm  machine state before the last processed frame
  step      frames the peer has sent so far (0..BUDGET)

Input variable (IVAR):
  fr        the frame the peer sends at the current step. Input variables
            cannot be assigned, so `fr` is nondeterministic -- it is the
            peer's free choice, and the model explores every frame script.

`step` changes at every transition, so it is always printed in a trace;
the input `fr` is always printed (inputs are never elided); any elided
asm / prev_asm value is recovered by forward-fill from the initial state.

For a target transition (FROM, FRAME) the property
    G !( (prev_asm = FROM) & (fr = FRAME) )
is violated exactly when that transition fires; the counterexample is a
minimal frame script that reaches it. That is the systematic-trace
mechanism.
"""

import deflate as D

# The longest minimal prefix any target needs (the count-6 plain
# fragment states: start + five single-token continuations).
BUDGET = 6
NONE = "NONE"


def emit_model(states=None):
    """The SMV model of the machine.

    `states` restricts the model's state space to a subset; the cross-
    check uses the reachable states plus the one-step closure (the
    nuXmv BDD build of the transition relation is what the model check
    actually runs, and the full 239-state table over the 84-frame input
    segfaults it -- ~13k case rows is the threshold, the pruned model
    is ~7.5k). The pruning is sound in both directions for the target-
    reachability cross-check: every target is reachable, so every
    minimal prefix stays inside the reachable set, and any script the
    pruned model finds is also a script of the full model (same
    transition function on the same states)."""
    ss = states if states is not None else D.STATES
    L = []
    a = L.append
    a("MODULE main")
    a("")
    a("VAR")
    a("  asm      : { %s };" % ", ".join(ss))
    a("  prev_asm : { %s };" % ", ".join(ss))
    a("  step     : 0..%d;" % BUDGET)
    a("")
    a("IVAR")
    a("  fr : { %s };" % ", ".join(D.FRAME_NAMES + [NONE]))
    a("")
    a("ASSIGN")
    a("  init(asm)      := %s;" % D.IDLE)
    a("  init(prev_asm) := %s;" % D.IDLE)
    a("  init(step)     := 0;")
    a("")
    a("  next(step) := case")
    a("    step < %d : step + 1;" % BUDGET)
    a("    TRUE      : step;")
    a("  esac;")
    a("")
    a("  next(prev_asm) := asm;")
    a("")
    # next(asm) applies the machine's transition on the frame being sent.
    a("  next(asm) := case")
    a("    step >= %d : asm;" % BUDGET)
    for s in ss:
        for f in D.FRAME_NAMES:
            to, _, _, _ = D.trans(s, f)
            a("    asm=%s & fr=%s : %s;" % (s, f, to))
    a("    TRUE : asm;")
    a("  esac;")
    a("")
    return "\n".join(L)


def emit_target_property(from_state, frame):
    """Violated exactly when the transition (from_state, frame) fires."""
    return "LTLSPEC G !( (prev_asm = %s) & (fr = %s) );\n" % (from_state, frame)


def emit_properties():
    """Self-consistency property the model must SATISFY: P2, TERM
    absorbing. (The close-code legitimacy, RSV1 placement and
    domain-separation properties are checked exhaustively over the
    transition function in check_deflprops.py, since they are properties
    of the transition function rather than of reachability.)"""
    return "LTLSPEC G ( asm = %s -> X( asm = %s ) );\n" % (D.TERM, D.TERM)


if __name__ == "__main__":
    print(emit_model())
    print()
    print(emit_properties())
