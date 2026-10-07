"""Emit the nuXmv (SMV) model of the frame-reassembly machine.

Derived entirely from common.trans, so the formal model and the
expected-outcome annotations on the traces share one source of truth.

State variables (VAR):
  asm       assembler state after the last processed frame
  prev_asm  assembler state before the last processed frame
  step      frames the peer has sent so far (0..BUDGET)

Input variable (IVAR):
  fr        the frame the peer sends at the current step. Input variables
            cannot be assigned, so `fr` is nondeterministic -- it is the
            peer's free choice, and the model explores every frame script.

`step` changes at every transition, so it is always printed in a trace; the
input `fr` is always printed (inputs are never elided); any elided asm /
prev_asm value is recovered by forward-fill from the initial state.

For a target transition (FROM, FRAME) the property
    G !( (prev_asm = FROM) & (fr = FRAME) )
is violated exactly when that transition fires; the counterexample is a
minimal frame script that reaches it. That is the systematic-trace mechanism.
"""

import common as C

BUDGET = 4
NONE = "NONE"


def emit_model():
    L = []
    a = L.append
    a("MODULE main")
    a("")
    a("VAR")
    a("  asm      : { %s };" % ", ".join(C.STATES))
    a("  prev_asm : { %s };" % ", ".join(C.STATES))
    a("  step     : 0..%d;" % BUDGET)
    a("")
    a("IVAR")
    a("  fr : { %s };" % ", ".join(C.FRAME_NAMES + [NONE]))
    a("")
    a("ASSIGN")
    a("  init(asm)      := %s;" % C.IDLE)
    a("  init(prev_asm) := %s;" % C.IDLE)
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
    for s in C.STATES:
        for f in C.FRAME_NAMES:
            to, _, _, _ = C.trans(s, f)
            a("    asm=%s & fr=%s : %s;" % (s, f, to))
    a("    TRUE : asm;")
    a("  esac;")
    a("")
    return "\n".join(L)


def emit_target_property(from_state, frame):
    """Violated exactly when the transition (from_state, frame) fires."""
    return "LTLSPEC G !( (prev_asm = %s) & (fr = %s) );\n" % (from_state, frame)


def emit_properties():
    """Self-consistency properties the model must SATISFY (the proof layer).

    P2: TERM is absorbing: once terminal, the state never leaves it.

    (P1 -- the transmitted close code is always legitimate -- is checked
    exhaustively over every (state, frame) pair in check_props.py, since it
    is a property of the transition function rather than of reachability.)
    """
    return "LTLSPEC G ( asm = %s -> X( asm = %s ) );\n" % (C.TERM, C.TERM)


if __name__ == "__main__":
    print(emit_model())
    print()
    print(emit_properties())
