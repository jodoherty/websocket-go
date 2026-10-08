"""Emit the nuXmv (SMV) model of the close-handshake machine.

Derived entirely from closehandshake.close_trans, so the formal model and the
expected-outcome annotations on the traces share one source of truth.

State variables (VAR):
  state      connection state after the last processed Close (OPEN/CLOSING/
             CLOSED, RFC 6455 7.1.1-7.1.4)
  prev_state connection state before the last processed Close
  step       Close frames the peer has sent so far (0..BUDGET)

Input variables (IVAR):
  shape      the body shape of the Close the peer sends at the current step.
             Input variables cannot be assigned, so `shape` is nondeterministic
             -- it is the peer's free choice, and the model explores every
             Close script.
  initiate   whether this endpoint starts the closing handshake at this step
             (RFC 6455 7.1.2: send a Close control frame). This is the one
             transition not driven by a frame arriving: 7.1.3 puts the
             connection in CLOSING on *sending* as well as receiving, so
             without this input CLOSING would be unreachable and the whole
             initiating half of the handshake unmodelled.

The transition is closehandshake.close_trans: OPEN on a well-formed Close
answers it and closes; OPEN on an invalid Close fails to CLOSED; CLOSING sends
no second frame and closes; CLOSED is absorbing. Receiving a Close wins over a
simultaneous initiation, which is the both-sides-close-at-once case of 7.1.5.

For a target transition (FROM, SHAPE) the property
    G !( (prev_state = FROM) & (shape = SHAPE) )
is violated exactly when that transition fires; the counterexample is a minimal
Close script that reaches it. That is the systematic-trace mechanism.
"""

import closehandshake as C

BUDGET = 4
NONE = "NONE"


def emit_model():
    L = []
    a = L.append
    a("MODULE main")
    a("")
    a("VAR")
    a("  state      : { %s };" % ", ".join(C.STATES))
    a("  prev_state : { %s };" % ", ".join(C.STATES))
    a("  step       : 0..%d;" % BUDGET)
    a("")
    a("IVAR")
    a("  shape    : { %s };" % ", ".join(C.FRAME_NAMES + [NONE]))
    a("  initiate : { YES, NO };")
    a("")
    a("ASSIGN")
    a("  init(state)      := %s;" % C.OPEN)
    a("  init(prev_state) := %s;" % C.OPEN)
    a("  init(step)       := 0;")
    a("")
    a("  next(step) := case")
    a("    step < %d : step + 1;" % BUDGET)
    a("    TRUE      : step;")
    a("  esac;")
    a("")
    a("  next(prev_state) := state;")
    a("")
    a("  next(state) := case")
    a("    step >= %d : state;" % BUDGET)
    for s in C.STATES:
        for f in C.FRAME_NAMES:
            to, _, _ = C.close_trans(s, f)
            a("    state=%s & shape=%s : %s;" % (s, f, to))
    # 7.1.2/7.1.3: sending our own Close starts the handshake and puts the
    # connection in CLOSING, where it waits for the peer's answer.
    a("    state=%s & initiate=YES : %s;" % (C.OPEN, C.CLOSING))
    a("    TRUE : state;")
    a("  esac;")
    a("")
    return "\n".join(L)


def emit_target_property(from_state, shape):
    """Violated exactly when the transition (from_state, shape) fires."""
    return "LTLSPEC G !( (prev_state = %s) & (shape = %s) );\n" % (from_state, shape)


def emit_properties():
    """Self-consistency properties the model must SATISFY (the proof layer).

    P2: CLOSED is absorbing: once the transport is closed, the state never
    leaves it.
    """
    return "LTLSPEC G ( state = %s -> X( state = %s ) );\n" % (C.CLOSED, C.CLOSED)


if __name__ == "__main__":
    print(emit_model())
    print()
    print(emit_properties())
