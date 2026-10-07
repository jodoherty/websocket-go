"""The frame-reassembly machine: RFC 6455 transformation, single source of truth.

This module is the careful transformation of the RFC 6455 read path into an
explicit state machine. It is the authoritative source for three artifacts:

  * the nuXmv model (gen_model.py emits the SMV transition function),
  * the expected-outcome annotations on generated traces (gen_traces.py),
  * the concrete wire encoding of each symbolic frame (encode_frame).

Everything here is derived from the RFC, not from ws/ws.go. The check order
inside a single frame mirrors the receiver's obligation order: header
validation first (RFC 6455 Section 5.2, 5.5), then the message-level rules
(Section 5.4, 5.5, 5.6), then close resolution (Section 5.5.1, 7.4). A frame
that trips a header check never reaches the message-level rules.

The payload is symbolic (token count, not raw bytes) for the model; the
concrete byte encoding lives in encode_frame and is side-dependent (the mask
bit flips with which side is under test).
"""

MAXMSG = 3  # abstract message size limit, in token units (concrete: bytes)
C_TERM = "TERM"  # forward ref used by wire_close before the state list

# Assembler states. IDLE: not in a message. FGB: accumulating a binary
# fragment, subscript = token count so far (1..MAXMSG). FGT / FGT..B:
# accumulating a text fragment, subscript = count, optional B suffix = the
# accumulated bytes so far are not valid UTF-8 (RFC 6455 5.6 checks the
# whole message, so a fragment must remember whether it is already broken).
# TERM: terminal.
IDLE = "IDLE"
FGB = ["FGB1", "FGB2", "FGB3"]
FGT = ["FGT1", "FGT2", "FGT3"]
FGTB = ["FGT1B", "FGT2B", "FGT3B"]
TERM = "TERM"
STATES = [IDLE] + FGB + FGT + FGTB + [TERM]

# Frame classes: the peer's alphabet. Each is a symbolic frame; the concrete
# wire bytes come from encode_frame. Fields: op (opcode), fin, rsv1, rsv23
# (RSV2 set), maskok (masking correct for the side), lenform (short/16/64),
# plen (payload length in token units), payload (concrete payload bytes),
# and fault (which check it is designed to trip, or None if well-formed).
FRAMES = {
    # well-formed data / continuation
    "text1":  dict(op=1, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault=None),
    "bin0":   dict(op=2, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault=None),
    "bin02":  dict(op=2, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=2, payload=b"\x41\x42", fault=None),
    "text0":  dict(op=1, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault=None),
    "text0ff": dict(op=1, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\xff", fault=None),
    "cont0":  dict(op=0, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault=None),
    "cont02": dict(op=0, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=2, payload=b"\x41\x42", fault=None),
    "cont1":  dict(op=0, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault=None),
    "cont12": dict(op=0, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=2, payload=b"\x41\x42", fault=None),
    "contff": dict(op=0, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\xff", fault=None),
    "textbad":  dict(op=1, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\xff", fault=None),
    # well-formed controls
    "ping":    dict(op=9,  fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=0, payload=b"", fault=None),
    "ping1":   dict(op=9,  fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault=None),
    "pong":    dict(op=10, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=0, payload=b"", fault=None),
    # well-formed closes
    "close1000":  dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=2, payload=b"\x03\xe8", fault=None),
    "close1000r": dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=3, payload=b"\x03\xe8\x6f", fault=None),
    "close3000":  dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=3, payload=b"\x0b\xb8\x72", fault=None),
    "closeempty": dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=0, payload=b"", fault=None),
    # close-code faults
    "close999":    dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=2, payload=b"\x03\xe7", fault="close-unusable-code"),
    "close1005":   dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=2, payload=b"\x03\xed", fault="close-mustnotset"),
    "close1byte":  dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x00", fault="close-onebyte"),
    "closebadutf8": dict(op=8, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=3, payload=b"\x03\xe8\xff", fault="close-bad-utf8"),
    # header / opcode faults (trip from any state)
    "badop":       dict(op=3, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=0, payload=b"", fault="reserved-opcode"),
    "rsv1":        dict(op=1, fin=1, rsv1=1, rsv23=0, maskok=1, lenform="short", plen=1, payload=b"\x41", fault="rsv1-unnegotiated"),
    "rsv23":       dict(op=2, fin=1, rsv1=0, rsv23=1, maskok=1, lenform="short", plen=0, payload=b"", fault="rsv23-set"),
    "maskbad":     dict(op=1, fin=1, rsv1=0, rsv23=0, maskok=0, lenform="short", plen=1, payload=b"\x41", fault="mask-violation"),
    "len16nonmin": dict(op=1, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="16", plen=100, payload=b"\x41" * 100, fault="nonminimal-16"),
    "len64nonmin": dict(op=1, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="64", plen=1000, payload=b"\x41" * 1000, fault="nonminimal-64"),
    "ping0":       dict(op=9, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=0, payload=b"", fault="control-not-fin"),
    "pingbig":     dict(op=9, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="16", plen=200, payload=b"\x41" * 200, fault="control-too-big"),
    "big":         dict(op=2, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=4, payload=b"\x41" * 4, fault="frame-too-big"),
    # transport end (not a frame)
    "eof":         dict(op=-1, fin=0, rsv1=0, rsv23=0, maskok=1, lenform="short", plen=0, payload=b"", fault="eof"),
}

FRAME_NAMES = sorted(FRAMES)

# Frames that trip a header/opcode check and therefore fail the connection
# from any non-terminal state, before message-level rules are reached.
ANY_STATE_1002 = {
    "badop", "rsv1", "rsv23", "maskbad",
    "len16nonmin", "len64nonmin", "ping0", "pingbig", "big",
}

# RFC citation per fault (used for trace annotation and STATES.md).
FAULT_RFC = {
    "close-unusable-code": "RFC 6455 7.4",
    "close-mustnotset": "RFC 6455 7.4",
    "close-onebyte": "RFC 6455 5.5.1",
    "close-bad-utf8": "RFC 6455 7.1.5, 8.1",
    "reserved-opcode": "RFC 6455 5.5",
    "rsv1-unnegotiated": "RFC 7692 6",
    "rsv23-set": "RFC 6455 5.2",
    "mask-violation": "RFC 6455 5.1",
    "nonminimal-16": "RFC 6455 5.2",
    "nonminimal-64": "RFC 6455 5.2",
    "control-not-fin": "RFC 6455 5.5",
    "control-too-big": "RFC 6455 5.5",
    "frame-too-big": "RFC 6455 5.5",
    "eof": "RFC 6455 7.1.5",
    "cont-without-start": "RFC 6455 5.4",
    "data-while-infrag": "RFC 6455 5.4",
    "cross-frame-too-big": "RFC 6455 5.5",
    "utf8-invalid": "RFC 6455 5.6",
}


def should_close(state, frame):
    """The close code that SHOULD be on the wire for this frame step.

    This is the RFC 6455 7.1.7 SHOULD: an endpoint failing the connection
    SHOULD send a Close frame with an appropriate status code. It is the
    target the conformance layer measures against; a peer (or this
    implementation) MAY omit the frame entirely (see terminal_outcomes),
    which is recorded as a warning to be assessed, not a MUST failure.

    The code is always a usable code (1000-4999, minus must-not-set) or the
    protocol-error 1002 / invalid-data 1007 -- never an echoed unusable code,
    never 1005/1006/1015, and never outside 1000-4999. Property P1 asserts
    this over every (state, frame).
    """
    if state == C_TERM:
        return 0
    if frame in ANY_STATE_1002:
        return 1002
    if frame == "eof":
        return 0  # transport gone; no close frame can be written
    if frame in ("ping", "ping1", "pong"):
        return 0
    if frame.startswith("close"):
        if frame in ("close1000", "close1000r"):
            return 1000
        if frame == "close3000":
            return 3000
        if frame == "closeempty":
            return 0  # 1005 is resolved but MUST NOT be set on the wire
        return 1002  # unusable / must-not-set / one-byte / bad-utf8
    # data / continuation
    _, _, _, fault = trans(state, frame)
    if fault == "utf8-invalid":
        return 1007
    # Every other fault (header, close-code, message-level) SHOULD carry 1002.
    # Message-level violations currently omit the frame entirely, but that is
    # a MAY (7.1.7), so the SHOULD target stays 1002 and the omission is a
    # counted warning, not a MUST violation.
    if fault is not None:
        return 1002
    return 0


def frag_count(state):
    """Token count accumulated in a fragment state, else 0."""
    if state in FGB or state in FGT or state in FGTB:
        return int(state.rstrip("B")[-1])
    return 0


def frag_op(state):
    return "binary" if state in FGB else ("text" if state in FGT or state in FGTB else None)


def frag_bad(state):
    """True when a text fragment's accumulated bytes are not valid UTF-8."""
    return state in FGTB


def _bump(state, add, bad):
    """Advance a fragment state by `add` tokens, or None if it overflows.

    `bad` is True when the incoming frame's payload is not valid UTF-8; for
    text fragments the broken flag is sticky.
    """
    is_text = state in FGT or state in FGTB
    c = frag_count(state) + add
    if c > MAXMSG:
        return None
    if state in FGB:
        return "FGB%d" % c
    was_bad = state in FGTB
    if is_text and (was_bad or bad):
        return "FGT%dB" % c
    return "FGT%d" % c


def payload_bad(frame):
    """True when the frame's payload is not valid UTF-8."""
    return not _utf8(FRAMES[frame]["payload"])


def trans(state, frame):
    """One frame step of the machine.

    Returns (to_state, emits, rfc, fault) where emits is the list of
    ReadEvent results produced by processing this frame (empty when
    ReadEvent keeps accumulating a fragment), rfc is the citation(s), and
    fault names the rule that fired (None for well-formed steps).
    """
    if state == TERM:
        return TERM, [], "terminal-absorbing", None

    f = FRAMES[frame]

    # Header / opcode checks: fire from any state, before message rules.
    if frame in ANY_STATE_1002:
        return TERM, [term(1002)], FAULT_RFC[f["fault"]], f["fault"]

    if frame == "eof":
        return TERM, [term(1006)], FAULT_RFC["eof"], "eof"

    # Well-formed controls: interleaved with fragments, which are preserved.
    if frame in ("ping", "ping1", "pong"):
        op = "ping" if frame in ("ping", "ping1") else "pong"
        to = IDLE if state == IDLE else state
        return to, [ctrl(op, f["payload"])], "RFC 6455 5.5", None

    # Close frames: resolve the peer's close (Section 5.5.1, 7.4).
    if frame.startswith("close"):
        return _close(state, frame)

    # Data / continuation frames (Section 5.4, 5.5, 5.6).
    return _data(state, frame)


def _close(state, frame):
    if frame == "close1000":
        return TERM, [close(1000, ""), term_eof()], "RFC 6455 5.5.1, 7.4", None
    if frame == "close1000r":
        return TERM, [close(1000, "o"), term_eof()], "RFC 6455 5.5.1, 7.4", None
    if frame == "close3000":
        return TERM, [close(3000, "r"), term_code(3000)], "RFC 6455 5.5.1, 7.4", None
    if frame == "closeempty":
        # No status received: 1005, which is never transmitted on the wire.
        return TERM, [close(1005, ""), term_eof()], "RFC 6455 5.5.1, 7.4", None
    # Unusable / must-not-set code, one-byte payload, or non-UTF-8 reason:
    # failed with 1002 and never echoed.
    return TERM, [term(1002)], FAULT_RFC[FRAMES[frame]["fault"]], FRAMES[frame]["fault"]


def _data(state, frame):
    f = FRAMES[frame]
    is_cont = f["op"] == 0
    in_frag = state in FGB or state in FGT or state in FGTB

    # A data frame (text/binary) may not arrive while a fragment is in
    # progress; a continuation may not arrive with no fragment in progress.
    # Both are message-level violations: torn down with no close frame.
    if is_cont and not in_frag:
        return TERM, [term_proto()], FAULT_RFC["cont-without-start"], "cont-without-start"
    if not is_cont and in_frag:
        return TERM, [term_proto()], FAULT_RFC["data-while-infrag"], "data-while-infrag"

    # Continuation with RSV1 is a permessage-deflate misuse (RFC 7692 6);
    # with no extension negotiated it is caught earlier by the rsv1 header
    # check, so it is not a separate transition here.

    if in_frag:
        to = _bump(state, f["plen"], payload_bad(frame))
        if to is None:
            return TERM, [term_proto()], FAULT_RFC["cross-frame-too-big"], "cross-frame-too-big"
        if not f["fin"]:
            return to, [], "RFC 6455 5.4", None
        # Final fragment: the message completes. RFC 6455 5.6 validates the
        # whole (concatenated) text message, so a text fragment that is
        # already broken -- or is broken by this final fragment -- fails
        # with 1007.
        if frag_op(state) == "text" and frag_bad(to):
            return TERM, [term(1007)], FAULT_RFC["utf8-invalid"], "utf8-invalid"
        return IDLE, [msg(frag_op(state), _frag_payload(state, frame))], "RFC 6455 5.4", None

    # Not in a fragment: this frame starts a multi-frame message.
    if not f["fin"]:
        if f["plen"] > MAXMSG:
            return TERM, [term(1002)], FAULT_RFC["frame-too-big"], "frame-too-big"
        if f["op"] == 1:
            if payload_bad(frame):
                return "FGT%dB" % f["plen"], [], "RFC 6455 5.4", None
            return "FGT%d" % f["plen"], [], "RFC 6455 5.4", None
        return "FGB%d" % f["plen"], [], "RFC 6455 5.4", None

    # Single-frame message (fin=1, not in a fragment).
    op = "text" if f["op"] == 1 else "binary"
    if op == "text" and not _utf8(f["payload"]):
        return TERM, [term(1007)], FAULT_RFC["utf8-invalid"], "utf8-invalid"
    return IDLE, [msg(op, f["payload"])], "RFC 6455 5.5", None


def _frag_payload(state, frame):
    """Concatenated payload of a completed fragment (symbolic hex)."""
    # For the pilot, the accumulated payload is the start payload plus the
    # continuation payloads; the concrete bytes are rebuilt by the runner
    # from the frame bytes, so here we only track validity / length.
    return b""


def _utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# --- Concrete wire encoding -------------------------------------------------

# A fixed, deterministic mask key so generated traces are reproducible.
_MASK_KEY = b"\x01\x02\x03\x04"


def encode_frame(frame_name, side):
    """The concrete bytes for a symbolic frame on the given side.

    side is the side UNDER TEST ('server' or 'client'). The peer's frames
    are masked exactly when the side under test is the server (RFC 6455
    5.1: clients mask, servers do not). 'eof' encodes to the empty byte
    string (transport end, no frame).
    """
    f = FRAMES[frame_name]
    if frame_name == "eof":
        return b""

    b0 = f["op"]
    if f["fin"]:
        b0 |= 0x80
    if f["rsv1"]:
        b0 |= 0x40
    if f["rsv23"]:
        b0 |= 0x20

    should_mask = side == "server"  # peer is the client
    actual_mask = should_mask if f["maskok"] else (1 - should_mask)

    payload = f["payload"]
    plen = len(payload)
    b1 = (actual_mask << 7)
    out = bytearray([b0])
    if f["lenform"] == "short":
        b1 |= plen
        out.append(b1)
    elif f["lenform"] == "16":
        b1 |= 126
        out.append(b1)
        out += plen.to_bytes(2, "big")
    else:  # "64"
        b1 |= 127
        out.append(b1)
        out += plen.to_bytes(8, "big")

    if actual_mask:
        out += _MASK_KEY
        out += bytes(payload[i] ^ _MASK_KEY[i % 4] for i in range(plen))
    else:
        out += payload
    return bytes(out)


# --- ReadEvent result constructors (dicts serialized into the JSON traces) ---

def msg(op, payload):
    return {"t": "event", "kind": "msg", "op": op}


def ctrl(op, payload):
    return {"t": "event", "kind": "ctrl", "op": op}


def close(code, reason):
    return {"t": "event", "kind": "close", "code": code, "reason": reason}


def term(code):
    return {"t": "terminal", "code": code}


def term_proto():
    # A message-level protocol violation (continuation without start, a data
    # frame while a fragment is in progress, a cross-frame size overflow) is
    # answered by tearing the connection down with NO close frame: the
    # terminal error is the raw protocol error, not a *CloseError. (Header
    # violations, by contrast, are answered with a 1002 close frame.)
    return {"t": "terminal", "proto": True}


def term_eof():
    return {"t": "terminal", "eof": True}


def term_code(code):
    return {"t": "terminal", "code": code}


# --- Conformance assertions (the MUST / SHOULD / MAY layer) -----------------

# The assessable warning the pilot tracks: a protocol violation where the RFC
# 6455 7.1.7 SHOULD Close frame was not sent (the impl invoked the MAY and
# tore the connection down bare). One ID groups every trace that would fire
# it, so a regression back to a bare teardown is a single countable, assessable
# signal. ws.go now sends the 1002 frame on every protocol violation, so it
# does not fire today.
MAY_OMIT_ID = "MAY:close-frame-omitted"
MAY_OMIT_NOTE = ("RFC 6455 7.1.7 MAY: omit the Close frame when the error "
                 "corrupts message state (the peer is unlikely to receive and "
                 "process it). The implementation sends the SHOULD 1002 frame "
                 "on these violations instead, uniform with header-level; a "
                 "regression to a bare teardown would warn under this ID.")
SHOULD_NOTE = ("RFC 6455 7.1.7 SHOULD: send a Close frame with an "
               "appropriate status code before closing the connection")


def _out(wire, term, mod, code=None, wid=None, note=""):
    """One close-frame outcome. wire is 'none' (no frame), 'empty' (a close
    frame with no code), or an int (a close frame carrying that code)."""
    d = {"term": term, "mod": mod}
    if wire == "none":
        d["wire"] = {"kind": "none"}
    elif wire == "empty":
        d["wire"] = {"kind": "empty"}
    else:
        d["wire"] = {"kind": "coded", "code": wire}
    if code is not None:
        d["code"] = code
    if wid:
        d["id"] = wid
        d["note"] = note
    return d


def terminal_outcomes(state, frame):
    """The SHOULD/MAY/MUST close-frame outcomes for a terminal step.

    MUST outcomes are hard (a mismatch fails the test). A SHOULD outcome is
    the RFC's recommended behavior (meeting it raises no warning; a
    MAY-permitted alternative is a counted, assessable warning). For a
    protocol violation the model offers both the SHOULD (send the frame) and
    the MAY (omit it): which one fires is what the implementation actually
    does, and invoking the MAY is the warning we track.
    """
    to, _, _, fault = trans(state, frame)
    if to != TERM:
        return []
    if frame == "eof":
        # A transport end with no close frame from the peer is an abnormal
        # closure: the terminal is the 1006 close error, and no close frame
        # can be written back (RFC 6455 7.1.5).
        return [_out("none", "closeErr", "must", code=1006)]
    if frame in ("ping", "ping1", "pong"):
        return []  # controls do not terminate the connection
    if frame.startswith("close") and fault is None:
        # A well-formed close: MUST resolve it and reply. The reply frame is
        # the close-handshake machine's concern; here we pin the resolved
        # terminal and the delivered close event.
        if frame in ("close1000", "close1000r"):
            return [_out(1000, "eof", "must")]
        if frame == "close3000":
            return [_out(3000, "closeErr", "must", code=3000)]
        if frame == "closeempty":
            # 1005 resolves to no status; the reply carries an empty frame.
            return [_out("empty", "eof", "must")]
    # A protocol violation: SHOULD send the close frame, MAY omit it.
    code = should_close(state, frame)
    return [
        _out(code, "closeErr", "should", code=code, note=SHOULD_NOTE),
        _out("none", "proto", "may", wid=MAY_OMIT_ID, note=MAY_OMIT_NOTE),
    ]


def trace_assertions(frames):
    """Replay a frame sequence; return the trace assertions for the final
    (target) step: {"events": [...], "terminal": None | {"outcomes": [...]}}.

    events are the MUST-delivered ReadEvent results (msg/ctrl/close), with the
    message payload reconstructed (a single-frame message carries its own
    payload; a fragmented message carries the concatenation of all its
    fragments, RFC 6455 5.4). The prefix frames drive the machine to the
    target state and are non-observable (fragment accumulation, no events),
    so only the target step contributes events.
    """
    state = IDLE
    acc = b""
    for f in frames[:-1]:
        fr = FRAMES[f]
        was_frag = state in FGB or state in FGT or state in FGTB
        if was_frag:
            acc += fr["payload"]
        to, _, _, _ = trans(state, f)
        if (not was_frag) and (to in FGB or to in FGT or to in FGTB):
            acc = fr["payload"]  # started a multi-frame message
        state = to

    f = frames[-1]
    fr = FRAMES[f]
    was_frag = state in FGB or state in FGT or state in FGTB
    if was_frag:
        acc += fr["payload"]
    to, emits, _, _ = trans(state, f)

    events = []
    for e in emits:
        if e["t"] != "event":
            continue
        e = dict(e)
        if e.get("kind") == "msg":
            e["payload"] = (acc if was_frag else fr["payload"]).hex()
        events.append(e)

    terminal = None
    if to == TERM:
        terminal = {"outcomes": terminal_outcomes(state, f)}
    return {"events": events, "terminal": terminal}
