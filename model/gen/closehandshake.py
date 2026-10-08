"""The close-handshake machine: RFC 6455 transformation, pure-RFC.

This module is the careful transformation of RFC 6455's close-handshake into an
explicit state machine. It is the authoritative source for the close-handshake
nuXmv model (gen_closemodel.py), the expected-outcome annotations on the close
traces (gen_closetraces.py), and the concrete wire encoding of each close frame
(encode_close).

Everything here is derived from the RFC, not from ws/ws.go. The states are the
RFC's own (Section 7.1.1-7.1.4): OPEN (no Close sent or received), CLOSING (we
have sent a Close, so the closing handshake is started, 7.1.3), and CLOSED
(the transport is gone, 7.1.4). For each (state, close-body-shape) the model
records the RFC's required outcome:

  * the WIRE -- the Close frame the endpoint MUST/SHOULD/MAY send in response
    (Section 5.5.1 for the echo and its code; Section 7.4 for which codes may
    appear on the wire; Section 7.1.7 for the 1002 on a protocol failure);
  * the RESOLUTION -- the WebSocket Connection Close Code (Section 7.1.5);
  * the DISPOSITION -- whether the closure is clean (the handshake completed)
    or a failure (Section 7.1.4 / 7.1.7).

The implementation is the target this validates, never the source of these
rules. Where the implementation deviates, the divergence is a finding the
suite surfaces (a MUST failure, or a counted SHOULD/MAY), not something baked
in here.
"""

# RFC 6455 7.1.1-7.1.4: the connection states.
OPEN = "OPEN"      # no Close sent or received
CLOSING = "CLOSING"  # we have sent a Close; the closing handshake is started (7.1.3)
CLOSED = "CLOSED"    # the transport is closed (7.1.4); absorbing
STATES = [OPEN, CLOSING, CLOSED]

# RFC 6455 7.4 / 7.4.1 / 7.4.2: the status-code rules.
CLOSE_MIN = 1000
CLOSE_MAX = 4999
MUST_NOT_SET = {1004, 1005, 1006, 1015}  # 7.4: MUST NOT be set on the wire
CODE_NO_STATUS = 1005  # 7.1.5: a Close with no status resolves to 1005
CODE_PROTOCOL = 1002   # 7.4: protocol error -- the 7.1.7 SHOULD code

# The peer's close-frame alphabet: one symbolic frame per body shape. The value
# is the concrete Close-frame BODY bytes (the "Application data" portion,
# Section 5.5.1); the frame header (opcode 0x8, FIN, RSV, mask) comes from
# encode_close.
CLOSE_FRAMES = {
    # well-formed closes: empty body (no status) or a usable code + reason
    "close1000": b"\x03\xe8",      # 1000, no reason
    "close1000r": b"\x03\xe8\x6f",  # 1000, reason "o"
    "close1001": b"\x03\xe9",      # 1001 (going away)
    "close1002": b"\x03\xea",      # 1002 (protocol error, received legitimately)
    "close1007": b"\x03\xef",      # 1007 (invalid data type)
    "close1009": b"\x03\xf1",      # 1009 (message too big)
    "close3000": b"\x0b\xb8",      # 3000 (library/framework range)
    "close4999": b"\x13\x87",      # 4999 (private-use range, max)
    "closeempty": b"",             # no body -> 1005 (7.1.5)
    # close-code faults (Section 7.4 / 5.5.1 / 8.1)
    "close1004": b"\x03\xec",      # 1004: reserved -> must-not-set
    "close1005w": b"\x03\xed",     # 1005: MUST NOT be set on the wire
    "close1006w": b"\x03\xee",     # 1006: MUST NOT be set on the wire
    "close1015w": b"\x03\xf7",     # 1015: MUST NOT be set on the wire
    "close0000": b"\x00\x00",      # 0: below 1000 (7.4.2: not used)
    "close5000": b"\x13\x88",      # 5000: above 4999 (7.4.2: undefined)
    "close1byte": b"\x03",         # one-byte body: no 2-byte code (5.5.1)
    "closebadutf8": b"\x03\xe8\xff",  # 1000 + non-UTF-8 reason (8.1)
}
FRAME_NAMES = sorted(CLOSE_FRAMES)


def _utf8(b):
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def classify(shape):
    """RFC 6455 5.5.1 + 7.4 + 8.1: is this Close body well-formed?

    Returns ("valid", code) where code is the Connection Close Code per 7.1.5
    (the received code, or 1005 for a body-less Close), or ("invalid", reason)
    naming the violated rule. The check order mirrors the receiver's obligation
    order: the body must carry a 2-byte code (5.5.1), the code must be a usable
    status (7.4), and the reason must be UTF-8 (8.1).
    """
    body = CLOSE_FRAMES[shape]
    if len(body) == 0:
        return "valid", CODE_NO_STATUS  # 7.1.5: no status received
    if len(body) == 1:
        return "invalid", "onebyte"  # 5.5.1: first two bytes MUST be a code
    code = int.from_bytes(body[:2], "big")
    if code < CLOSE_MIN or code > CLOSE_MAX:
        return "invalid", "range"  # 7.4.2: 0-999 unused, >4999 undefined
    if code in MUST_NOT_SET:
        return "invalid", "mustnotset"  # 7.4: MUST NOT be set
    if not _utf8(body[2:]):
        return "invalid", "utf8"  # 8.1
    return "valid", code


def resolution(state, shape):
    """The WebSocket Connection Close Code (7.1.5) the model expects.

    For a well-formed Close it is the code in the first Close received (1005 if
    that Close carried no status). For an invalid Close the connection is failed
    (7.1.7), and the code reported is 1002 -- never the peer's invalid code,
    which MUST NOT be echoed (7.4) or is undefined (7.4.2). In CLOSING the
    expected code is the peer's (the first Close received); the implementation
    resolving to its own sent code instead is the 7.1.2 finding the suite
    surfaces, not a value this model bakes in.
    """
    if state == CLOSED:
        return None  # the connection is already closed; no further resolution
    kind, code = classify(shape)
    return code if kind == "valid" else CODE_PROTOCOL


def wire_expected(state, shape):
    """The Close frame the RFC says the endpoint should send in response.

    Returns a dict: {"kind": none|empty|coded, "code": int|None,
    "must": bool, "echo_should": bool, "may_omit": bool}.

      * must        -- the very act of sending (or not) a response Close is a
                       MUST (5.5.1: a received Close, when we have not already
                       sent one, MUST be answered; 7.4: a must-not-set code
                       MUST NOT be put on the wire).
      * echo_should -- the response Close should carry the received status code
                       (5.5.1: "the endpoint typically echos the status code it
                       received").
      * may_omit    -- the response Close MAY be omitted (7.1.7: on a protocol
                       failure the frame MAY be left out if the peer is unlikely
                       to process it).
    """
    kind, code = classify(shape)
    if state == CLOSED:
        # The transport is already closed: no Close frame is (or can be) sent.
        return dict(kind="none", code=None, must=True, echo_should=False, may_omit=False)
    if state == CLOSING:
        # We already sent a Close, so the 5.5.1 MUST-to-answer does not apply:
        # a second Close frame is not expected (and would be a protocol error
        # after a Close). The response frame is therefore absent.
        return dict(kind="none", code=None, must=True, echo_should=False, may_omit=False)
    # state == OPEN
    if kind == "valid":
        if code == CODE_NO_STATUS:
            # Answer with a Close that carries NO status: 1005 resolves the
            # closure but MUST NOT be set on the wire (7.4), so the body is empty.
            return dict(kind="empty", code=None, must=True, echo_should=False, may_omit=False)
        return dict(kind="coded", code=code, must=True, echo_should=True, may_omit=False)
    # invalid Close: fail the connection (7.1.7). The SHOULD is to send 1002;
    # the frame MAY be omitted.
    return dict(kind="coded", code=CODE_PROTOCOL, must=False, echo_should=False,
                may_omit=True)


def disposition(state, shape):
    """The RFC closure class: 'clean' (the handshake completed) or 'failed'
    (the connection was failed on a protocol error, 7.1.7)."""
    if state == CLOSED:
        return "clean"  # already closed; absorbing
    kind, _ = classify(shape)
    return "clean" if kind == "valid" else "failed"


def outcomes(state, shape):
    """The RFC's permitted outcome(s) for (state, shape), as a list of dicts.

    Most (state, shape) pairs have one outcome; OPEN on an invalid Close has two
    (the SHOULD -- send the 1002 frame -- and the MAY -- omit it). Each dict:
      wire, code, disposition, resolution, mod, id, note.
    mod is 'must' (a hard invariant), 'should' (the RFC recommendation -- a
    MAY-permitted alternative is a counted warning), or 'may' (a permitted
    deviation).
    """
    disp = disposition(state, shape)
    res = resolution(state, shape)
    w = wire_expected(state, shape)

    def one(wire, code, mod, ident, note):
        return dict(wire=wire, code=code, disposition=disp, resolution=res,
                    mod=mod, id=ident, note=note)

    if state == CLOSED:
        return [one("none", None, "must", None,
                    "7.1.4: CLOSED is absorbing -- a received Close is not processed")]
    if state == CLOSING:
        # No second Close frame (5.5.1); the closure is clean and its code is
        # the peer's (7.1.5) once both have been sent and received (7.1.2).
        if w["kind"] == "none":
            return [one("none", None, "should", "SHOULD:close-712",
                        "5.5.1 no second Close; 7.1.2: SHOULD close once both sent and "
                        "received, resolving to the first Close received (7.1.5)")]
    # state == OPEN
    kind, code = classify(shape)
    if kind == "valid":
        if code == CODE_NO_STATUS:
            return [one("empty", None, "must", None,
                        "5.5.1 MUST answer; 7.4: 1005 resolves but MUST NOT be set")]
        return [one("coded", code, "must", None,
                    "5.5.1 MUST answer, SHOULD echo the received code (7.4)")]
    # OPEN + invalid Close: SHOULD send 1002, MAY omit; MUST NOT echo the bad code.
    return [
        one("coded", CODE_PROTOCOL, "should", "SHOULD:close-717",
            "7.1.7 SHOULD send a Close with the protocol-error code 1002"),
        one("none", None, "may", "MAY:close-omit",
            "7.1.7 MAY omit the Close if the peer is unlikely to process it"),
    ]


# RFC citation per fault (used for trace annotation).
FAULT_RFC = {
    "onebyte": "RFC 6455 5.5.1",
    "range": "RFC 6455 7.4.2",
    "mustnotset": "RFC 6455 7.4",
    "utf8": "RFC 6455 8.1",
}


def close_trans(state, shape):
    """One close step of the machine: (to_state, outcomes, rfc).

    OPEN on a well-formed Close answers it and the connection closes; OPEN on
    an invalid Close fails (7.1.7). CLOSING on any Close does not send a second
    frame and the connection closes. CLOSED is absorbing.

    Why OPEN on a valid Close lands in CLOSED and not CLOSING: receiving the
    Close starts the handshake (7.1.3, so the connection passes through
    CLOSING), 5.5.1 requires the answer, and once both frames have been
    exchanged 5.5.1 says the endpoint "considers the WebSocket connection
    closed and MUST close the underlying TCP connection" -- which is 7.1.4's
    CLOSED. CLOSING is therefore transient in the responding case: it is
    entered and left inside one step. CLOSING is observable only in the
    initiating case, where this endpoint sent its Close first and is waiting.
    """
    if state == CLOSED:
        return CLOSED, outcomes(CLOSED, shape), "terminal-absorbing"
    kind, _ = classify(shape)
    if state == OPEN:
        rfc = "RFC 6455 5.5.1, 7.4" if kind == "valid" else FAULT_RFC[classify(shape)[1]]
        return CLOSED, outcomes(OPEN, shape), rfc
    # CLOSING
    return CLOSED, outcomes(CLOSING, shape), "RFC 6455 5.5.1, 7.1.2"


# --- Concrete wire encoding -------------------------------------------------

# A fixed, deterministic mask key so generated traces are reproducible.
_MASK_KEY = b"\x01\x02\x03\x04"


def encode_close(shape, side):
    """The concrete bytes for a close frame on the given side.

    side is the side UNDER TEST ('server' or 'client'). The peer's frames are
    masked exactly when the side under test is the server (RFC 6455 5.1: clients
    mask, servers do not). The frame is a single, FIN-set, opcode-0x8 frame with
    a short length form (every close body here is <= 125 bytes).
    """
    payload = CLOSE_FRAMES[shape]
    should_mask = side == "server"  # peer is the client
    plen = len(payload)
    b0 = 0x88  # FIN=1, opcode=0x8
    b1 = (should_mask << 7) | plen  # all bodies here are <= 125
    out = bytearray([b0, b1])
    if should_mask:
        out += _MASK_KEY
        out += bytes(payload[i] ^ _MASK_KEY[i % 4] for i in range(plen))
    else:
        out += payload
    return bytes(out)


# --- Trace assertions -------------------------------------------------------

def close_assertions(state, shape):
    """The trace assertions for a (state, shape) close step: the modeled
    outcome(s) and the resolution the model expects. The runner drives the
    implementation and checks the observed wire and resolution against these."""
    return dict(
        state=state,
        shape=shape,
        resolution=resolution(state, shape),
        disposition=disposition(state, shape),
        outcomes=outcomes(state, shape),
    )
