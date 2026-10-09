"""The RSV1 / compressed-message machine: RFC 7692 6 on top of RFC 6455 5.

This machine models the receiver side of a WebSocket connection on which
permessage-deflate is negotiated (RFC 7692 6: "On a WebSocket connection
where a PMCE is in use, this bit [RSV1] indicates whether a message is
compressed or not"). It is derived from the RFCs, not from any
implementation:

  * RFC 7692 6:  a message is compressed exactly when RSV1 is set on its
    first fragment; the frames of a compressed message carry compressed
    data, and the receiver decompresses the concatenation of the frames'
    compressed payloads (6.2) and uses the decompressed bytes for the
    message event, with the compressed bit unset.
  * RFC 7692 6.1: RSV1 MUST NOT be set on control frames or on non-first
    fragments of a data message; a receiver MUST fail the connection on
    such a frame. (The generic failure is RFC 6455 7.1.7: MUST close,
    SHOULD send a Close frame, MAY omit it.)
  * RFC 7692 6.1: the payload of a compressed frame is not subject to the
    original data type's constraints (a compressed text message's wire
    bytes need not be valid UTF-8); after decompression the payload is
    subject to them again -- so a compressed text message is checked
    against RFC 6455 5.6 on its decompressed bytes (1007).
  * RFC 6455 5: everything else -- header rules, continuation-without-start,
    data-while-in-fragment, close resolution -- applies unchanged to
    compressed traffic, and the plain (uncompressed) domain of a negotiated
    connection is this machine's plain domain, instantiated at its own
    limit.

What this machine deliberately does NOT model (scope, documented in
doc/DEFLATE-MACHINE.md):

  * The DEFLATE stream's internal structure (bit buffers, block headers,
    the LZ77 window). The machine's compressed frames declare their
    decompressed chunk symbolically; the wire bytes are concrete DEFLATE
    blocks verified by self_check against the decompression semantics.
    Splitting a stream mid-block across frames is the DEFLATE stream
    machine's concern (a follow-up); this machine's compressed messages
    use the RFC 7692 7.2.1 fragmentation in which every frame carries
    complete DEFLATE block(s) ("for non-final fragments, the removal of
    0x00 0x00 0xff 0xff MUST NOT be done").
  * The LZ77 sliding-window / context-takeover axis (7.1.1): the window
    content is unbounded state; this machine's traces run in per-message
    (no context takeover) mode, which the implementation negotiates.

The size limit is the project's maxMessageSize policy (not an RFC 6455
concept) instantiated at MAXMSG for this machine: large enough that a
representative multi-frame compressed message (three small DEFLATE
blocks) fits under the wire limit, small enough that a decompressed size
overflow stays an explicit alphabet class (the LZ77 bomb chunk), not an
arithmetic accident. The reassembly machine instantiates the same policy
at 3 (common.py); each machine picks its own instantiation because the
policy value is a model parameter, and the trace carries it
(maxMessageSize) so the concrete replay uses exactly the modeled limit.

The policy bounds BOTH axes of a compressed message, and the machine
tracks both: the wire payload (checked on every frame while accumulating,
before decompression -- a compressed fragment's wire bytes are bounded
exactly like a plain fragment's) and the DECOMPRESSED total (checked at
completion, when it is known). The compressed fragment states are the
(wire, decompressed) pairs the alphabet can accumulate under the wire
limit; the pair set is closed under the machine's non-fault transitions.
"""

import json
import os
import zlib

import common as C
import deflate_stream as DS
import utf8bound as U

MAXMSG = 6

IDLE = C.IDLE
TERM = C.TERM

# --- States -------------------------------------------------------------
#
# Plain domain (identical names to the reassembly machine, limit MAXMSG):
#   FGB{n}      accumulating a plain binary fragment, n wire tokens (0..MAXMSG)
#   FGT{n}<S>   accumulating a plain text fragment, n wire tokens, boundary
#               suffix S = the shared UTF-8 boundary machine's state
#
# Compressed domain (RFC 7692 6): a continuation frame that arrives while
# a compressed message is in progress carries compressed data even though
# its RSV1 bit is 0 (6.1 forbids RSV1 on non-first fragments); the
# compressed context is exactly what CFB/CFT track. The policy bounds both
# the accumulated WIRE payload (checked per frame, before decompression,
# as in the plain domain) and the DECOMPRESSED total (checked at
# completion), so a compressed fragment state is the (wire, decompressed)
# pair accumulated so far: CFB{w}_{d} / CFT{w}_{d}<S>, where d == MAXMSG+1
# is the saturating "already over the limit" mark (reached only by a
# single large decompressed chunk; the message cannot complete validly).
#
# The pair set is exactly the one the alphabet can accumulate under the
# wire limit (closed under the machine's non-fault transitions; every
# other accumulation is a wire cross-frame fault): the 2-byte empty
# block, the 3-byte one-token block, the 4-byte two-token block and the
# 5-byte bomb are the frame costs, and wire totals beyond the limit fault.
FGB = ["FGB%d" % n for n in range(MAXMSG + 1)]
FGT = [C.frag_state("text", n, b) for n in range(MAXMSG + 1) for b in U.STATES]

COMP_PAIRS = [
    (2, 0), (3, 0), (3, 1),
    (4, 0), (4, 1), (4, 2),
    (5, 0), (5, 1), (5, 2), (5, MAXMSG + 1),
    (6, 0), (6, 1), (6, 2), (6, MAXMSG + 1),
]
CFB = ["CFB%d_%d" % (w, d) for w, d in COMP_PAIRS]
CFT = ["CFT%d_%d%s" % (w, d, C.BOUND_SUFFIX[b]) for w, d in COMP_PAIRS for b in U.STATES]

# A poisoned compressed message: a non-final frame whose bytes cannot join
# any DEFLATE stream (the receiver's segment scan is left a stranded,
# uncomplete prefix). The accumulated bytes are undecodable for the rest of
# the message -- completion can only be a decompression failure -- but the
# receiver does not know that until it decompresses, at completion, and the
# per-frame WIRE check keeps applying in the meantime (a poisoned message
# that grows past the wire limit faults on the wire, not on the
# decompression). (Reachable via the accidental plain-continuation class
# cont02, whose two bytes leave a stranded trailing byte under the
# receiver's greedy scan; deterministic regardless of what follows, given
# this alphabet's self-contained frame streams. Poison wire is the
# start's wire (2-4) plus cont02's two bytes, so the reachable poisoned
# wire counts are exactly 4, 5 and 6 (a fate-bad non-final start would
# poison at the start's own wire, but no alphabet class does).
POISON_STATES = ["CFB_P%d" % w for w in (4, 5, 6)] + ["CFT_P%d" % w for w in (4, 5, 6)]


# The pending-41 states: the accidental 1-byte continuation (payload 0x41)
# is not a complete stream on its own -- it starts the current segment as
# an undecodable prefix -- yet it decodes to the empty payload WHEN the
# message ends exactly on it (the completion tail completes it), and it
# poisons the message if ANY byte follows (0x41 followed by 0x00, 0x41,
# 0x42, a full stream, or nothing-decodable all fail under the receiver's
# segment scan; pinned by the decompression oracle, W2/W3). The state
# carries the (wire, decompressed) pair and, for text, the boundary over
# the decompressed bytes so the completion checks run on them.
# Reachable pairs: (w-1, d) + the 1-byte frame, i.e. the preceding
# (wire, decompressed) pair plus one wire byte.
P41_PAIRS = [
    (3, 0),
    (4, 0), (4, 1),
    (5, 0), (5, 1), (5, 2),
    (6, 0), (6, 1), (6, 2), (6, MAXMSG + 1),
]
P41_STATES = ["CFB_P41_%d_%d" % (w, d) for w, d in P41_PAIRS] + [
    "CFT_P41_%d_%d%s" % (w, d, C.BOUND_SUFFIX[b]) for w, d in P41_PAIRS for b in U.STATES
]


def poison_state(mode, wire):
    return ("CFB_P%d" if mode == "binary" else "CFT_P%d") % wire


STATES = [IDLE] + FGB + FGT + CFB + CFT + POISON_STATES + P41_STATES + [TERM]


def cfrag_state(mode, wire, count, boundary):
    """The state name for a compressed fragment (mode, accumulated wire
    tokens, decompressed token count saturating at MAXMSG+1, boundary
    state)."""
    count = min(count, MAXMSG + 1)
    if mode == "binary":
        return "CFB%d_%d" % (wire, count)

    return "CFT%d_%d%s" % (wire, count, C.BOUND_SUFFIX[boundary])


def cparse_frag(state):
    """(mode, wire, count, boundary) for a CFB/CFT state."""
    rest = state[3:]
    w = int(rest[0])
    d = int(rest[2])
    suffix = rest[3:]
    if state[2] == "B":
        return "binary", w, d, None

    return "text", w, d, C.SUFFIX_BOUND[suffix]


def cparse_poison(state):
    """(mode, wire) for a CFB_P{w}/CFT_P{w} poisoned state."""
    return ("binary" if state[2] == "B" else "text"), int(state[5])


def p41_state(mode, wire, count, boundary):
    """The pending-41 state name (mode, wire, decompressed count,
    boundary state)."""
    count = min(count, MAXMSG + 1)
    if mode == "binary":
        return "CFB_P41_%d_%d" % (wire, count)

    return "CFT_P41_%d_%d%s" % (wire, count, C.BOUND_SUFFIX[boundary])


def cparse_p41(state):
    """(mode, wire, count, boundary) for a CFB_P41/CFT_P41 state."""
    rest = state[8:]
    w = int(rest[0])
    d = int(rest[2])
    suffix = rest[3:]
    if state[2] == "B":
        return "binary", w, d, None

    return "text", w, d, C.SUFFIX_BOUND[suffix]


def wire_kind(frame):
    """How the frame's wire bytes behave in a compressed context
    (pinned by the decompression oracle, W2/W3):

      complete    a self-contained complete DEFLATE stream (every dedicated
                  compressed class): composes exactly, its chunk is the
                  declared chunk;
      empty       zero wire bytes: contributes nothing;
      pending41   the single byte 0x41: decodes to the empty payload only
                  when the message ends exactly on it; any following byte
                  makes the accumulated bytes undecodable;
      poison      bytes that strand the segment scan (0x41 0x42): the
                  accumulated bytes are undecodable for the rest of the
                  message;
      bad         a stream the receiver's decompression fails (BAD_STREAM).
    """
    f = FRAMES[frame]
    if f["fate"] == "bad":
        return "bad"
    if f["dec"] is not None:
        return "complete"
    p = f["payload"]
    if p == b"":
        return "empty"
    if p == b"\x41":
        return "pending41"

    return "poison"


# --- DEFLATE wire encoding (concrete bytes for the symbolic chunks) ------
#
# A compressed frame's payload is concrete DEFLATE bytes that the receiver
# must decompress to the frame's declared chunk. The encoding used is the
# RFC 7692 7.2.1/7.2.3.5 per-fragment complete-stream form: each frame
# carries self-contained complete DEFLATE block(s), so the concatenation
# of a compressed message's frames is a concatenation of complete
# streams and decompresses to the concatenation of the chunks.
# (The receiver's completion tail -- the 7.2.2 four octets plus the
# interop 01 00 00 ff ff -- is the part-1 reference's TAIL9,
# deflate_stream.py: the single source of truth.)


def _deflate_wire(chunk):
    """A self-contained complete raw-DEFLATE stream for chunk (one final
    block), the per-fragment complete-stream wire form (RFC 7692 7.2.1)."""
    co = zlib.compressobj(6, zlib.DEFLATED, -15, 9)
    return co.compress(chunk) + co.flush()


def _stored_wire(chunk):
    """A complete stored-block stream for chunk (the 5-byte
    byte-aligned header plus the data, RFC 1951 3.2.4): table-
    independent, so the compliant-wire family is well-formed under
    both the RFC's literal fixed table and the implementation's
    canonical one (a zlib fixed block is not: the empty fixed
    stream 03 00 is a bad code under the RFC table)."""
    ln = len(chunk)
    return bytes([0x01, ln & 0xFF, (ln >> 8) & 0xFF,
                  (ln ^ 0xFFFF) & 0xFF, (ln ^ 0xFFFF) >> 8 & 0xFF]) + chunk


def emu_decompress(wire):
    """The receiver's decompression over wire, via the part-1 reference
    classifier (deflate_stream.impl_decompress): the segment scan (each
    complete stream decodes in order) with the completion tail on the
    final remainder -- the implementation's decompress() semantics, the
    single source of truth. The decompressed bytes on success, None on
    a decompression failure. Runs without the size guard: a chunk is
    either decodable or not, independent of the limit.
    """
    status, value = DS.impl_decompress(wire, 10 ** 9)
    return value if status == DS.OK else None


# A compressed payload that is not a decodable stream (any corruption the
# receiver's decompression rejects): BFINAL=1 with BTYPE=11 (dynamic
# Huffman) but no valid table. Chosen bytes; pinned by self_check
# (W2/W3) to fail emu_decompress.
BAD_STREAM = b"\xff"


# --- The alphabet --------------------------------------------------------
#
# Fields per frame: op (opcode), fin, rsv1, rsv23, maskok, lenform,
# plen, payload (concrete wire bytes), fault (header fault name or None),
# dec (the compressed frame's decompressed chunk, dedicated classes),
# fate ("bad" = a stream the receiver's decompression fails).
#
# The alphabet has four families:
#   * the plain domain at limit MAXMSG (single-frame messages, fragments,
#     controls, closes, header faults, eof) -- the same rules as the
#     reassembly machine, its own instantiation;
#   * compressed single-frame messages (RSV1, FIN=1, from IDLE);
#   * compressed starts (RSV1, FIN=0, from IDLE) and compressed
#     continuations (RSV1=0, continuation frames interpreted in the
#     compressed context);
#   * the RSV1-misuse shapes (RSV1 on a control frame; RSV1 on a
#     continuation frame) -- RFC 7692 6.1 MUST NOT.
#
# A plain continuation frame (rsv1=0) that arrives in a compressed context
# is a compressed continuation: its payload reads as compressed data. Its
# chunk is whatever its concrete bytes decode to (the "accidental"
# semantics, computed by emu_decompress and pinned by self_check) -- the
# same wire frame genuinely means different things in the two contexts,
# and the machine branches on context exactly as the receiver must.

FRAMES = {}
FRAME_NAMES = []


def _frame(name, **kw):
    f = dict(op=1, fin=1, rsv1=0, rsv23=0, maskok=1, lenform="short",
             payload=b"", fault=None, dec=None, fate=None)
    f.update(kw)
    f["plen"] = len(f["payload"])
    FRAMES[name] = f
    FRAME_NAMES.append(name)


# Plain data frames (limit MAXMSG: plen > MAXMSG is the frame-size fault).
_frame("text1", op=1, fin=1, payload=b"A")
_frame("text0", op=1, fin=0, payload=b"A")
_frame("text0ff", op=1, fin=0, payload=b"\xff")
_frame("textbad", op=1, fin=1, payload=b"\xff")
_frame("text4", op=1, fin=1, payload=b"ABAB")
_frame("text04", op=1, fin=0, payload=b"ABAB")
_frame("bin0", op=2, fin=0, payload=b"A")
_frame("bin02", op=2, fin=0, payload=b"AB")
_frame("bin4", op=2, fin=1, payload=b"ABAB")
_frame("bin04", op=2, fin=0, payload=b"ABAB")
_frame("cont0", op=0, fin=0, payload=b"A")
_frame("cont02", op=0, fin=0, payload=b"AB")
_frame("cont1", op=0, fin=1, payload=b"A")
_frame("cont12", op=0, fin=1, payload=b"AB")
_frame("contff", op=0, fin=1, payload=b"\xff")
_frame("bin0e", op=2, fin=0, payload=b"")
_frame("text0e", op=1, fin=0, payload=b"")
_frame("cont0e", op=0, fin=0, payload=b"")
_frame("cont1e", op=0, fin=1, payload=b"")

# Controls, closes (identical to the reassembly machine).
_frame("ping", op=9, fin=1, payload=b"")
_frame("ping1", op=9, fin=1, payload=b"A")
_frame("pong", op=10, fin=1, payload=b"")
_frame("close1000", op=8, fin=1, payload=b"\x03\xe8")
_frame("close1000r", op=8, fin=1, payload=b"\x03\xe8\x6f")
_frame("close3000", op=8, fin=1, payload=b"\x0b\xb8\x72")
_frame("closeempty", op=8, fin=1, payload=b"")
_frame("close999", op=8, fin=1, payload=b"\x03\xe7", fault="close-unusable-code")
_frame("close1005", op=8, fin=1, payload=b"\x03\xed", fault="close-mustnotset")
_frame("close1byte", op=8, fin=1, payload=b"\x00", fault="close-onebyte")
_frame("closebadutf8", op=8, fin=1, payload=b"\x03\xe8\xff", fault="close-bad-utf8")

# Header / opcode faults (fire from any state, before message rules).
_frame("badop", op=3, fin=1, payload=b"", fault="reserved-opcode")
_frame("rsv23", op=2, fin=1, rsv23=1, payload=b"", fault="rsv23-set")
_frame("maskbad", op=1, fin=1, maskok=0, payload=b"A", fault="mask-violation")
_frame("len16nonmin", op=1, fin=1, lenform="16", payload=b"A" * 100, fault="nonminimal-16")
_frame("len64nonmin", op=1, fin=1, lenform="64", payload=b"A" * 1000, fault="nonminimal-64")
_frame("ping0", op=9, fin=0, payload=b"", fault="control-not-fin")
_frame("pingbig", op=9, fin=1, lenform="16", payload=b"A" * 200, fault="control-too-big")
_frame("big7", op=2, fin=1, payload=b"A" * 7, fault="frame-too-big")

# Transport end (not a frame).
_frame("eof", op=-1, fin=0, payload=b"", fault="eof")

# Compressed single-frame messages (RSV1, FIN=1). dec is the chunk the
# payload decompresses to; fate "bad" marks an undecodable stream.
_frame("ctext1", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"A"), dec=b"A")
_frame("ctexte", op=1, fin=1, rsv1=1, payload=_deflate_wire(b""), dec=b"")
_frame("ctextff", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xff"), dec=b"\xff")
_frame("ctextc2", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xc2"), dec=b"\xc2")
_frame("ctexte0", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xe0"), dec=b"\xe0")
_frame("ctextp3", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xe3"), dec=b"\xe3")
_frame("ctexted", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xed"), dec=b"\xed")
_frame("ctextf0", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xf0"), dec=b"\xf0")
_frame("ctextf4", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xf4"), dec=b"\xf4")
_frame("ctextp4", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xf1"), dec=b"\xf1")
_frame("ctextk2", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"\xf4\x80"), dec=b"\xf4\x80")
_frame("ctextbad", op=1, fin=1, rsv1=1, payload=BAD_STREAM, fate="bad")
_frame("ctextbomb", op=1, fin=1, rsv1=1, payload=_deflate_wire(b"A" * 7), dec=b"A" * 7)
_frame("cbin1", op=2, fin=1, rsv1=1, payload=_deflate_wire(b"A"), dec=b"A")
_frame("cbine", op=2, fin=1, rsv1=1, payload=_deflate_wire(b""), dec=b"")
_frame("cbinbad", op=2, fin=1, rsv1=1, payload=BAD_STREAM, fate="bad")
_frame("cbinbomb", op=2, fin=1, rsv1=1, payload=_deflate_wire(b"A" * 7), dec=b"A" * 7)

# Compressed starts (RSV1, FIN=0). The fin=0 starts exist so that every
# boundary-machine state -- including the four narrow hazard states and
# K2 -- is reachable as a compressed text fragment state (the RX
# property); the
# matching single-frame (fin=1) classes exercise the same boundaries at
# completion instead.
_frame("ctext0", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"A"), dec=b"A")
_frame("ctext0e", op=1, fin=0, rsv1=1, payload=_deflate_wire(b""), dec=b"")
_frame("ctext0ff", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xff"), dec=b"\xff")
_frame("ctext0w", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xc2"), dec=b"\xc2")
_frame("ctext0e0", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xe0"), dec=b"\xe0")
_frame("ctext0p3", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xe3"), dec=b"\xe3")
_frame("ctext0ed", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xed"), dec=b"\xed")
_frame("ctext0f0", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xf0"), dec=b"\xf0")
_frame("ctext0p4", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xf1"), dec=b"\xf1")
_frame("ctext0f4", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xf4"), dec=b"\xf4")
_frame("ctext0k2", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"\xf4\x80"), dec=b"\xf4\x80")
_frame("ctext0bomb", op=1, fin=0, rsv1=1, payload=_deflate_wire(b"A" * 7), dec=b"A" * 7)
_frame("cbin0", op=2, fin=0, rsv1=1, payload=_deflate_wire(b"A"), dec=b"A")
_frame("cbin0e", op=2, fin=0, rsv1=1, payload=_deflate_wire(b""), dec=b"")
_frame("cbin0bomb", op=2, fin=0, rsv1=1, payload=_deflate_wire(b"A" * 7), dec=b"A" * 7)

# Compressed continuations (RSV1=0, continuation frames). The dedicated
# ccont classes carry declared chunks; the plain cont classes carry their
# accidental compressed-context chunks (pinned by self_check).
_frame("ccontA0", op=0, fin=0, payload=_deflate_wire(b"A"), dec=b"A")
_frame("ccontA1", op=0, fin=1, payload=_deflate_wire(b"A"), dec=b"A")
_frame("ccontAB0", op=0, fin=0, payload=_deflate_wire(b"AB"), dec=b"AB")
_frame("ccontAB1", op=0, fin=1, payload=_deflate_wire(b"AB"), dec=b"AB")
_frame("ccontC30", op=0, fin=0, payload=_deflate_wire(b"\xc3"), dec=b"\xc3")
_frame("ccontC31", op=0, fin=1, payload=_deflate_wire(b"\xc3"), dec=b"\xc3")
_frame("ccont890", op=0, fin=0, payload=_deflate_wire(b"\x89"), dec=b"\x89")
_frame("ccont891", op=0, fin=1, payload=_deflate_wire(b"\x89"), dec=b"\x89")
_frame("ccontK20", op=0, fin=0, payload=_deflate_wire(b"\xf4\x80"), dec=b"\xf4\x80")
_frame("ccont1bomb", op=0, fin=1, payload=_deflate_wire(b"A" * 7), dec=b"A" * 7)
# (A corrupted-stream completion in a compressed context is the plain
# contff frame itself in that context -- same wire bytes, the machine
# branches on context -- so there is no dedicated multi-frame bad class.)

# RSV1 misuse (RFC 7692 6.1 MUST NOT): RSV1 on a control frame; RSV1 on a
# continuation frame. The payloads are concrete compressed bytes (any
# payload would do; the fault is in the header, not the stream).
_frame("rsv1ctrl", op=9, fin=1, rsv1=1, payload=_deflate_wire(b"A"))
_frame("ccontR", op=0, fin=1, rsv1=1, payload=_deflate_wire(b"A"))


def chunk_of(frame_name):
    """The decompressed chunk of a frame in the compressed domain: the
    declared chunk for the dedicated compressed classes, the accidental
    DEFLATE interpretation of the concrete payload for the plain
    continuation classes (same wire frame, compressed context). None when
    the stream fails the receiver's decompression."""
    f = FRAMES[frame_name]
    if f["fate"] == "bad":
        return None
    if f["dec"] is not None:
        return f["dec"]
    return emu_decompress(f["payload"])


# Frames that trip a header/opcode check and therefore fail the connection
# from any non-terminal state, before message-level rules are reached.
HEADER_FAULTS = {
    "badop", "rsv23", "maskbad", "len16nonmin", "len64nonmin", "ping0", "pingbig", "big7",
}

# RFC citation per fault (trace annotation).
FAULT_RFC = {
    "close-unusable-code": "RFC 6455 7.4",
    "close-mustnotset": "RFC 6455 7.4",
    "close-onebyte": "RFC 6455 5.5.1",
    "close-bad-utf8": "RFC 6455 7.1.5, 8.1",
    "reserved-opcode": "RFC 6455 5.5",
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
    "rsv1-control": "RFC 7692 6.1",
    "rsv1-nonfirst": "RFC 7692 6.1",
    "decompress-fail": "RFC 7692 6.2, RFC 6455 7.1.7",
    "dec-size": "RFC 6455 7.4.2 (project maxMessageSize policy)",
    "dec-utf8": "RFC 7692 6.1, RFC 6455 5.6",
}


# --- The transition function ---------------------------------------------

def trans(state, frame):
    """One frame step of the machine.

    Returns (to_state, emits, rfc, fault) where emits is the list of
    ReadEvent results produced by processing this frame (empty when
    ReadEvent keeps accumulating a fragment), rfc is the citation(s), and
    fault names the rule that fired (None for well-formed steps).

    Check order per frame (outcome-preserving: every ordering choice lands
    both branches on the same terminal outcome):
      1. header / opcode rules (RSV2/3, masking, non-minimal length,
         control-FIN, control-size, single-frame wire size) -- RFC 6455
         5.1/5.2/5.5, 1002;
      2. transport end -- RFC 6455 7.1.5, 1006;
      3. controls: RSV1 on a control frame is the 7692 6.1 violation
         (1002); well-formed controls interleave with fragments;
      4. close resolution -- RFC 6455 5.5.1/7.4 (identical in both
         domains);
      5. data / continuation: RSV1 placement (7692 6.1) before message
         structure (6455 5.4) before accumulation/completion.
    """
    if state == TERM:
        return TERM, [], "terminal-absorbing", None

    f = FRAMES[frame]

    if frame in HEADER_FAULTS:
        return TERM, [C.term(1002)], FAULT_RFC[f["fault"]], f["fault"]

    if frame == "eof":
        return TERM, [C.term(1006)], FAULT_RFC["eof"], "eof"

    if frame == "rsv1ctrl":
        # RSV1 on a control frame (RFC 7692 6.1 MUST NOT): fail the
        # connection. Fires from any state, controls carry no message
        # position, so the header-level check is exact here.
        return TERM, [C.term(1002)], FAULT_RFC["rsv1-control"], "rsv1-control"

    if frame in ("ping", "ping1", "pong"):
        op = "ping" if frame in ("ping", "ping1") else "pong"
        to = IDLE if state == IDLE else state
        return to, [C.ctrl(op, f["payload"])], "RFC 6455 5.5", None

    if frame.startswith("close"):
        return C.close_resolution(state, frame)

    return _data(state, frame)


def _data(state, frame):
    f = FRAMES[frame]
    op = f["op"]
    is_cont = op == 0
    is_start = op in (1, 2)
    plain_frag = state in FGB or state in FGT
    comp_frag = state in CFB or state in CFT
    poisoned = state in POISON_STATES
    pending41 = state in P41_STATES
    in_frag = plain_frag or comp_frag or poisoned or pending41

    # RSV1 on a data frame: legal only as the first frame of a compressed
    # message (from IDLE); on a non-first fragment it is the 7692 6.1
    # violation (also a 6455 5.4 data-while-in-fragment violation; both
    # fail with 1002, the 7692 citation is the specific one).
    if f["rsv1"] and is_start:
        if state == IDLE:
            if f["fin"]:
                return _comp_single(frame)

            return _comp_start(frame)
        return TERM, [C.term(1002)], FAULT_RFC["rsv1-nonfirst"], "rsv1-nonfirst"

    # RSV1 on a continuation frame (ccontR): 7692 6.1 violation on any
    # in-progress message; with no message in progress it is a
    # continuation-without-start (6455 5.4) -- the frame is not a
    # non-first fragment of any data message, so 6.1 does not apply. Both
    # fail with 1002.
    if f["rsv1"] and is_cont:
        if not in_frag:
            return TERM, [C.term_proto()], FAULT_RFC["cont-without-start"], "cont-without-start"
        return TERM, [C.term(1002)], FAULT_RFC["rsv1-nonfirst"], "rsv1-nonfirst"

    # Plain data frames (RSV1=0).
    if is_start:
        if in_frag:
            return TERM, [C.term_proto()], FAULT_RFC["data-while-infrag"], "data-while-infrag"
        if f["plen"] > MAXMSG:
            return TERM, [C.term(1002)], FAULT_RFC["frame-too-big"], "frame-too-big"
        if not f["fin"]:
            if op == 1:
                to_boundary = U.apply(U.CLEAN, f["payload"])

                return C.frag_state("text", f["plen"], to_boundary), [], "RFC 6455 5.4", None
            return C.frag_state("binary", f["plen"], None), [], "RFC 6455 5.4", None
        if op == 1 and U.apply(U.CLEAN, f["payload"]) != U.CLEAN:
            return TERM, [C.term(1007)], FAULT_RFC["utf8-invalid"], "utf8-invalid"
        return IDLE, [C.msg("text" if op == 1 else "binary", b"")], "RFC 6455 5.5", None

    # Plain continuations (RSV1=0, continuation frames).
    if not in_frag:
        return TERM, [C.term_proto()], FAULT_RFC["cont-without-start"], "cont-without-start"
    if plain_frag:
        return _plain_cont(state, frame)
    if poisoned:
        return _comp_poisoned(state, frame)
    if pending41:
        return _comp_p41(state, frame)

    return _comp_cont(state, frame)


def _plain_cont(state, frame):
    """A plain continuation in a plain fragment: RFC 6455 5.4/5.6 at this
    machine's limit (identical to the reassembly machine's rows, its own
    MAXMSG instantiation)."""
    f = FRAMES[frame]
    mode, count, boundary = C.parse_frag(state)
    new_count = count + f["plen"]
    if new_count > MAXMSG:
        return TERM, [C.term_proto()], FAULT_RFC["cross-frame-too-big"], "cross-frame-too-big"
    to_boundary = boundary if mode == "binary" else U.apply(boundary, f["payload"])
    if not f["fin"]:
        return C.frag_state(mode, new_count, to_boundary), [], "RFC 6455 5.4", None
    if mode == "text" and to_boundary != U.CLEAN:
        return TERM, [C.term(1007)], FAULT_RFC["utf8-invalid"], "utf8-invalid"
    return IDLE, [C.msg(mode, b"")], "RFC 6455 5.4", None


def _comp_start(frame):
    """A compressed start from IDLE (RSV1, FIN=0): the compressed context
    begins; the wire and decompressed counts start from the frame's
    self-contained stream (RFC 7692 7.2.1: non-final fragments carry
    complete stream(s), so the per-frame chunk composes exactly)."""
    f = FRAMES[frame]
    chunk = chunk_of(frame)
    if f["fate"] == "bad" or chunk is None:
        # A non-final frame with an undecodable stream poisons the message:
        # the receiver cannot know until completion (decompression happens
        # on the accumulated bytes), so the poisoned state waits.
        return poison_state("binary" if f["op"] == 0 else "text", f["plen"]), [], FAULT_RFC["decompress-fail"], "decompress-fail"
    mode = "text" if f["op"] == 1 else "binary"
    if mode == "binary":
        return cfrag_state("binary", f["plen"], len(chunk), None), [], "RFC 7692 6", None
    boundary = U.apply(U.CLEAN, chunk)
    return cfrag_state("text", f["plen"], len(chunk), boundary), [], "RFC 7692 6", None


def _comp_cont(state, frame):
    """A continuation in a compressed context: the frame's compressed
    payload joins the accumulation (RFC 7692 6: frames of a compressed
    message have compressed data; the RSV1 bit is 0 on every frame after
    the first). The policy bounds both axes: the WIRE total is checked
    per frame while accumulating (before decompression, exactly as the
    plain domain), and the DECOMPRESSED total is checked at completion
    (RFC 7692 is silent on overflow, so its close target is the
    under-specified set {1002, 1009}). Then the decompressed UTF-8
    (RFC 7692 6.1 puts the decompressed payload back under the original
    data type's constraints; RFC 6455 5.6 -> 1007)."""
    f = FRAMES[frame]
    mode, wire, count, boundary = cparse_frag(state)
    new_wire = wire + f["plen"]
    if new_wire > MAXMSG:
        # The wire cross-frame fault fires before any decompression:
        # compressed fragments are bounded by the wire policy exactly as
        # plain fragments are (RFC 6455 7.4.2-style size failure -> 1002).
        return TERM, [C.term(1002)], FAULT_RFC["cross-frame-too-big"], "cross-frame-too-big"
    kind = wire_kind(frame)
    if kind in ("poison", "bad"):
        if f["fin"]:
            # Decompression failure at completion: RFC 7692 names no Close
            # frame for it (6.2 is silent on failure); the generic RFC
            # 6455 7.1.7 SHOULD applies -- target set {1002, 1007}, MAY omit.
            return TERM, [C.term(1002)], FAULT_RFC["decompress-fail"], "decompress-fail"
        # A non-final frame whose bytes cannot join any stream: the
        # accumulated bytes are undecodable for the rest of the message
        # (the receiver's segment scan is left a stranded, uncomplete
        # prefix), so the message can only complete as a decompression
        # failure. The poisoned state records that (the wire count keeps
        # advancing: the per-frame wire check still applies).
        return poison_state(mode, new_wire), [], FAULT_RFC["decompress-fail"], "decompress-fail"
    if kind == "pending41":
        # The 0x41 byte starts the current segment as an undecodable
        # prefix: the message ends exactly on it (fin) or it poisons the
        # message (non-fin) -- see the pending-41 states. Either way the
        # accumulated decompressed bytes so far are carried through.
        if f["fin"]:
            chunk = b""  # the completion tail completes the 0x41 to empty
        else:
            return p41_state(mode, new_wire, count, boundary if mode == "text" else None), [], "RFC 7692 6", None
    elif kind == "empty":
        chunk = b""
    else:  # complete
        chunk = f["dec"]
    new_count = min(count + len(chunk), MAXMSG + 1)
    to_boundary = boundary if mode == "binary" else U.apply(boundary, chunk)
    if not f["fin"]:
        return cfrag_state(mode, new_wire, new_count, to_boundary if mode == "text" else None), [], "RFC 7692 6", None
    if new_count > MAXMSG:
        return TERM, [C.term(1009)], FAULT_RFC["dec-size"], "dec-size"
    if mode == "text" and to_boundary != U.CLEAN:
        return TERM, [C.term(1007)], FAULT_RFC["dec-utf8"], "dec-utf8"
    return IDLE, [C.msg(mode, b"")], "RFC 7692 6.2", None


def _comp_p41(state, frame):
    """A continuation while the current segment starts with the pending
    0x41 prefix: the receiver's segment scan cannot complete that prefix,
    so ANY following wire byte makes the accumulated bytes undecodable
    (0x41 followed by 0x00, 0x41, 0x42, a full stream, anything -- pinned
    by the decompression oracle): a non-final frame poisons the message
    (the wire count keeps advancing), a final frame with any payload of
    its own completes it as a decompression failure ({1002, 1007}), and
    only the zero-byte final frame ends the message exactly on the 0x41,
    which the completion tail decodes to the empty payload."""
    f = FRAMES[frame]
    mode, wire, count, boundary = cparse_p41(state)
    new_wire = wire + f["plen"]
    if new_wire > MAXMSG:
        return TERM, [C.term(1002)], FAULT_RFC["cross-frame-too-big"], "cross-frame-too-big"
    if not f["fin"]:
        if wire_kind(frame) == "empty":
            # Nothing was added: the pending prefix is still pending.
            return state, [], "RFC 7692 6", None

        return poison_state(mode, new_wire), [], FAULT_RFC["decompress-fail"], "decompress-fail"
    if wire_kind(frame) == "empty":
        # The message ends exactly on the 0x41: it decodes to empty, so
        # the accumulated decompressed bytes are the completed payload.
        if count > MAXMSG:
            return TERM, [C.term(1009)], FAULT_RFC["dec-size"], "dec-size"
        if mode == "text" and boundary != U.CLEAN:
            return TERM, [C.term(1007)], FAULT_RFC["dec-utf8"], "dec-utf8"

        return IDLE, [C.msg(mode, b"")], "RFC 7692 6.2", None

    return TERM, [C.term(1002)], FAULT_RFC["decompress-fail"], "decompress-fail"


def _comp_poisoned(state, frame):
    """A continuation frame in a poisoned compressed message: the
    accumulated bytes are undecodable for the rest of the message, so a
    final frame completes it as a decompression failure (RFC 7692 names
    no Close frame for the failure; target set {1002, 1007}), a
    non-final one keeps accumulating, and the per-frame wire check still
    applies (a wire overflow faults on the wire, not the decompression)."""
    f = FRAMES[frame]
    mode, wire = cparse_poison(state)
    new_wire = wire + f["plen"]
    if new_wire > MAXMSG:
        return TERM, [C.term(1002)], FAULT_RFC["cross-frame-too-big"], "cross-frame-too-big"
    if not f["fin"]:
        return poison_state(mode, new_wire), [], "RFC 7692 6", None
    return TERM, [C.term(1002)], FAULT_RFC["decompress-fail"], "decompress-fail"


def _comp_single(frame):
    """A single-frame compressed message from IDLE (RSV1, FIN=1): the
    completion checks of _comp_cont on a one-frame message."""
    f = FRAMES[frame]
    mode = "text" if f["op"] == 1 else "binary"
    if f["plen"] > MAXMSG:
        return TERM, [C.term(1002)], FAULT_RFC["cross-frame-too-big"], "cross-frame-too-big"
    chunk = chunk_of(frame)
    if f["fate"] == "bad" or chunk is None:
        return TERM, [C.term(1002)], FAULT_RFC["decompress-fail"], "decompress-fail"
    if len(chunk) > MAXMSG:
        return TERM, [C.term(1009)], FAULT_RFC["dec-size"], "dec-size"
    if mode == "text" and U.apply(U.CLEAN, chunk) != U.CLEAN:
        return TERM, [C.term(1007)], FAULT_RFC["dec-utf8"], "dec-utf8"
    return IDLE, [C.msg(mode, b"")], "RFC 7692 6.2", None


# --- Conformance layer (MUST / SHOULD / MAY) ------------------------------

def should_close(state, frame):
    """The set of close codes that SHOULD be on the wire for this frame
    step (the RFC 6455 7.1.7 SHOULD, generalized to target sets).

    Singleton where the RFC or project policy designates the code; a set
    where it does not: RFC 7692 is silent on a failed decompression
    (1002 protocol error or 1007 invalid payload data are the candidates)
    and on a decompressed size overflow (1002 or 1009 "message too big").
    A peer (or this implementation) MAY omit the frame entirely
    (terminal_outcomes); omitting is a counted, assessable warning.
    """
    if state == TERM:
        return frozenset()
    if frame in HEADER_FAULTS:
        return frozenset({1002})
    if frame == "eof":
        return frozenset()  # transport gone; no close frame can be written
    if frame == "rsv1ctrl":
        return frozenset({1002})
    if frame in ("ping", "ping1", "pong"):
        return frozenset()
    if frame.startswith("close"):
        if frame in ("close1000", "close1000r"):
            return frozenset({1000})
        if frame == "close3000":
            return frozenset({3000})
        if frame == "closeempty":
            return frozenset()  # 1005 is resolved but MUST NOT be set on the wire
        return frozenset({1002})
    _, _, _, fault = trans(state, frame)
    if fault is None:
        return frozenset()
    if fault in ("utf8-invalid", "dec-utf8"):
        return frozenset({1007})
    if fault == "decompress-fail":
        return frozenset({1002, 1007})
    if fault == "dec-size":
        return frozenset({1002, 1009})
    return frozenset({1002})


# The assessable warnings this machine tracks: the RFC 7692 silences, where
# the implementation reports the error directly and sends no Close frame
# (the 7.1.7 MAY). One stable ID per root cause; accepted in
# ws/testdata/deflate/NOTES.json.
MAY_DECOMP_ID = "MAY:decompress-close-omitted"
MAY_DECOMP_NOTE = ("RFC 7692 names no Close frame for a failed decompression "
                   "(6.2 is silent on failure; the RFC 6455 7.1.7 SHOULD "
                   "applies generically, 1002/1007 the candidate codes). "
                   "The implementation reports the error directly, no Close "
                   "frame: the MAY omission.")
MAY_DECSIZE_ID = "MAY:decompress-size-close-omitted"
MAY_DECSIZE_NOTE = ("The decompressed payload is bounded by the project's "
                    "maxMessageSize while decompressing; the RFC names no "
                    "close for the overflow (1009 'message too big' and "
                    "1002 'protocol error' are the candidates). The "
                    "implementation reports the error directly, no Close "
                    "frame: the MAY omission.")


def terminal_outcomes(state, frame):
    """The SHOULD/MAY/MUST close-frame outcomes for a terminal step.

    MUST outcomes are hard (a mismatch fails the test). Each code in the
    SHOULD target set is its own SHOULD outcome (meeting any one raises no
    warning). The MAY (omit the frame) is a counted, assessable warning:
    the stable ID distinguishes the RFC 7692 silences (decompression
    failure, decompressed size) from the generic 7.1.7 omission."""
    to, _, _, fault = trans(state, frame)
    if to != TERM:
        return []
    if frame == "eof":
        return [C.out("none", "closeErr", "must", code=1006)]
    if frame in ("ping", "ping1", "pong"):
        return []
    if frame.startswith("close") and fault is None:
        if frame in ("close1000", "close1000r"):
            return [C.out(1000, "eof", "must")]
        if frame == "close3000":
            return [C.out(3000, "closeErr", "must", code=3000)]
        if frame == "closeempty":
            return [C.out("empty", "eof", "must")]
    out = []
    for code in sorted(should_close(state, frame)):
        out.append(C.out(code, "closeErr", "should", code=code, note=C.SHOULD_NOTE))
    if fault == "decompress-fail":
        out.append(C.out("none", "proto", "may", wid=MAY_DECOMP_ID, note=MAY_DECOMP_NOTE))
    elif fault == "dec-size":
        out.append(C.out("none", "proto", "may", wid=MAY_DECSIZE_ID, note=MAY_DECSIZE_NOTE))
    elif fault is not None:
        out.append(C.out("none", "proto", "may", wid=C.MAY_OMIT_ID, note=C.MAY_OMIT_NOTE))
    return out


def trace_assertions(frames):
    """Replay a frame sequence; return the trace assertions for the final
    (target) step: {"events": [...], "terminal": None | {"outcomes": [...]}}.

    The delivered message payload is reconstructed from the context: a
    plain message carries the concatenation of its frames' payloads
    (RFC 6455 5.4); a compressed message carries the concatenation of its
    frames' DECOMPRESSED chunks (RFC 7692 6.2). The prefix frames drive
    the machine to the target state and are non-observable, so only the
    target step contributes events."""
    state = IDLE
    acc = b""
    cacc = b""
    for f in frames[:-1]:
        fr = FRAMES[f]
        was_plain = state in FGB or state in FGT
        was_comp = state in CFB or state in CFT or state in POISON_STATES or state in P41_STATES
        if was_plain:
            acc += fr["payload"]
        if was_comp:
            ch = chunk_of(f)
            if ch is not None:
                cacc += ch
        to, _, _, _ = trans(state, f)
        if (not was_plain) and (to in FGB or to in FGT):
            acc = fr["payload"]  # started a plain multi-frame message
        if (not was_comp) and (to in CFB or to in CFT):
            ch = chunk_of(f)
            cacc = ch if ch is not None else b""  # started a compressed message
        state = to

    f = frames[-1]
    fr = FRAMES[f]
    was_plain = state in FGB or state in FGT
    was_comp = state in CFB or state in CFT or state in POISON_STATES or state in P41_STATES
    if was_plain:
        acc += fr["payload"]
    if was_comp:
        ch = chunk_of(f)
        if ch is not None:
            cacc += ch
    to, emits, _, _ = trans(state, f)

    events = []
    for e in emits:
        if e["t"] != "event":
            continue
        e = dict(e)
        if e.get("kind") == "msg":
            if was_comp:
                payload = cacc
            elif was_plain:
                payload = acc
            elif fr["rsv1"] and fr["op"] in (1, 2):
                ch = chunk_of(f)
                payload = ch if ch is not None else b""
            else:
                payload = fr["payload"]
            e["payload"] = payload.hex()
        events.append(e)

    terminal = None
    if to == TERM:
        terminal = {"outcomes": terminal_outcomes(state, f)}
    return {"events": events, "terminal": terminal}


def encode(frame_name, side):
    """The concrete bytes for one of this machine's frames on a side
    (the reassembly machine's shared wire encoder, this alphabet)."""
    return C.encode_wire(FRAMES[frame_name], side)


# --- Self-consistency (the wire-level invariants) -------------------------

def self_check():
    """Self-consistency of the machine's wire encoding, pure Python.
    Returns a list of failure strings (empty when all pass):

      W1  wire budget: every non-fault data frame's wire payload fits the
          limit (a compressed frame that did not would fail at the header
          before its compressed logic, and the class's declared behavior
          would be unreachable);
      W2  declared chunks: every dedicated compressed class's payload
          decompresses (per emu_decompress, the receiver's semantics) to
          exactly its declared chunk, and its fate-"bad" payload fails;
      W3  accidental chunks: the plain continuation classes' compressed-
          context chunks are deterministic and match the pinned
          expectations (the same wire frame reads as compressed data in a
          compressed context; the machine must not drift from the bytes);
      W4  the limit is honest: the bomb chunk exceeds the limit in
          decompressed tokens and fits it in wire bytes (the decompressed
          overflow is a real alphabet class, not an arithmetic accident);
          the empty wire decompresses to the empty payload;
      W5  no wire collision: no two frame classes encode to the same
          bytes on the same side (a collision would make the concrete
          traces ambiguous -- the receiver's interpretation is the
          machine's context branching, not a class distinction);
      W6  the decompression oracle: emu_decompress (the part-1
          reference, deflate_stream.impl_decompress) matches the
          implementation's decompress() on every wire the machine can
          accumulate (deflate_oracle.json) -- the pending-41 and
          poisoned state branching is derived from this table.
      W7  the spec-implementation bridge on compliant wires: every
          payload the alphabet expresses, in the RFC 7692 7.2.1
          compliant shape (one complete byte-aligned stream plus the
          truncated empty stored header's first octet, 0x00 or 0x01),
          is COMPLETE under the spec classifier and accepted by the
          receiver's semantics with exactly that payload.
    """
    failures = []

    # W1: wire budget over the non-fault data frames.
    for name in FRAME_NAMES:
        f = FRAMES[name]
        if f["fault"] is not None or f["op"] == -1 or f["op"] == 8 or f["op"] in (9, 10):
            continue
        if len(f["payload"]) > MAXMSG:
            failures.append("W1: %s wire payload %d > limit %d" % (name, len(f["payload"]), MAXMSG))

    # W2: declared chunks vs the receiver's decompression semantics.
    for name in FRAME_NAMES:
        f = FRAMES[name]
        if f["fate"] == "bad":
            if emu_decompress(f["payload"]) is not None:
                failures.append("W2: %s fate bad but payload decompresses" % name)
            continue
        if f["dec"] is None:
            continue
        got = emu_decompress(f["payload"])
        if got != f["dec"]:
            failures.append("W2: %s payload decompresses to %r, declared %r" % (name, got, f["dec"]))

    # W3: the plain continuation classes' accidental compressed chunks.
    # cont0/cont1 (payload 0x41) decode to the empty payload only when the
    # message ends exactly on the byte (the completion tail completes it);
    # any following byte makes the accumulation undecodable (the machine's
    # pending-41 states). cont02/cont12 (0x41 0x42) and contff (0xff) are
    # undecodable in every position. W6 pins all of this against the full
    # decompression oracle.
    expected_accidental = {
        "cont0": b"", "cont1": b"", "cont0e": b"", "cont1e": b"",
        "cont02": None, "cont12": None, "contff": None,
    }
    for name, want in expected_accidental.items():
        got = chunk_of(name)
        if got != want:
            failures.append("W3: %s compressed-context chunk %r, pinned %r" % (name, got, want))

    # W4: limit honesty.
    bomb = FRAMES["ctextbomb"]
    if len(bomb["dec"]) <= MAXMSG:
        failures.append("W4: bomb chunk %d tokens does not exceed the limit %d" % (len(bomb["dec"]), MAXMSG))
    if len(bomb["payload"]) > MAXMSG:
        failures.append("W4: bomb wire payload %d exceeds the limit %d" % (len(bomb["payload"]), MAXMSG))
    if emu_decompress(b"") != b"":
        failures.append("W4: empty wire must decompress to the empty payload")

    # W5: wire collisions (one side suffices: masking depends only on
    # side, not on frame).
    seen_bytes = {}
    for name in FRAME_NAMES:
        b = C.encode_wire(FRAMES[name], "server").hex()
        if b in seen_bytes:
            failures.append("W5: %s and %s encode identically on the wire" % (seen_bytes[b], name))
        else:
            seen_bytes[b] = name

    # W6: the decompression oracle. emu_decompress (now the part-1
    # reference itself) must match the implementation's decompress()
    # on every wire the machine can accumulate: all sequences of
    # alphabet payloads up to the limit (deflate_oracle.json, generated
    # by the Go oracle test). The oracle is the receiver's
    # decompression semantics, pinned by the implementation's own code
    # -- the same code the traces replay against -- and it is what the
    # pending-41 / poisoned state branching is derived from.
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "deflate_oracle.json")) as fh:
            oracle = json.load(fh)
    except OSError:
        oracle = None
    if oracle is None:
        failures.append("W6: deflate_oracle.json missing")
    else:
        mismatches = 0
        for row in oracle:
            wire = bytes.fromhex(row["wire"]) if row["wire"] else b""
            got = emu_decompress(wire)
            want = bytes.fromhex(row["out"]) if row["ok"] else None
            if got != want:
                mismatches += 1
                if mismatches <= 5:
                    failures.append("W6: emu(%s) = %r, oracle %r" % (row["wire"], got, want))
        if mismatches > 5:
            failures.append("W6: %d more oracle mismatches" % (mismatches - 5))

    # W7: the spec-implementation bridge on compliant wires. Every
    # payload the alphabet expresses, in the RFC 7692 7.2.1 compliant
    # shape -- one complete byte-aligned stream (the 7.2.1 MUST zero
    # padding) plus the truncated empty stored header's first octet
    # (0x00 or 0x01: its BFINAL bit, the RFC leaving BFINAL
    # unspecified) -- must be COMPLETE under the spec classifier and
    # accepted by the receiver's semantics with exactly that payload.
    # The exhaustive 1-2 byte domain and the oracle wires contain no
    # COMPLETE wire (the minimal compliant buffer is three bytes --
    # the empty fixed final block, which reaches the byte boundary at
    # bit 10, plus the tail octet -- and the alphabet's frames carry
    # raw complete streams without the completion octet), so W7
    # synthesizes the compliant wires.
    # Stored blocks keep the family table-independent (an RFC-literal
    # fixed-block wire is misdecoded by the implementation's canonical
    # table -- the documented 3.2.6 deviation); a two-stream wire is
    # not compliant (7.2.1 names one stream) and out of scope here.
    chunks = sorted({f["dec"] for f in FRAMES.values()
                     if f["dec"] is not None and len(f["dec"]) <= MAXMSG})
    streams = [_stored_wire(ch) for ch in chunks]
    stream_outs = list(chunks)
    for tail in (bytes([0x00]), bytes([0x01])):
        for wire, out in zip(streams, stream_outs):
            wire = wire + tail
            cls, spec_out, _ = DS.spec7692(wire)
            st, val = DS.impl_decompress(wire, 10 ** 9)
            if cls != DS.COMPLETE or spec_out != out or st != DS.OK \
                    or val != out:
                failures.append("W7: compliant wire %s (tail %s): "
                                "spec %s/%r, impl %s/%r, want %r"
                                % (wire.hex(), tail.hex(), cls, spec_out,
                                   st, val, out))
                break

    return failures


if __name__ == "__main__":
    bad = self_check()
    if bad:
        for line in bad:
            print("FAIL", line)
        raise SystemExit("deflate self-check failed (%d)" % len(bad))
    print("deflate self-check: W1-W7 pass (%d states x %d frames)" % (len(STATES), len(FRAME_NAMES)))
