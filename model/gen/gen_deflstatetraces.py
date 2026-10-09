"""Model-based trace generation for the DEFLATE state machine (machine
B2, doc/DEFLATE-STREAM.md part 2): concrete compressed-frame sequences
over the machine's byte alphabet, with the expected outcomes computed
from the reference classifier (deflate_stream.impl_decompress, the
implementation model; deflate_stream.spec7692, the RFC 7692 7.2.1
classification) and the machine (deflate_state) on the same bytes.

What a trace pins on the live connection:

  * only the final frame decompresses: the read loop returns a
    compressed fragment untouched (no per-frame decompression, no
    per-frame size check on the decoded output) and decompresses the
    whole accumulated wire on the final frame. So the machine's
    mid-stream state (pending codes, table bytes) is not observable at
    the frame level; the trace's expectations live at the final frame
    and the ledger.
  * final-frame outcomes, from the reference:
      OK      -> the message is delivered (the payload is asserted);
                 a ledger entry records a non-compliant acceptance when
                 the RFC classification of the wire is not COMPLETE.
      SIZE    -> the terminal 1009 (SHOULD) frame, or the MAY bare
                 teardown (MAY:decompress-size-close-omitted).
      CORRUPT -> the terminal 1002 (SHOULD) frame, or the MAY bare
                 teardown (MAY:decompress-close-omitted).
      EOF     -> as CORRUPT (the tail could not complete the stream).
  * the ledger IDs are MAY:deflate-accept:<name> with the RFC
    7692 7.2.1 shape name (the spec7692 fault, or stream-incomplete /
    tail-missing / empty for the PREFIX class): the RFC requires the
    peer to send a complete stream (MUST) but assigns the receiver no
    obligation to refuse a truncated or malformed one; the
    implementation's completion tail is a deliberate lenient parse,
    so every such acceptance is a counted, assessable warning.

Trace families (one file each, both sides):

  S_<witness>_fin:      the witness bytes as one final frame.
  S_<witness>_frag:     the witness bytes split across a non-final
                        frame and a final frame (RFC 7692 6.2: a
                        compressed message may span fragments; the
                        stream need not be whole in any one fragment).
  S_<witness>_ping:     the split with an interleaved ping (delivery
                        traces only: the ping is the only mid-message
                        event, and the terminal wire check expects the
                        close frame to be the first written frame).
  S_multi:              a wire of two complete streams in one message
                        (the DONE state starting a new stream on the
                        next byte; the decoded output is their
                        concatenation).
  S_textutf8:           a text message whose decoded payload is valid
                        UTF-8 (delivered) and one whose is not
                        (terminal 1007).

The witness states (gen_deflstatemodel.witnesses) cover every coarse
(phase, output) class the cross-check proved reachable.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common as C
import deflate_state as S
import deflate_stream as DS
import gen_deflstatemodel as G

MACHINE = "deflstate"
SIDES = ["server", "client"]


def frame(op, fin, rsv1, payload):
    """A frame dict of the reassembly machine's shared wire shape
    (common.encode_wire)."""
    return dict(op=op, fin=fin, rsv1=rsv1, rsv23=0, maskok=1,
                lenform="short", plen=len(payload), payload=payload,
                fault=None, dec=None, fate=None)


def wire(frames, side):
    return [C.encode_wire(f, side) for f in frames]


def ledger_for_wire(wirebytes):
    """The MAY:deflate-accept ledger entries for a delivered wire:
    one when the RFC 7692 7.2.1 class of the wire is not COMPLETE."""
    cls, out, fault = DS.spec7692(wirebytes)
    if cls == DS.COMPLETE:
        return []
    return [{"id": "MAY:deflate-accept:%s" % fault, "mod": "may",
             "basis": "RFC 7692 7.2.1 (the final frame's payload is a "
                      "complete stream, MUST) + 7.2.1 completion "
                      "octets",
             "note": "the wire is %s (%s); the implementation decodes "
                     "it anyway and delivers the message -- a lenient "
                     "parse the RFC does not require" % (cls, fault)}]


OUTCOME_WIRE = {"outcomes": [
    {"code": 1002, "mod": "should", "term": "closeErr",
     "wire": {"code": 1002, "kind": "coded"}},
    {"id": "MAY:wire-size-close-omitted", "mod": "may",
     "note": "RFC 6455 5.5 (the message-size limit applies to the "
             "reassembled message) + RFC 6455 7.1.7 (SHOULD close, "
             "MAY omit) + project maxMessageSize policy: a "
             "compressed message whose accumulated wire already "
             "exceeds the limit fails before any decompression. "
             "The implementation reports the error directly and "
             "takes the MAY.",
     "term": "proto", "wire": {"kind": "none"}},
]}
OUTCOME_SIZE = {"outcomes": [
    {"code": 1009, "mod": "should", "term": "closeErr",
     "wire": {"code": 1009, "kind": "coded"}},
    {"id": "MAY:decompress-size-close-omitted", "mod": "may",
     "note": "RFC 6455 7.4.2 (1009) + RFC 7692 8 (informative): the "
             "decompressed-size limit is project policy, the RFC "
             "assigns no Close frame to the overflow; the "
             "implementation reports the error directly and takes "
             "the 7.1.7 MAY.",
     "term": "proto", "wire": {"kind": "none"}},
]}
OUTCOME_PROTO = {"outcomes": [
    {"code": 1002, "mod": "should", "term": "closeErr",
     "wire": {"code": 1002, "kind": "coded"}},
    {"id": "MAY:decompress-close-omitted", "mod": "may",
     "note": "RFC 7692 6.2 (silent on failure) + RFC 6455 7.1.7 "
             "(SHOULD close, MAY omit): the implementation reports "
             "the error directly and takes the MAY.",
     "term": "proto", "wire": {"kind": "none"}},
]}


def fin_expectation(wirebytes, op):
    """The expected (events, terminal, warnings) at the final frame
    for one accumulated wire."""
    # The wire-side limit (RFC 6455 5.5 via project policy) is
    # enforced on the accumulated wire before any decompression:
    # a compressed message whose wire already exceeds the limit
    # fails here, so the decompression outcomes below are reachable
    # only under the limit.
    if len(wirebytes) > S.MAXMSG:
        return [], OUTCOME_WIRE, []
    status, value = DS.impl_decompress(wirebytes, S.MAXMSG)
    if status == DS.SIZE:
        return [], OUTCOME_SIZE, []
    if status in (DS.CORRUPT, DS.EOF):
        return [], OUTCOME_PROTO, []
    events = [{"kind": "msg", "op": {1: "text", 2: "binary"}[op],
               "payload": value.hex(), "t": "event"}]
    if op == 1:
        # A text message must decode to valid UTF-8 (RFC 6455 5.6):
        # invalid bytes are the terminal 1007, not a delivery.
        try:
            value.decode("utf-8")
        except UnicodeDecodeError:
            return [], {"outcomes": [
                {"code": 1007, "mod": "must", "term": "closeErr",
                 "wire": {"code": 1007, "kind": "coded"}}]}, []
    return events, None, ledger_for_wire(wirebytes)


def machine_check(wirebytes, label):
    """Q1 cross-check at the wire level: the machine's outcome class
    and output length agree with the reference on this wire."""
    st = S.initial()
    for b in wirebytes:
        st = S.step(st, b)
    st = G.with_tail(st)
    overflow = S.out_len(st) > S.MAXMSG
    status, _ = DS.impl_decompress(wirebytes, S.MAXMSG)
    if overflow != (status == DS.SIZE):
        return "machine/impl overflow disagree on %s" % label
    if status == DS.OK and S.out_len(st) != len(
            DS.impl_decompress(wirebytes, S.MAXMSG)[1]):
        return "machine/impl output disagree on %s" % label
    return None


def build(tid, side, frames, wirebytes, op=2):
    events, terminal, warnings = fin_expectation(wirebytes, op)
    tr = {
        "id": "%s_%s" % (tid, side),
        "machine": MACHINE,
        "side": side,
        "maxMessageSize": S.MAXMSG,
        "desc": "wire %s" % wirebytes.hex(),
        "rfc": ["RFC 7692 6.2", "RFC 7692 7.2.1"],
        "frames": [f.hex() for f in wire(frames, side)],
        "events": events,
        "terminal": terminal,
        "warnings": warnings,
    }
    if events and op == 1:
        tr["rfc"].append("RFC 6455 5.6")
    return tr


def gen():
    """Every trace, as {id: trace}. Deterministic."""
    traces = {}
    for (cls, o), path in sorted(G.witnesses().items()):
        name = "%s%d" % (cls, o)
        wirebytes = bytes(path)
        events, terminal, _ = fin_expectation(wirebytes, 2)
        for variant in ("fin", "frag", "ping"):
            if variant == "fin":
                frames = [frame(2, True, True, wirebytes)]
            else:
                if variant == "ping" and terminal is not None:
                    continue
                cut = 1 if len(wirebytes) > 1 else 0
                frames = [frame(2, False, True, wirebytes[:cut]),
                          frame(0, True, False, wirebytes[cut:])]
            if variant == "ping":
                frames.insert(1, frame(9, True, False, b""))
            tid = "S_%s_%s" % (name, variant)
            for side in SIDES:
                tr = build(tid, side, frames, wirebytes)
                if variant == "ping":
                    tr["events"] = [{"kind": "ctrl", "op": "ping",
                                     "t": "event"}] + tr["events"]
                    tr["rfc"].append("RFC 6455 5.5.2")
                err = machine_check(wirebytes, tid)
                if err:
                    raise AssertionError(err)
                traces[tr["id"]] = tr
    # Two complete streams in one message under the wire limit: the
    # canonical empty fixed block is two bytes (03 00), so two of them
    # fit; the decoder concatenates their output and delivers the
    # empty message. The spec walk faults on the first block already
    # (03 00 is a bad code under the RFC's literal fixed table -- the
    # empty block there is 13 00), so the delivery is counted under
    # lit-badcode. (The longer two-stream wire above the limit is a
    # wire-size trace, not a decompression one.)
    two = bytes((0x03, 0x00, 0x03, 0x00))
    for tid, frames in (("S_twostream",
                         [frame(2, True, True, two)]),
                        ("S_twostream_frag",
                         [frame(2, False, True, two[:2]),
                          frame(0, True, False, two[2:])])):
        for side in SIDES:
            tr = build(tid, side, frames, two)
            err = machine_check(two, tid)
            if err:
                raise AssertionError(err)
            traces[tr["id"]] = tr
    # A wire the spec classifier names tail-shape (the truncated
    # stored header's first octet is not 0x00/0x01) that the
    # implementation still delivers: the RFC-literal empty final
    # fixed block (13 00: EOB = 7-bit code 32) plus 0x04, which the
    # implementation's canonical decode reads as a literal, a
    # non-final EOB, and a final empty stored block from the tail.
    tailshape = bytes((0x13, 0x00, 0x04))
    for tid, frames in (("S_tailshape",
                         [frame(2, True, True, tailshape)]),
                        ("S_tailshape_frag",
                         [frame(2, False, True, tailshape[:1]),
                          frame(0, True, False, tailshape[1:])])):
        for side in SIDES:
            tr = build(tid, side, frames, tailshape)
            err = machine_check(tailshape, tid)
            if err:
                raise AssertionError(err)
            traces[tr["id"]] = tr
    # A decompression bomb under the wire limit: the repeated
    # length-3 / distance-1 code (0x02 each, from the 0b00000
    # pending) triplets the output; four wire bytes decode to nine,
    # past the limit, so the terminal is the decompressed-size 1009
    # (the only size outcome reachable: under the wire limit the
    # decoded output of a block is bounded by its wire bytes except
    # through repetition codes).
    bomb = bytes((0x03, 0x02, 0x02, 0x02))
    for tid, frames in (("S_bomb_fin", [frame(2, True, True, bomb)]),
                        ("S_bomb_frag",
                         [frame(2, False, True, bomb[:2]),
                          frame(0, True, False, bomb[2:])])):
        for side in SIDES:
            tr = build(tid, side, frames, bomb)
            err = machine_check(bomb, tid)
            if err:
                raise AssertionError(err)
            traces[tr["id"]] = tr
    # Two complete streams in one message: DONE starts the next stream
    # on the following byte; the output is the concatenation.
    stream_a = bytes(G.witnesses()[("done", 1)])
    stream_b = bytes(G.witnesses()[("done", 2)])
    wb = stream_a + stream_b
    for tid, frames in (("S_multi", [frame(2, True, True, wb)]),
                        ("S_multifrag",
                         [frame(2, False, True, wb[:2]),
                          frame(0, True, False, wb[2:])])):
        for side in SIDES:
            tr = build(tid, side, frames, wb)
            err = machine_check(wb, tid)
            if err:
                raise AssertionError(err)
            traces[tr["id"]] = tr
    # Text frames: the decoded payload is the UTF-8 validity test.
    text_ok = bytes(G.witnesses()[("done", 1)])  # decodes to one byte
    for side in SIDES:
        tr = build("S_textutf8", side, [frame(1, True, True, text_ok)],
                   text_ok, op=1)
        traces[tr["id"]] = tr
    # A wire whose decoded payload is invalid UTF-8 on a text frame:
    # a stored block with one raw 0xff byte (LEN = 1), which the 7.2.1
    # tail completes.
    raw_wire = b"\x00\x01\x00\xfe\xff\xff"
    for side in SIDES:
        tr = build("S_textutf8bad", side,
                   [frame(1, True, True, raw_wire)], raw_wire, op=1)
        traces[tr["id"]] = tr
    return traces


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "ws/testdata/deflstate"
    os.makedirs(out_dir, exist_ok=True)
    traces = gen()
    for tid in sorted(traces):
        path = os.path.join(out_dir, tid + ".json")
        with open(path, "w") as fh:
            json.dump(traces[tid], fh, indent=1, sort_keys=True)
            fh.write("\n")
    print("%d traces in %s" % (len(traces), out_dir))


if __name__ == "__main__":
    main()
