"""The exact UTF-8 boundary machine: RFC 3629 transformation, pure-RFC.

This module is the careful transformation of RFC 3629's UTF-8 definition
(doc/rfc3629.txt: the octet sequence table in Section 3 and the ABNF in
Section 4) into an explicit state machine over *fragment boundaries*. A
boundary state answers one question: given that the bytes accumulated so
far end exactly here, what does the UTF-8 decoder know?

  * which continuation bytes are still acceptable (the acceptance set),
  * what the boundary becomes when more bytes are appended (the successor).

A state is a distinct (acceptance set, successor) pair: two boundary
positions with the same pair are the same state, and every distinct pair
is a state. That is what makes the machine exact -- the state determines
the outcome of appending any byte, and appending is compositional
(``apply`` is the fold of ``step``), so a message assembled from fragments
is validated exactly as RFC 6455 5.6 requires: on the whole
concatenation, never on a fragment. A fragment may legally end mid-rune
and still yield a valid message; only an invalid byte (a byte that is
wrong in every context) makes the concatenation unrepairable, which is
what BROKEN means.

The pending states fall into two families. The wide states (PEND1,
PEND3, PEND4, PEND4K2) accept the full continuation range 80-BF. The
narrow states are the spec's own hazard classes, each with its own
acceptance set and its own reason:

  * PEND_E0  -- after E0: accepts A0-BF, the overlong-3-byte guard;
  * PEND_ED  -- after ED: accepts 80-9F, the surrogate range guard
                (U+D800-U+DFFF are not encodable);
  * PEND_F0  -- after F0: accepts 90-BF, the overlong-4-byte guard;
  * PEND_F4  -- after F4: accepts 80-8F, the maximum code point
                (U+10FFFF).

Everything here is derived from the RFC, not from any implementation's
UTF-8 package. The concrete acceptance sets are checked verbatim against
the Section 4 ABNF by check_utf8props.py.

This module is the single source of truth for UTF-8 boundary semantics
shared by the frame-reassembly machine (common.py) and the RSV1 /
compressed-message machine (deflate.py): both track their fragment
accumulations through these states instead of re-deriving the rules.
"""

# --- The states -------------------------------------------------------------

CLEAN = "CLEAN"      # a code-point boundary; the next byte starts a sequence
BROKEN = "BROKEN"    # an invalid byte has occurred; absorbing
PEND1 = "PEND1"      # one continuation byte wanted, wide (80-BF): after
                     # C2-DF, after the 2nd byte of a 3-byte sequence, or
                     # after the 3rd byte of a 4-byte sequence
PEND_E0 = "PEND_E0"  # after E0; accepts A0-BF (overlong-3 guard)
PEND3 = "PEND3"      # after E1-EC / EE-EF (3-byte lead); accepts 80-BF
PEND_ED = "PEND_ED"  # after ED; accepts 80-9F (surrogate guard)
PEND_F0 = "PEND_F0"  # after F0; accepts 90-BF (overlong-4 guard)
PEND4 = "PEND4"      # after F1-F3 (4-byte lead); accepts 80-BF
PEND_F4 = "PEND_F4"  # after F4; accepts 80-8F (max code point)
PEND4K2 = "PEND4K2"  # two of four bytes received; accepts 80-BF

STATES = [
    CLEAN, BROKEN,
    PEND1, PEND_E0, PEND3, PEND_ED, PEND_F0, PEND4, PEND_F4, PEND4K2,
]

# The documented acceptance sets (low, high inclusive), per the RFC 3629
# Section 4 ABNF. Data, not logic: check_utf8props.py verifies that the
# transition table agrees with it on every byte.
ACCEPTS = {
    PEND1: [(0x80, 0xBF)],
    PEND_E0: [(0xA0, 0xBF)],
    PEND3: [(0x80, 0xBF)],
    PEND_ED: [(0x80, 0x9F)],
    PEND_F0: [(0x90, 0xBF)],
    PEND4: [(0x80, 0xBF)],
    PEND_F4: [(0x80, 0x8F)],
    PEND4K2: [(0x80, 0xBF)],
}

# The successor a pending state moves to on an accepted continuation byte,
# per the ABNF (each UTF8-char is lead byte(s) followed by UTF8-tail octets,
# the last of which lands on a code-point boundary).
ACCEPT_NEXT = {
    PEND1: CLEAN,
    PEND_E0: PEND1,
    PEND3: PEND1,
    PEND_ED: PEND1,
    PEND_F0: PEND4K2,
    PEND4: PEND4K2,
    PEND_F4: PEND4K2,
    PEND4K2: PEND1,
}


def _next(state, b):
    """The successor of (state, byte), derived from the Section 3 table and
    the Section 4 ABNF. Total over 0-255: every (state, byte) has exactly
    one successor."""
    if state == BROKEN:
        # An invalid byte is invalid in every context: the concatenation
        # can never become valid, no matter what follows.
        return BROKEN
    if state == CLEAN:
        if b <= 0x7F:
            # UTF8-1: a complete one-octet code point.
            return CLEAN
        if 0xC2 <= b <= 0xDF:
            # UTF8-2 lead: one wide tail wanted.
            return PEND1
        if b == 0xE0:
            return PEND_E0
        if 0xE1 <= b <= 0xEC or 0xEE <= b <= 0xEF:
            # UTF8-3 lead (wide): two tails wanted.
            return PEND3
        if b == 0xED:
            return PEND_ED
        if b == 0xF0:
            return PEND_F0
        if 0xF1 <= b <= 0xF3:
            # UTF8-4 lead (wide): three tails wanted.
            return PEND4
        if b == 0xF4:
            return PEND_F4
        # 80-BF: a continuation byte with no lead (stray); C0/C1 and
        # FE/FF appear in no ABNF alternative (overlong leads,
        # forbidden values). Invalid.
        return BROKEN
    # A pending state: an accepted continuation advances to the documented
    # successor; any other byte (wrong range, a new lead, ASCII) is wrong
    # in this position.
    for lo, hi in ACCEPTS[state]:
        if lo <= b <= hi:
            return ACCEPT_NEXT[state]
    return BROKEN


# The full transition table: TABLE[i][b] is the successor of (STATES[i], b).
# Built once from _next; the table is the source the step/apply fast path
# and the property checks both consult, so they cannot disagree.
TABLE = [[_next(s, b) for b in range(256)] for s in STATES]
STATE_IDX = {s: i for i, s in enumerate(STATES)}


def step(state, byte):
    """One byte of the boundary machine."""
    return TABLE[STATE_IDX[state]][byte]


def apply(state, payload):
    """Fold the boundary machine over the bytes of payload: the boundary
    state after appending payload to an accumulation that ended at
    ``state``. This is how a fragment's bytes (or a decompressed chunk's)
    update the tracked boundary."""
    s = state
    for b in payload:
        s = TABLE[STATE_IDX[s]][b]
    return s


def is_complete(state):
    """Whether an accumulation ending at ``state`` is valid UTF-8 as a
    whole: a code-point boundary (RFC 6455 5.6's check on a message)."""
    return state == CLEAN


def accepts(state, byte):
    """Whether byte is an acceptable continuation at boundary state
    (the documented acceptance set; CLEAN has none -- every byte from
    CLEAN is a start, not a continuation)."""
    return any(lo <= byte <= hi for lo, hi in ACCEPTS.get(state, []))


# --- Self-consistency ---------------------------------------------------------

# The byte sequences that reach each pending state from CLEAN; used by the
# edge-coverage property so every acceptance set is probed at its own
# boundaries, in its own state.
REACH = {
    PEND1: b"\xc2",
    PEND_E0: b"\xe0",
    PEND3: b"\xe1",
    PEND_ED: b"\xed",
    PEND_F0: b"\xf0",
    PEND4: b"\xf1",
    PEND_F4: b"\xf4",
    PEND4K2: b"\xf0\x90",
}

# A deterministic validity corpus: every hazard class the ABNF defines, at
# its edges. Three classes, because the machine distinguishes them:
# valid entries land on CLEAN; broken entries contain a byte that is wrong
# in every context (unrepairable, BROKEN); truncated entries end mid-rune
# (invalid as a whole, but repairable -- a pending state, not BROKEN).
_CORPUS_VALID = [
    b"",                                   # the empty message
    b"A", b"AB",                           # one- and two-octet code points
    b"\xc2\x80",                           # U+0080, minimum 2-byte
    b"\xc3\xa9",                           # U+00E9, mid 2-byte
    b"\xdf\xbf",                           # U+07FF, maximum 2-byte
    b"\xe0\xa0\x80",                       # U+0800, minimum 3-byte
    b"\xe2\x82\xac",                       # U+20AC, mid 3-byte
    b"\xed\x9f\xbf",                       # U+DFFF, maximum below surrogates
    b"\xef\xbf\xbf",                       # U+FFFF, maximum 3-byte
    b"\xf0\x90\x80\x80",                   # U+10000, minimum 4-byte
    b"\xf0\x9f\x98\x80",                   # U+1F600, mid 4-byte
    b"\xf4\x8f\xbf\xbf",                   # U+10FFFF, the maximum code point
    b"\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80",  # a mixed run
]
_CORPUS_BROKEN = [
    b"\x80",                               # stray continuation, no lead
    b"\xc3\x28",                           # 2-byte with a non-continuation 2nd byte
    b"\xc0\xaf",                           # overlong 2-byte (the C0/C1 leads)
    b"\xe0\x80\x80",                       # overlong 3-byte (the E0 guard)
    b"\xed\xa0\x80",                       # a surrogate (the ED guard)
    b"\xf0\x80\x80\x80",                   # overlong 4-byte (the F0 guard)
    b"\xf4\x90\x80\x80",                   # beyond U+10FFFF (the F4 guard)
    b"\xf7\xbf\xbf\xbf",                   # a lead outside the F0-F4 range
    b"\xff",                               # a byte invalid in every context
    b"\xc3\xa9\x80",                       # valid prefix, stray continuation
    b"AB\xff",                             # valid prefix, an invalid byte
]
# Truncated: ends mid-rune. The entry is invalid as a whole, but the boundary
# is a pending state, not BROKEN -- the missing continuation may still
# arrive, and RFC 6455 5.6 checks the message, so a fragment may legally
# end here.
_CORPUS_TRUNCATED = {
    b"\xc3": PEND1,
    b"\xe1": PEND3,
    b"\xed\x9f": PEND1,
    b"\xf1": PEND4,
    b"AB\xc3": PEND1,
    b"\xe0": PEND_E0,
    b"\xf0\x90": PEND4K2,
}


def self_check():
    """Self-consistency of the boundary machine, pure Python.

    Returns a list of failure strings (empty when all pass):

      B1  totality: every (state, byte) pair has a defined state;
      B2  BROKEN is absorbing;
      B3  the table agrees with the documented acceptance data: from each
          pending state, every accepted byte moves to the documented
          successor and every other byte moves to BROKEN;
      B4  corpus validity: every valid corpus entry lands on CLEAN, every
          broken one on BROKEN, every truncated one on its exact pending
          state, from CLEAN;
      B5  composition: apply(s, a+b) == apply(apply(s, a), b) over the
          corpus, from every state;
      B6  edge coverage: every acceptance set is probed at its low and
          high edges -- accepted at both, rejected just outside both --
          in the state that has that set;
      B7  decoder cross-check: apply(CLEAN, s) is CLEAN exactly when the
          platform's UTF-8 decoder accepts s, over a large deterministic
          pseudo-random corpus plus every two- and three-byte combination
          of the alphabet's interesting bytes (an independent oracle for
          the table; the table itself stays RFC-derived).
    """
    failures = []

    # B1: totality.
    for s in STATES:
        row = TABLE[STATE_IDX[s]]
        if len(row) != 256:
            failures.append("B1: row for %s has %d entries" % (s, len(row)))
            continue
        for to in row:
            if to not in STATES:
                failures.append("B1: %s + byte -> %r not a state" % (s, to))

    # B2: BROKEN absorbing.
    for b in range(256):
        if step(BROKEN, b) != BROKEN:
            failures.append("B2: BROKEN + 0x%02x -> %s" % (b, step(BROKEN, b)))

    # B3: the table agrees with the documented acceptance data.
    for state in ACCEPTS:
        succ = ACCEPT_NEXT[state]
        for b in range(256):
            got = step(state, b)
            want = succ if accepts(state, b) else BROKEN
            if got != want:
                failures.append("B3: %s + 0x%02x -> %s, want %s"
                                % (state, b, got, want))

    # B4: corpus validity from CLEAN -- three classes.
    for entry in _CORPUS_VALID:
        if apply(CLEAN, entry) != CLEAN:
            failures.append("B4: valid %r lands at %s" % (entry, apply(CLEAN, entry)))
    for entry in _CORPUS_BROKEN:
        if apply(CLEAN, entry) != BROKEN:
            failures.append("B4: broken %r lands at %s, want BROKEN"
                            % (entry, apply(CLEAN, entry)))
    for entry, want in _CORPUS_TRUNCATED.items():
        got = apply(CLEAN, entry)
        if got != want:
            failures.append("B4: truncated %r lands at %s, want %s" % (entry, got, want))

    all_entries = _CORPUS_VALID + _CORPUS_BROKEN + list(_CORPUS_TRUNCATED)

    # B5: composition (apply is the fold of step).
    for s in STATES:
        for a in all_entries:
            for b in all_entries:
                if apply(s, a + b) != apply(apply(s, a), b):
                    failures.append("B5: apply(%s, %r+%r) disagrees with the fold"
                                    % (s, a, b))
                    break
            else:
                continue
            break

    # B6: edge coverage of every documented acceptance set.
    for state, ranges in ACCEPTS.items():
        mid = apply(CLEAN, REACH[state])
        if mid != state:
            failures.append("B6: REACH[%s] = %r lands at %s, want %s"
                            % (state, REACH[state], mid, state))
            continue
        for lo, hi in ranges:
            if not accepts(state, lo) or step(state, lo) != ACCEPT_NEXT[state]:
                failures.append("B6: %s + 0x%02x (low edge) not accepted" % (state, lo))
            if not accepts(state, hi) or step(state, hi) != ACCEPT_NEXT[state]:
                failures.append("B6: %s + 0x%02x (high edge) not accepted" % (state, hi))
            if lo > 0x00 and step(state, lo - 1) != BROKEN:
                failures.append("B6: %s + 0x%02x (just below) accepted, want BROKEN"
                                % (state, lo - 1))
            if hi < 0xFF and step(state, hi + 1) != BROKEN:
                failures.append("B6: %s + 0x%02x (just above) accepted, want BROKEN"
                                % (state, hi + 1))

    # B7: decoder cross-check over a deterministic corpus.
    import random
    r = random.Random(3629)
    corpus = []
    for _ in range(20000):
        corpus.append(bytes(r.randrange(256) for _ in range(r.randrange(0, 13))))
    interesting = [0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF,
                   0xC0, 0xC2, 0xDF, 0xE0, 0xED, 0xF0, 0xF4, 0xF7, 0xFE, 0xFF]
    for a in interesting:
        for b in interesting:
            corpus.append(bytes([a, b]))
            corpus.append(bytes([a, b, 0x80]))
    for entry in corpus:
        table_says = apply(CLEAN, entry) == CLEAN
        try:
            entry.decode("utf-8")
            decoder_says = True
        except UnicodeDecodeError:
            decoder_says = False
        if table_says != decoder_says:
            failures.append("B7: %r: table=%s decoder=%s"
                            % (entry, table_says, decoder_says))
            if len(failures) > 30:
                break

    return failures


if __name__ == "__main__":
    bad = self_check()
    if bad:
        for line in bad:
            print("FAIL", line)
        raise SystemExit("utf8bound check failed (%d)" % len(bad))
    print("utf8bound check: B1-B7 pass (%d states x 256 bytes)" % len(STATES))
