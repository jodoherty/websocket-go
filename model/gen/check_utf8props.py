"""UTF-8 boundary machine self-consistency checks, pure Python.

Run by `make utf8-model` (and by `make model`, which depends on it). These
validate the shared boundary machine (utf8bound.py) that both the
frame-reassembly machine and the RSV1 / compressed-message machine build
on:

  B1  totality: every (state, byte) pair has a defined state;
  B2  BROKEN is absorbing;
  B3  the transition table agrees with the documented acceptance sets
      (the RFC 3629 Section 4 ABNF, on every byte of every pending state);
  B4  corpus validity: the hazard-class corpus lands exactly where the
      ABNF says (overlong, surrogate, over-max, truncated, stray);
  B5  composition: apply is the fold of step;
  B6  edge coverage: every acceptance set is probed at its own low/high
      edges, in the state that has that set;
  B7  decoder cross-check: the table agrees with the platform's UTF-8
      decoder over a large deterministic corpus (an independent oracle;
      the table itself stays RFC-derived).

A failure here means the shared boundary machine -- and therefore every
machine built on it -- is wrong; fix utf8bound.py and re-run.
"""

import sys

import utf8bound as U


def main():
    failures = U.self_check()
    if failures:
        for line in failures:
            print("FAIL", line, file=sys.stderr)
        sys.exit("utf8bound check failed (%d)" % len(failures))
    print("utf8bound check: B1-B7 pass (%d states x 256 bytes, "
          "%d acceptance sets)" % (len(U.STATES), len(U.ACCEPTS)))


if __name__ == "__main__":
    main()
