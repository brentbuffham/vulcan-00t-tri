# First-500 rule extraction — result (2026-07-06)

Goal: fully solve the first 500 vertices of the intercepts file, GT-free.
Decoder: `decode_v6_clean.py` (file-derived ranges, no hand-tuning). Baseline
first-500 = **76/500** correct (<1m); full file = 601/2936 (20.5%).

## What we did
1. Instrumented every emitted vertex with per-axis write context (`trace_first500.py`,
   `ruleextract_first500.py`).
2. For broken vertices whose OTHER two axes are bit-exact, the two exact axes PIN
   the true GT vertex → the wrong axis's true value is known (no guessing).
3. Teacher-forced (k0, carry) on the corrupting token to hit that true value;
   checked BIT-EXACT vs approximate; cross-tabbed by (T1-class, nb).
4. Applied the resulting class→carry as a real GT-free rule and measured NET effect
   (`apply_carry_rule.py`).

## Results (GT for scoring/teacher-force only, never fed to decoder)
- 424/500 broken. Only **159 single-axis** (2 coords exact, 1 wrong). 265 are
  multi-axis / cascade damage — not a single mis-splice.
- Of 159 single-axis, **46 are bit-for-bit explainable** by some (k0, carry) of the
  corrupting token. These are REAL (exact, not <1m fudge) and cluster by class:
  - `T1=21-3F, nb=5` → (k0=2, **carry −2**): 11/13 exact
  - `T1=20, nb∈{4,5}` → (k0=3, **carry +2**): 14 exact
- **BUT applying the carry as a class rule CRATERS the decode:**
  | mode | first500 | full |
  |---|---|---|
  | off (v6-clean) | 76 | 601 |
  | carry a (21-3F,nb5→−2) | 4 | 41 |
  | carry b (20,nb4/5→+2) | 3 | 16 |
  | a+b | 2 | 6 |

## Verdict
The bit-exact carries are real but **context-dependent, and the context is NOT
(T1,T2,nb).** Some tokens of the identical class need the carry, some don't;
forcing it destroys the currently-correct ones. So:

- The value math is solved (exact when the target is known).
- The unsolved piece is **which adjustment applies to a given token** — a hidden
  STATE the encoder carries that we are not tracking. This is the documented core
  wall (Mystery E / phase-slot grammar), now localised precisely to the carry
  selector on single-axis tokens.
- No rule in the currently-tracked byte features (T1,T2,nb,payload,phase) pushes
  the first 500 past ~76. Verified, not assumed.

## Next detective question (hidden-state hunt — suited to a Fable session)
Within one class (e.g. `21-3F, nb=5`), what distinguishes the tokens that NEED
carry −2 from those correct with carry 0? Candidate selectors to test, GT-free:
- the preceding op-channel byte(s) / the 2-byte pre-token `lastT` value
- the SEP byte low bits beyond nb
- position in a running cycle since the last FULL on that axis
- whether the previous emission on this axis was itself carried
Method: from `ruleextract_first500.py`, tag each `21-3F,nb=5` token as
carry-needed vs carry-0, dump the surrounding bytes for both groups, and look for
a byte that separates them. If one does → that's the missing state → apply +
net-score. If none does at this quality → the selector is non-local (needs the
topology/op stream), escalate.

Artifacts: `trace_first500.py`, `ruleextract_first500.py`, `apply_carry_rule.py`,
`decode_v6_clean.py`, `test_continuity.py` (continuity ruled out: 16/500).
