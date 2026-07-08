# Slot alignment (MYSTERY_A_HUNT §NEXT #1) — executed, BLOCKED, redirected (2026-07-08 Opus)

Task from MYSTERY_A_HUNT.md: pin decode_v11's 11 dropped emissions (2964 rows
vs 2975 GT verts) to get absolute true-slot indexing, "Opus-executable,"
prerequisite for the scheduler attack. Scripts: `python/ma_slotdiag.py`
(gap diagnosis), `python/ma_slotanchor.py` (ref-anchored objective test). GT
(DXF verts/faces) used for LABELING/SCORING only.

## What was established (solid)

1. **The 11-gap is a real vertex-count gap, not decoder junk.** All 2975 GT
   verts are face-referenced (0 unreferenced). The mesh has a **boundary**:
   5724 faces vs 5946 for a closed sphere (Δ222) → it is an OPEN terrain patch,
   so the simple-mesh invariants `t=2v−4` / `C=v−2` are RELAXED. This confirms
   the cut-border-machine / border-handling EdgeBreaker variant (MYSTERY_A_HUNT
   headline). Only 4 v11 rows are near-duplicate positions (2508/2514/2519/2963).

2. **Refs index the TRUE 2975-slot space — model CONFIRMED and bounded.**
   Explicit ref indices range [0..2970]: **6 refs exceed v11's max row (2963),
   none exceed 2974.** Impossible under v11-compressed indexing, valid under the
   true 2975-slot space → the "R/L op carries an explicit TRUE-slot index" model
   is right, and the slot space is exactly ~2975 wide.

## Why alignment is BLOCKED (the spec's assumption was false)

The spec assumed a dense-enough answer map so that the 11 drops could be located
by "row-gap vs graph-distance" and the rows shifted. Two measurements kill that:

- **decode_v11 REACHES only 1931/2975 true slots** (3D-hit 1451 + XY-exact 480);
  1044 slots are never reached. The answer map is inherently ≤65%.
- **The strong ref-anchored objective is at noise under every model.** Over all
  3336 refs in stream order, "consecutive ref → GT vertex is a mesh neighbor of
  the previous ref's vertex": identity 6.0%, best global shift (−1) 8.4%,
  greedy-drops 5.7%. 70.6% of refs land on a MAPPED slot, so this is NOT a
  coverage artifact. Random baseline is ~0.2% (valence/nverts), so 6–8% is weak
  real structure — but nowhere near the ~100% expected if refs were correct.
- **The decisive diagnostic:** same-group multi-ref pairs are a face's SHARED
  EDGE — they MUST be mesh-adjacent — yet land adjacent only **15%** (9/60,
  MYSTERY_A_HUNT; reconfirmed here). A forced-adjacent relation coming out at
  15% means the **ref INDICES are being decoded incorrectly** (the delta-splice
  ref-index reconstruction), OR the rail-clusterer's group order ≠ true emission
  order. Row-realignment of a correct map cannot fix a wrong map.

## Redirect (the real prerequisite)

Slot alignment does NOT cleanly separate from the scheduler as the spec hoped.
The prerequisite for BOTH is **correct ref-index decoding**: make same-group
ref pairs resolve to actual shared edges (target: same-group adjacency ≫15%,
toward ~100%). That is a STREAM-DECODING problem (how the explicit true-slot
index is delta-spliced/encoded in the ref-carrying e003 group) — detective work,
not mechanical row-shifting.

### Spec for the next Fable session (replaces #1)
1. **Fix ref-index decoding.** Dump the ref-carrying e003 groups' bytes; the
   payload should encode a true-slot index (0..2974). Current extraction yields
   indices whose same-group pairs are mesh-adjacent only 15% → wrong. Find the
   correct field/delta rule. VALIDATION (GT-free-capable): the two refs of a
   split-quad group must be an emission-adjacent pair; score by same-group
   adjacency rate against the *emission-order* walk (P_v11 adjacency is 92.3%
   GT-edge, usable as the target lattice). Cross-check: the 6 refs in
   (2963,2970] must resolve to plausible boundary verts.
2. Only once same-group adjacency is high does true-slot realignment become the
   trivial monotonic shift the spec imagined — revisit then.

## Artifacts
- `python/ma_slotdiag.py` — gap characterization (unref verts, dups, coverage,
  ref range).
- `python/ma_slotanchor.py` — ref-anchored alignment objective sweep (identity /
  global shift / greedy drops) + coverage ceiling.
- Consumes `map11.pkl`, `rails.pkl`, `faces_gt.npy`, `intercepts_gt.csv`,
  `P_v11_intercepts.npy`.
