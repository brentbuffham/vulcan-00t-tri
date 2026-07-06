# Drift-band autopsy — intercepts v5-P2 decode (2026-07-06, Fable)

**Question (from viewer session):** ortho/plan view makes decoded points look far more
aligned than perspective — is the .00t decode "plan-view biased", or is delta drift
between sections causing it?

Scripts: `python/drift_band_map.py`, `python/drift_axis_autopsy.py`
Output: `python/drift_band_report.txt`. Data: P_base.npy (2937 pts) vs intercepts_gt.csv
(scoring only). Point-kind per emission tagged with byte position in coord stream.

## Verdicts

1. **Section-boundary drift: REJECTED.**
   Coord region has only **1** `e0 03` marker; 47 e0-class records total.
   Band onsets show NO spatial correlation with them: median gap onset→previous
   e0-record = 1792 B vs **2000 B for random good points** (control). Only 1/227
   onsets within 16 B. The 3-byte e0 skip in the tokenizer is not the drift source.

2. **"Plan-view algorithm": NO — but the observation was real and diagnostic.**
   XY-only match 46% vs 3D 25.9%. Z-dominant errors are 31% of bad points and
   invisible in plan; the surface is nearly flat (GT Z span 14.6 m), so perspective
   amplifies exactly the axis that ortho-top-down hides.

3. **Actual cause: single-register mis-splice (k0/carry), wandering thereafter.**
   - 39% of bad points have >90% of their L1 error on ONE axis
     (X 25% / Y 43% / Z 31%); the other two registers stay correct.
   - Error magnitudes cluster at **byte-position scales**: peaks at 2^7, 2^9,
     2^10 (674 pts), 2^11 — i.e. wrong splice offset / wrong carry in a HIGH
     mantissa byte, value stays in `band()` so the sanity gate can't catch it.
     Isolated island at 2^16 = the 35 wild ±100 km X points.
   - Bands **wander** (40 of 51 long bands) rather than hold a constant offset:
     subsequent DELTAs decode correctly *relative to a corrupted base* until a
     FULL rescues that register (only 440 FULLs in the whole stream).
   - 253 bad bands; onset/recovery point-kind mix (V vs FULLz) matches base rates —
     no single trigger record type.

## What this means

This is the KNOWN v5 wall (see `[[project_coord_codec_cracked]]`: "right except 81
event sites — hand-trace them"), now quantified on intercepts: **each band = one k0/
carry mis-decision on one axis register, then faithful relative decode on a bad
base.** Fixing the k0 event-site rule fixes whole bands at once — 253 decision
errors stand between 25.9% and near-perfect.

## Spec-shaped next step (Opus-executable)

For each of the 253 band-onset points (indices + byte positions in
`drift_band_report.txt`):
1. Load the onset token (`drift_band_map.py` meta gives token idx + byte pos).
2. Recompute `r2_value` exhaustively over (k0 ∈ 0..8−nb, carry ∈ −4..4) and record
   which (k0,c) reproduces the GT-nearest value **exactly** (teacher-forced, label
   as such).
3. Diff the winning (k0,c) against `k0_rule()`'s choice; cross-tab vs (T1,T2,nb,
   payload[0]) to extract the missing rule.
4. Validate GT-free: re-run decode with amended rule, report anchor % (was 760/2937
   <1 m) — regression: X/Z-exact map ≥ 970 must not drop.
