# Cold validation of v7 shorth bands (2026-07-06)

Question: does the v7 approach (dynamic container location + file-derived shorth
bands + self-healing carry search) generalize, or is it fit to intercepts?
Test: run the FAITHFUL v7 pipeline on two unseen files, offsets located
dynamically, bands derived from each file's own bytes, scored against each file's
DXF (scoring only). Scripts: `decode_v7_cold.py`, `cold_probe.py`,
`cold_band_validate.py`.

## Container offsets are per-file (found dynamically)
| file | seed_off | coord_start | seeds (X,Y,Z) |
|---|---|---|---|
| intercepts | 8326 | 8350 | 55963.9 / 162948.4 / 656.6 |
| SYLVANIA | 8328 | 8352 | 51601 / 212411 / 539.7 |
| OB34 | 8318 | 8342 | 53008 / 219000 / 521.2 |
Offsets shift a few bytes (variable prelude), but the format is identical: three
axes at well-separated magnitudes. `locate()` finds the first coord-like BE-double
triple → seeds; +24 → coord stream; e0-03 gap → face_start.

## Results (GT-FREE decode; DXF for scoring only)
| file | seen? | vertex count vs GT | decode <1m |
|---|---|---|---|
| intercepts | yes | 2950 / 2975 (99%) | **42.1%** |
| SYLVANIA | COLD | 213321 / 214709 (99.4%) | **19.3%** |
| OB34 | COLD | 241376 / 271914 (88.8%) | **7.9%** |
(Control: generalized pipeline reproduces intercepts 42.1% bit-identical to
decode_v7_carry.py, confirming faithful reproduction.)

## Verdict — HONEST
**The format model generalizes; the band effectiveness does not (consistently).**

- GENERALIZES: container location, record framing, coord grammar, axis-by-magnitude
  all transfer to unseen files. Vertex COUNTS are close (89–99%) — the tokenizer
  produces the right number of vertices on files it never saw. The method is NOT
  overfit to intercepts: it produces real, nonzero decodes (7.9–19.3%) cold.
- INCONSISTENT: accuracy drops on cold files (42% → 19% → 8%). Cause = band
  tightness. Shorth bands are SAFE (always cover the true extent — verified in
  cold_band_validate.py, covers=True on all axes/files) but only TIGHT where a
  file's FULL records are clean. Where FULLs are junk-heavy (OB34 all axes;
  SYLVANIA X), the band stays wide, drift is not rejected, score falls.
  - OB34 bands X[38718..70761] Y[206812..229005] Z[398..678] vs true
    X[52000..58200] Y[216900..219000] Z[504..630] — far too loose.

So v7's 42.1% on intercepts was partly a favorable-band case. The honest
cross-file rate is ~8–42%, and the single biggest lever is band tightness.

## Root cause of loose bands = misframing (ties to the open next-lead)
The junk in the FULL harvest is MISFRAMED records (8-byte doubles read at wrong
offsets / escape records mis-parsed). Better FRAMING would clean the FULL harvest
→ tighter bands → higher scores on ALL files, AND directly fix decode drift.
Misframing at Fe/escape records was already the prime suspect from FIRST500 /
SELECTOR_HUNT. Cold validation confirms it is the dominant cross-file bottleneck.

## Next
Failure/misframe census on v7 output (esp. Fe/escape record handling). Fixing
framing is now the highest-leverage move — it improves both band quality and the
direct decode, across all files, not just intercepts.
