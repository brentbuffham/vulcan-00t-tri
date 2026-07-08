# Z reconstruction hunt: the Z high byte is GEOMETRY — the encoder's Z reference is a SURFACE prediction, not the last Z (2026-07-08)

Follow-up to REFERENCE_COLUMN_HUNT (no vertex-value reference works) and
VALUE_SPLICE_HUNT (low-window value model). Scripts: `python/zhunt1..5.py`
(characterisation; GT for LABEL/SCORE only), `python/decode_v11_z.py` (the
fix, GT-free), `python/score25.py` (0.25 m scorer with GT cache).

PRIME DIRECTIVE held: GT (DXF) used only to pin true Z via bit-exact X/Y and
to score. The decoder consumes ONLY its own output (self-referential surface),
byte roles and codec-internal arithmetic. No per-file constants. Scoring
threshold this session: **0.25 m** (tightened from 1 m).

## 1. Characterising k (zhunt1/zhunt2, intercepts)

Pinned via exact X/Y (unique GT vertex): 1930 of 2964 decoded verts →
cleanZ 1317, yellowZ (|dZ| ≥ 0.25) 548, mid 65.

- Record-class census: yellow is nb=4 (b03, T1 21-3F) 275 + nb=5 (b04) 192;
  clean is nb=5 741 + nb=6 306 + FULL 155. **nb=6 / FULL records are never
  yellow** (byte 2 transmitted — confirms VALUE_SPLICE).
- Teacher-forcing (k0 placement × dh ±300): **547/548 yellow reconstruct
  bit-exact from (register, payload)** — the payload window is fine, only the
  reconstructed hi bytes (the window count k) are wrong. Winning placement is
  plc3 (payload = bytes 3..7 / 3..6); onset dh ranges ±2..±77 (median |dh| 4,
  far tail to 77 = 9.6 m).
- Only 104/548 are onsets (previous Z clean); 443 are inherited episodes
  (nb=4 keeps bytes 0..2 from the register, so one wrong onset paints a whole
  serpentine row — the "diagonal bands").

## 2. Where k does NOT come from (all tested, all dead)

- **The record's own bytes**: yellow-Z records are genuinely nb=4/nb=5 by
  their lead byte (b=03/04); no skipped byte-2 in the record; no nb=6 re-read.
- **Stream-byte correlation at onsets** (T1, T2, lead b, prev-record nb,
  X/Y-record T bytes and nb, payload bytes): all |corr| ≤ 0.44 and the
  strongest (b, prev_nb) are trivially confounded with record length; SAME
  T bytes appear with different dh (T=20bf → dh +28 and +44). **k is not
  transmitted in any local byte.** E0-class (W2 axis-state) tokens: none
  adjacent to yellow-Z records at all (E[] empty at every onset dumped).
- **Value references** (zhunt1 reference scan, |ref − trueZ| < half-window
  0.0625 m): last Z 1/548, last Z FULL 1/548, parallelogram-in-emission
  10/548, mean4/med4 ≤ 8/548, FULL+run 7/548. Nothing.

## 3. Where k DOES come from (zhunt3/zhunt4): the SURFACE

- **GT oracle**: a plane through the 3 XY-nearest GT vertices, evaluated at
  the yellow vertex's exact (X,Y), predicts trueZ with **median error
  0.029 m — 463/548 yellow, 1052/1317 clean, 45/65 mid inside the 0.0625 m
  half-window** (best 3-of-8 subset: 547/548). One uniform mechanism across
  all classes: **the encoder's Z reference is a local surface (planar /
  mesh-parallelogram) prediction at the already-transmitted (X,Y)** — which
  is exactly what a coordinate decoder can reproduce, because X and Y of the
  vertex are decoded BEFORE its Z in the X→Y→Z cycle.
- Causal restriction (earlier-emitted vertices only, true values): median err
  0.047 m, p90 0.133 — 53% inside the half-window, ~90% within 1.5 windows
  (= still < 0.25 m after nearest-congruent snap). The encoder-visible info
  is there causally.
- This also explains REFERENCE_COLUMN_HUNT's oracle failure: no single
  vertex VALUE is within 0.0625 m (nearest-3D-neighbour median err 0.50 m =
  local relief), but a plane through them is.

## 4. The fix: decode_v11_z.py (GT-free, self-referential surface)

For every Z V-record:
1. **Surface prediction**: median of plane-interpolations over all 3-subsets
   of the 8 XY-nearest previously decoded vertices (robust to a minority of
   corrupted priors), queried from an incremental grid (cell = 2× median
   decoded XY step). ANCHOR-preferred: if ≥4 of the 40 nearest are anchors
   (Z from FULL/Fe, nb≥6, or nb=5 at effective plc2 — the byte-2-transmitted
   classes), fit on anchors only. Returns (median, IQR=confidence).
2. **Hybrid selection**: keep v10's nearest-to-last candidate unless it
   disagrees with the prediction by > ZTH (=0.5) window units at its
   effective placement — then rebuild the hi bytes FROM the prediction
   (recovers far-dh onsets; ±1 hi step, tail from register). plc2 records
   have ~32 m windows so are automatically protected: distance-to-ref must
   never arbitrate placement (REFERENCE_COLUMN_HUNT §3 trap, re-confirmed:
   an ordered absolute-tolerance selection scored 33% — the low placement
   can always park near any reference).
3. **Confidence-gated placement flip**: nb=5 parsed at plc2 sitting > 4
   windows from a CONFIDENT surface (IQR ≤ 1 window) while the plc3 rebuild
   lands within 1 window → flip to plc3 (the fold/plc3-truth class; ~46
   sites recovered).
4. **Multi-pass**: pass 1 incremental (causal); passes 2+ re-decode against
   the previous pass's full surface (the decoder's OWN output — later rows
   repair earlier bands). Converges by pass 3–4.

## 5. Scores (GT-free decode; DXF scoring only; 0.25 m)

FINAL config: ZTH 0.5, ZGATE 16 windows, 3 passes
(`python decode_v11_z.py <case> 0.5 3 16`).

| file | v10 baseline (0.25 m) | **v11 final** | net (gain/regr) | <1 m before→after |
|---|---|---|---|---|
| intercepts (seen) | 1384/2964 (46.7%), yellow 558 | **1543/2964 (52.1%), yellow 399** | **+159** (+168/−9) | 54.4% → 59.5% |
| SYLVANIA (COLD)   | 80673/214177 (37.7%), yellow 37056, first500 247 | **93640/214177 (43.7%), yellow 24089, first500 260** | **+12,967** (+15,548/−2,581) | 48.9% → 54.4% |
| OB34 (COLD)       | 22867/251858 (9.08%) fresh baseline | 22869/251858 (9.08%) | **+2** (+468/−466) — neutral wash | 10.95% → 11.0% |

Biggest absolute gain on the cold file — same arithmetic, no per-file
constants: not a fingerprint. Ungated variant (no ZGATE) reaches 53.3% on
intercepts and 43.1% on SYLVANIA but REGRESSES OB34 (9.08→7.3%) — see below.
(The OB34 v10 npy on disk was stale — from an older script build, X/Y differ;
its 8.71% was not a valid baseline. Regenerated fresh: 9.08%. The
intercepts/SYLVANIA npys were bit-identical in X/Y to v11's, as expected for
a Z-only rule.)

**OB34 catch (ungated run): 9.08% → 7.3%.** OB34's decode is already
globally broken (X FULL-harvest junk, MISFRAME_CENSUS diagnosis; its median
decoded XY step is ~205 m, grid cell 410 m), so "XY-neighbours" are
geometric nonsense there and the surface wrongly overrode good candidates
(yellow 8802 → 14957). Fix: the CONFIDENCE GATE — the ensemble IQR returned
by plane_ref must be ≤ ZGATE (=16) windows for any surface override
(codec-internal, self-measured; a meaningless neighbourhood leaves v10
behaviour untouched). Gate sweep on intercepts: no-gate 53.3% > 16u 52.1% >
8u 51.4% > 4u 51.1% > 2u 50.6% — the gate costs a little on a healthy file;
it exists for cold safety. It cut regressions hard (intercepts 41→9,
SYLVANIA 7,062→2,581), RAISED SYLVANIA overall (43.1→43.7, first500
242→260), and turned OB34 from a regression into a wash (the correct
behaviour: OB34's Z bottleneck is its FULL/band harvest, not the Z
reference — unchanged MISFRAME_CENSUS diagnosis).

## 6. Residue / open

- Intercepts residual yellow 399 (zhunt5 diagnosis of the near-final build):
  ~310 sites where the decoded surface is still locally corrupted
  (band-dominated neighbourhoods, false plc2 anchors), ~46 placement-flip
  sites below the confidence gate, plus the ~85/548 sites where even the
  full-GT plane misses the half-window (true surface discontinuities —
  those need the encoder's actual mesh parallelogram, i.e. the faces
  decode).
- SYLVANIA residual yellow 24k: GT-plane oracle on a 4k strict-pin sample
  says **77% still recoverable in principle** (median GT-plane err 0.076 m)
  — surface bootstrap quality, not missing information.
- The exact encoder predictor is still unknown (plane-of-which-3?
  Draco-style mesh parallelogram over the gate triangle?); the robust
  median-of-planes is a stand-in that is within half a window ~80% of the
  time on healthy neighbourhoods. The faces/topology decode would give the
  true gate triangle and should close most of the remaining gap — and is
  the only path for the ~85 discontinuity sites.
- The X analogue is NOT covered: X folds (200 m jumps, 8 m windows) are a
  different geometry (X is the scan coordinate; a surface in (Y,Z)→X makes
  no sense on a topo). X singles remain the second-largest error pool.
- OB34 is still bottlenecked by FULL/band harvest (X band 37320..69627 junk)
  — the Z rule can't engage there until framing improves.

## 7. Spec-shaped next step (for an Opus session)

1. **Placement-flip census, cross-file** (cheap): on SYLVANIA pins (better
   statistics than intercepts' hundreds), census nb=5/21-3F records whose
   teacher-forced placement is plc3 against context (prev Z-record nb, prev
   V-record nb, T2 bits, post-FULL distance). If a clean byte-role context
   emerges, replace the geometric confidence-gated flip with it (validate
   cold, Rule-B discipline).
2. **Two-pass surface hardening**: pass-2+ currently trusts all pass-1
   points equally except anchors. Add a residual filter: drop from the
   static grid any vertex whose pass-1 Z disagrees with the anchor-only
   surface by > 2 windows before re-decoding (still GT-free). Expected to
   eat into the ~310 band-corrupted-neighbourhood sites.
3. **Port to js/vulcan00TParser.js** once stable: the surface machinery is
   a straight port (grid + median-of-planes + the r2_v11 selection order).

Scripts: `python/zhunt1.py` (instrumented decode + k census),
`zhunt2.py` (teacher-force placements/dh), `zhunt3.py` (decoded-surface
refs), `zhunt4.py` (GT oracle + dh-byte correlations), `zhunt5.py`
(residual diagnosis), `decode_v11_z.py` (the decoder;
`<case> [ZTH] [NPASS] [ZGATE]`, defaults = the validated 0.5 / 3 / 16),
`score25.py <case> <npy>` (0.25 m scorer, caches GT_<case>.npy).
