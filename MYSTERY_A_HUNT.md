# MYSTERY A HUNT — 2026-07-08 Fable session (post-parallelogram-proof)

Input: PARALLELOGRAM_PROOF.md (coords are gate-parallelogram-predicted against
the connectivity; coords+faces = one traversal). Target: the C/R/L/E/S op
grammar of the intercepts faces section. This doc states what got PINNED, what
got REFUTED, and the spec for the next session. All scores state their
category. Scripts: `python/ma_*.py`; artifacts listed at the end.

## HEADLINE

**Mystery A's record-level op semantics are now essentially closed.** The .00t
faces stream is a cut-border-machine EdgeBreaker variant:

- **C op = the idless `e003` group.** Appends ONE new vertex, whose emission
  slot comes from the per-strip serpentine counter (RESUME-07-08 law, re-verified
  90.7% on the new dense map). No index is transmitted — allocation is decoder
  state. C ≈ GT C-face count (2710 groups vs 2894 GT C-faces).
- **R/L op = the ref-carrying `e003` group.** Appends ONE existing vertex,
  transmitted as an EXPLICIT emission-slot index (delta-spliced — this is why
  the textbook gate-offset stack never balanced: the variant sends indices
  instead of deriving tips from the gate; "R vs L" is not an op bit, it falls
  out of strip phase).
- **Face law = last-3-of-sequence.** Per strip, refs and allocations form one
  merged vertex sequence in group order; every group emits the triangle of its
  strip's last 3 vertices. Zigzag ⇒ quad split A `(rp,rk,np)+(rk,np,nk)` or
  split B `(rp,rk,nk)+(rp,np,nk)`; a fan step (ref unchanged) emits
  `(r, n_prev, n_k)` and flips the zigzag phase.
- **The op bytes carry NO per-face choice** (re-confirmed twice at pair level:
  op-byte census vs measured split label — no discrimination; `ma_opsplit.py`,
  `ma_final.py`). First-op arg 6-bit field = the global +6 phase clock
  (RESUME-07-10 stands). Delims: `e0:03` face group; `e0:02`×216 / `e0:04`×225
  remain the S/E (strip push/pop) CANDIDATES — counts push/pop-shaped, still
  unproven at record level.

**What remains open is NOT op semantics — it is the SCHEDULER**: which strip
each group belongs to (round-robin turn assignment), and each strip's init
(n0, d). Mystery A's residual wall and the allocation wall (RESUME-07-08/09/10)
have MERGED into this single unknown.

## EVIDENCE (numbers by category)

### New answer-key map (mechanism testing only — not a decode)
`ma_map11.py`: built `map11.pkl` from P_v11 (GT-matched): **1931/2964 slots**
(1451 3D<5cm unique + 480 XY-exact Z-drift class). Quality check:
emission-adjacent mapped pairs are GT mesh edges **92.3%** (1471/1594 at row-gap
1) — the emission order is itself a serpentine mesh walk, far cleaner than the
old P_base map (which map11 contradicts almost everywhere: the two decoders
drop different records; indexing is decoder-relative. `ma_map11b.py`,
`ma_truemap.py`: 20 drop-candidate sites found at GT graph-distance 2;
true-slot realignment inconclusive — same-group ref pairs are too few/noisy to
anchor absolute slot indexing. Local mechanism tests are shift-tolerant;
absolute alignment is a listed next step.)

### Face laws (GT faces used to LABEL/SCORE only)
- **Fan law: 49/49 = 100%** (`ma_gate3.py` curated dr=0 sites): face
  `(r, n_prev, n_k)` is a GT face at every fan site, all dn magnitudes.
- **Quad law on curated ±1-step sites** (`ma_gate2.py`, old-map region):
  (dr,dn)=(-1,+1) → split A 14/16; (+1,-1) → split B 6/8. C-op gate
  parallelogram `pred = G[r_k]+G[n_prev]-G[r_prev]` within the Z half-window
  at these sites (median 3D residual 0.04–0.05 m).
- **Quad law at scale with teacher-forced allocation** (`ma_final.py`,
  n = fitS−r per rail): complete-quad rate **56.3%** (A 158 / B 137 / none 229
  of 524 checkable). The 'none' class is dominated by counter-vs-mirror slips
  at fans (n=S−r cannot represent fan steps where n advances while r stays —
  the mirror is the zigzag shadow of the true per-strip counter).
- **Phase (A vs B) is NOT encoded and NOT a simple direction function**
  (A: dr+78/−80; B: +54/−83) — consistent with phase = derived state that
  flips at every fan, as the last-3-of-sequence law predicts.

### Machine replays (why the scheduler is the wall)
- `ma_replay.py` (teacher-forced fit of constant (n0,s) per rail segment):
  global face-hit 42.4%; short segments fit (39 segments ≥80%), LONG segments
  collapse to 5–15% — n resets at every fold/column boundary inside a rail's
  lifetime. Confirms: no constant-n0 model can span a rail; fold detection is
  mandatory.
- `ma_beam.py` / `ma_beam2.py` (beam alignment of rail segments to the GT
  mesh): mean quality 0.21–0.30. The binding noise is the rail CLUSTERER
  (JUMP=6/RETIRE=80 heuristic) mis-assigning groups to strips + 861 unmapped
  refs — NOT the face laws (which hold at 85–100% on cleanly-labeled sites).
  Do not re-run beams on clusterer rails; fix segmentation first.

### GT-free scorer status (the session's method finding)
The planned oracle "C gate must parallelogram-predict the next emitted vertex"
is NECESSARY but NOT SUFFICIENT on this mesh: the surface is a near-regular
grid, so any slot-translated quad also parallelogram-predicts (measured:
(+1,+1) class H1 median 0.03 m yet 1/9 faces exist). **Discrimination lives at
folds/fans/boundaries, not the grid interior.** A usable GT-free scorer must
combine: (a) parallelogram residual < half-window, (b) edge-length band
2–9 m, (c) each slot used ≈6× (valence), (d) fold sites score decisively.
This is implemented piecewise in `ma_*` but not yet as one function.

## REFUTED / DO NOT RETRY (this session)
- Op bytes (lead, arg, finalizer 40:1b vs 20:1b, delim within e003) encoding
  the quad split / R-vs-L / phase: NO correlation at pair level, twice.
- Constant (n0, d) per rail segment: dead on long segments (fold resets).
- alloc11-style chain resolution for site labeling: oscillates in fold/fan
  regions (produces repeated 512–515-type junk labels) — use fitted-S or beam
  labeling instead.
- Naive "unique-mapped-neighbor" seeding of teacher-forced walks
  (`ma_teacher.py`): starves (1640/2508 unseeded).

## THE STATE MACHINE (best-supported model, for the record)

    per strip: seq = [...vertices...], counter n, direction d
    REF group (e003 + explicit slot):  seq.append(slot)        # R/L
    IDLESS group (e003, no slot):      n += step; seq.append(n) # C
    every group: emit triangle (seq[-3], seq[-2], seq[-1])
    e0:02 / e0:04: strip push/pop (CANDIDATE, unproven)
    e0:ff / e1:xx: continuation/overflow records (RESUME-07-07)
    op-byte channel (arg>>2): global phase clock +6 mod 64 (not strip data)

Unknowns: (1) group→strip assignment (the round-robin schedule; turn
boundaries = phase-clock ticks are visible, turn→strip identity is not),
(2) per-strip (n0, d) at strip start and at every fold.

## NEXT SESSION SPEC (in order)

1. **Slot alignment (Opus-executable).** Pin the 11 dropped emissions of
   decode_v11_z on intercepts (candidates in `ma_truemap.py` output; 2964 vs
   2975). Deliverable: true-slot P_v11 + map11 in true-slot space. This
   removes the last indexing confound.
2. **Turn-level segmentation (Fable).** Re-segment the stream at phase-clock
   changes (turn = run of groups with constant first-op channel; RESUME-07-10
   init_read8 skeleton). Cluster TURNS (not individual refs) into strips by
   ref continuity. Test: does turn-granular clustering kill the 15.9% rail
   violations? Census e0:02/e0:04 against turn-cluster births/deaths — the
   push/pop test, now at the right granularity.
3. **Strip machine replay with fold resets (Opus after 2).** Replay the
   last-3-of-sequence machine per strip with (n0,d) refit at each fold
   (fold = counter reset detected by the combined GT-free scorer, (a)-(d)
   above). Validation ladder: teacher-forced face rate ≥85% per strip →
   GT-free scorer agreement → GT face score (category: GT-free) → toys
   regression → SYLVANIA cold.
4. **Only then** port to `js/vulcan00TParser.js`.

## ARTIFACTS
- `python/ma_map11.py` → `map11.pkl` (1931-slot answer map, v11-index space)
- `python/ma_map11b.py`, `ma_truemap.py` → `truemap.pkl`, `drops11.pkl`
- `python/ma_gate1.py`, `ma_gate2.py`, `ma_gate3.py` → gate/face-split tests,
  `ma_chains.pkl`
- `python/ma_opsplit.py` — op-byte vs split census (negative result)
- `python/ma_replay.py`, `ma_teacher.py`, `ma_beam.py`, `ma_beam2.py` —
  machine replays (`ma_beam*_out.pkl`)
- `python/ma_final.py` — pair-level census with fitted S (the 56.3%/100% run)
- Unchanged deps: `rails.pkl`, `faces_gt.npy`, `intercepts_gt.csv`,
  `P_v11_intercepts.npy` (52.1% GT-free), `rebuild_gt.py`, `rebuild_pipeline.py`
