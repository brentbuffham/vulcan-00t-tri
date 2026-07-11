# Strip schedule — the rails are REAL (interleaved), scheduler structure cracked open (2026-07-11 Fable session)

Input: RESUME-2026-07-11 step 1 (re-cluster strips from `refs_v2.pkl` anchors).
Scripts: `python/strip1_probe.py` … `strip10_strict.py`. Outputs:
`rails_v2.pkl` (greedy TOL=2), `rails_v3.pkl` (strict ±1, USE THIS).
GT (map11/faces_gt) = scoring/mechanism-labeling only, stated per number.

## HEADLINE

**RESUME-07-11's "sparse per-fold anchors" reading was wrong. The real refs
form ~10–13 CONCURRENT ±1 rails (one per live strip), interleaved round-robin;
the −95..−160 A→A steps are switches BETWEEN strips (rail spacing ≈ column
pitch ~70), not fold pitch.** The old rails.pkl was phantom-contaminated, but
rails per se are REAL — they just have to be clustered from refs_v2 by strict
value continuity. With strict rails, the strip machine's quad law scores
**82.3%** teacher-forced (was 56.3% on contaminated rails), and clean rails
replay at 90–100%.

## EVIDENCE (numbers, category-labeled)

1. **Composition census** (`strip2_census.py`, GT-free): 5738 groups =
   1489 A-ref + 205 S-ref + 21 multi-ref + 3944 idless + 78 is01 non-face.
   Modal anchor-to-anchor segment = **(1 ref, 1 idless)** ×727 — refs are
   per-TURN (a quad per turn), nothing like per-fold density.
2. **Interleaved-rail eyeball** (`strip3_frontier.py` dump): stream start
   shows simultaneous walks 1452→1459 (+1), 1508→1504 (−1), 1383→1377 (−1),
   1384→1387 (+1), 1445→1443, 1311→1309… — ~10 rails alive, spaced ~62–78
   ≈ column pitch. (Frontier-relative d=S−r with global alloc counter:
   REFUTED — d spans ±1500, 1.1% smooth.)
3. **Greedy clustering TOL=2** (`strip4_rails.py` → `rails_v2.pkl`, GT-free):
   448 rails; within-rail steps ±1 = 75% (±2 = 90%); **concurrency median 13**
   (matches init_read9's 8–13 round-robin trace); big-rail start spacing ~2–22.
4. **Mirror allocation on corrected rails** (`strip5_replay.py`,
   teacher-forced fitS): **S-mirror edge rate 92.7%** (1717/1853, was ~? on
   old rails); complete-quad rate **73.9%** (was 56.3%).
5. **Loss decomposition** (`strip9_loss.py`, teacher-forced): hit by step
   class: **|dr|=1 → 84%; |dr|=2,3,4+ → 0%; rail purity 1.0 → 90%**, purity
   0.7 → 58%. ⇒ ALL loss at non-±1 steps = clusterer errors, not format.
   Turn gi-gap uninformative (round-robin period ~12 dominates).
6. **Strict ±1 clustering** (`strip10_strict.py` → `rails_v3.pkl`, GT-free
   clustering): 678 rails, 237 ≥3 refs covering 1148/1741; within-rail steps
   exclusively {+1×496, −1×486, 0×81}. Teacher-forced: **quad rate 82.3%**
   (297/361 mapped pairs); per-rail deciles (≥6 scored) = {50s:1, 60s:1,
   80s:1, 100:4}; **fan rate with counter-step n=last_n+dn: 50%** (was 0%
   with pure mirror — mirror cannot advance at fans, known).
7. **Free-running per-rail alloc counter: REFUTED** (`strip6_machine.py`,
   9.4%) — allocation must RESYNC to the mirror n=S−r at each ref; only
   fan steps free-run. (One turn misassignment otherwise poisons the rail.)
8. **1:1 group↔DXF-face-order alignment: DEAD** (`strip7_align.py`, ~2%
   best over subsets × offsets ±40). DXF 3DFACE order ≠ stream group order.

## THE MODEL (best-supported, updates MYSTERY_A state machine)

    ~10–13 strips live at once, visited round-robin (turn = ref group +
    following idless groups, modal 1+1).
    per strip: rail value r walks ±1 per turn (dr=0 = fan turn);
      alloc n = S − r (mirror RESYNC each turn); fan turns: n = n_prev + dn.
    faces: turn vs prev turn on same strip = quad (split A/B, phase derived)
      or fan face (r, n_prev, n_k).
    S is per-strip(-per-fold) constant; currently TEACHER-FORCED (GT votes).

## LO-CHANNEL SESSION 2 (2026-07-11 later; strip11..strip19)

Re-tokenized with lo capture (`strip11_lochannel.py` → `refs_v3.pkl`, has
`lo` + `ops` per group). Census: 1685 lo events; 424 zeros; nonzero alphabet
DOMINATED by 1..11 (~980 events); carrier = idless e003 groups (931×1 event).

Tested and REFUTED (all ~chance):
- lo = revisit countdown / distinct-rails-until-revisit / prev-visit gap
  (`strip12`, ~8%).
- lo = rail age / turns-to-death / |r−r0| / |r−r_end| / turns-to-fold
  (`strip13`, ~5–10%).
- lo = unique strip slot-ID in round-robin table (`strip14`: concurrent
  rails share modal lo at chance 50%; neighbors 89/90/99/106 all modal 4).

POSITIVE (unfinished):
- **lo is near-constant per rail** (92/111 rails ≤3 distinct values) and
  **drifts regionally with the sweep** (5→4→3→2→1 over gi 400–3200, then
  8→7→6…) — a region/column-coordinate-like field, NOT strip identity.
- Median r rises monotonically with v for v=1..8 (665→2290).
- On mirror-VERIFIED events (map11[r]–map11[n] GT-edge): **v≤8 ∈
  {n>>8, (n>>8)−1} at 63.2%** (v==n>>8 40.7%); identical rate on
  unverified ⇒ miss is the rule-form, not fitS noise. No offset/threshold
  variant beats ~37% exact ((n−128)>>8 = (S−r0−128)>>8 = 124/339).
- **v≥9 (9/10/11, 189 events) = separate subfield**: 38% at rail BIRTH
  (~4× base), not fold/fan-correlated.

Honest state: lo = COMPOSITE channel; v≤8 tracks the alloc-slot high byte
REGION (2–3× chance, not exact), v≥9 birth-marker-ish. NOT yet the S source.

## S-ATTACK SESSION 3 (2026-07-11 Opus; strip20..strip26) — S model PINNED, blocked on column segmentation

Executed RESUME-07-12 steps 1–2. Two attacks ruled out, ONE model confirmed.

**Step 1 lo-channel high-byte sweep (strip20/21) — DEAD for S.** Raw idless
record = `e003 · 00 · fop · 00 pp(=lo) · payload · finalizer` (lo sits right
after the fop). Broad sweep on verified-mirror events: NO candidate (n>>8,
(n±128)>>8, r>>8, (S−r_next)>>8, n//270, fop_arg/lead fields) beats **38%**.
`lo | fop_lead` shows only a coarse monotone trend (lead 0x42→low lo,
0x44/45→high lo) ⇒ lo is a spatial region tag co-varying with the sweep,
NOT a mechanical S field. Confirmed dead.

**Step 2a emission frontier (strip22) — DEAD.** corr(mirror n, global alloc
counter E_all) = 0.32; |resid|<128 only 17%. Slot ≠ face-side alloc order.
Adjacent-birth ΔS not clustered at 0 (rails born together are in different
columns). n monotone within a rail = 164/165 (trivial: r monotone).

**Step 2b boustrophedon column model (strip23/25/26) — MODEL CONFIRMED,
column segmentation is the blocker.** Physical law: r ascends column c while
mirror n = S−r descends the spatially-adjacent column, so
**S = base(c_r) + base(c_n) + len(c_n) − 1 = base(c_r) + top(c_n)** (one
horizontal mesh edge; the two forms are algebraically identical). Evidence:
- both equivalent forms tie at **21.2%** (±2) with position-derived columns
  (strip26), vs 9% with holey mesh-adjacency columns (strip23) — the model
  FORM is right; the rate tracks column-map quality.
- REFUTED sub-case: mirror column is NOT slot-contiguous with the ref column
  (S ≠ 2·r_lo−1 / 2·r_hi+1 / r_lo+r_hi, all <5%, strip25) — so S can't come
  from the rail's own r-range; it needs the mirror column's absolute base.
- Blocker: no clean GT-free column segmentation exists. map11 is holey
  (28 singleton "columns" of 124); position-jump detection over-segments
  (233 cols, median slot-len 5, vs true ~25 cols of ~120) because the
  serpentine wiggles within a column. `full_flags.npy`/`k0_sites.pkl` are
  coord-carry artifacts, not column boundaries.

**THE WALL, precisely:** GT-free S needs the true column partition of the
coord emission order (slot → column, with correct bases/lengths). That is a
COORD-side derivation (the fold/column-boundary structure of the serpentine
value stream), feeding the FACE-side S = base(c_r)+top(c_n). This links the
two decoders — it is the coord-topology joint solve flagged since 07-05.

## §COLUMN PARTITION SESSION (2026-07-11 Fable; col_partition.py, col_probe1..10)

Task: GT-free `slot -> column` partition of the coord emission, feeding
S = base(col_r) + top(col_n). Deliverable: `python/col_partition.py` ->
`python/columns_v1.pkl` ({'colof' array slot->col, 'bounds', 'u'}).

### What the emission actually is (GT-free geometry, from P_v11 alone)

- The serpentine is a boustrophedon over parallel scan LINES: within a
  column the decoded point advances a ~4.0 m step along a fixed direction
  (~55 deg for the main region); at a fold it hops ~3-4 m laterally to the
  next line and reverses. w = XY.u_perp is a STAIRCASE (levels +-0.1 m,
  3-4 m apart) — the sharpest column signal in P_v11.
- **The assumed "~25 columns of ~120" is WRONG.** True structure ≈
  110-130 columns of ~25 slots (teacher fold spacing ~= ΔfitS/2 ~= 25-27).
  The −95..−160 A->A refs steps are multi-column strip switches, not pitch.
- **Interloper slots are REAL**: inside a column's slot range, sparse slots
  belong to concurrent threads elsewhere (GT confirms e.g. slot 453 truly
  sits 180 m off the local line). They inherit the enclosing column in slot
  arithmetic; fitS still walks straight through them.
- **S-form resolved: S = base(col_r) + top(col_n) is UNIVERSAL** (both
  sweep directions) — verified by hand on the 437/461/485 column pair
  (forward 921/922, backward 923, both = base_r+top_n). The strip20-26
  asc/dsc form split was an artifact: for adjacent columns br+tn and tr+bn
  differ by len_r−len_n ≈ 0-3, inside the +-2 window.

### Partition method (all GT-free) and ladder numbers

Winning detector: sliding-median (win 9) staircase on w + run cleanup
(merge same level / delete interloper bursts / absorb orphans) + optimal-
split boundary refinement on raw w (interlopers don't vote). Failed
alternatives (tested, don't retry): global (w,slot) line clustering (11%);
DP segmentation with trimmed line-fit cost (68% either — PCA fits get
hijacked by interlopers); per-region local axes (115 fake regions, 59%);
rail-interval boundary pruning (bogus rails cross true folds, 53%).

- Partition: **261 columns, median len 8** (over-segmented ~2x vs true
  ~110-130; extra splits come from v11 decode-error bursts).
- **L1 [GT-free folds vs fitS-implied odd-S folds, teacher key]: recall
  58/68 = 85.3% (+-2)**; precision 19.2% vs this key — but the key only
  covers backward-rail folds (68 of ~120), so true precision is bounded
  below ~45%, not 19%.
- **L2 [teacher-forced check, fitS-verified events, +-2]:
  S = base(col_r)+top(col_n) = 441/707 = 62.4%** (baseline 21.2%,
  strip26). Either-anchoring diagnostic 87.3%. Rails all-events-hit
  140/242. Residual histogram is centered (mode +1) with fat +-3..15
  tails = boundary placement noise.
- L3 not run: gate was L2 >= 80%.

### The decisive decomposition (col_probe8/9/10) — S is nearly free, the
### blocker is ONE BIT per rail

Mirror-geometry voting, GT-free: for a rail's refs, sweep S; the mirror
n = S−r must land 2-6 m (P_v11 XY) from r. Result per rail:
- unrestricted vote: |S_geo − fitS| <= 2 on **66.7%** of 201 rails
  [GT-scored]; the misses are almost all SIDE flips — both adjacent lines
  contain a ~3.5 m partner, so the vote has two peaks (left/right).
- **given a 1-bit side oracle (n<r vs n>r): 90.4%** (178/197)
  [teacher-forced, exactly 1 bit]. So geometry+stream already pin S to
  within the +-2 stagger once the side is known.
- GT-free side coverage today: 36% of rails have only ONE strong peak
  (mesh edge / thread gaps) and are 81.8% correct [GT-scored].
- Side is NOT predictable from column sweep direction, r-trend, or column
  parity (col_probe9: all ~50-56%). It is the strip identity bit — which
  of the two adjacent column-pairs the rail serves = the A/B phase
  question already open on the face side.

### Honest state of "S is GT-free"

S is **62.4% GT-free via the partition formula** (teacher-forced check
category) and **90.4% with one teacher bit per rail** via geometry voting.
NOT yet at the 80% GT-free gate. Two independent residual walls:
1. **The side bit per rail** (biggest, ~24 points of headroom): candidate
   sources — the op/phase channel (`00 pp` lo v>=9 birth markers), or a
   global round-robin tiling argument (live rails must serve consecutive
   column pairs).
2. **P_v11-invisible folds**: some true folds do not exist in the decoded
   positions at all — v11's XY walked STRAIGHT through a GT reversal
   (e.g. fold 973: w constant, along-line coordinate monotone through the
   fold; GT reverses). No partition from P_v11 can find these; needs the
   coord pass-2 decode (also the map-coverage track). Stream flags do NOT
   mark folds (col_probe7: FULL/k0 proximity to teacher folds ==
   random) — strip24's conclusion re-confirmed quantitatively.

## §SIDE-BIT SWEEP (2026-07-11 Opus; side1_sweep.py) — byte channels WASH, escalate to tiling

Target: per-rail side bit = sign((S−r_med)−r_med) from fitS teacher key
(242 rails, balance 130/112). col_probe9 already washed sweep-dir/r-trend/
parity. This sweep tested every FACE-SIDE byte channel — ALL wash:
- fop_lead 55.9%, delim 55.4%, ref form(A/S) 55.4%, lo_birth≥9 53.7%.
- **MYSTERY_A candidate bit-flips REFUTED**: idless payload nibble 2X vs 4X
  splits 58/51 & 59/51; finalizer 40:1b vs 20:1b splits 71/66 & 43/34 —
  both pure chance. The side is NOT the payload/finalizer bit.
- fop_arg 63.9% and lo_modal 64.8% are OVERFIT (42 / 26 distinct values,
  ~5 rails each); lo_birth 91.7% is only 12 rails (noise).

Conclusion: the side bit is not in any local byte — it is GLOBAL STATE.
NEXT (Fable, open hypothesis): the round-robin TILING argument. ~13 rails
live at once, each serving an adjacent column-pair; if live rails shingle
the surface (rail k serves (c,c+1), rail k+1 serves (c+1,c+2)…), the side
falls out of a rail's RANK among concurrent live rails ordered by col_r —
untested (probe9 tried column parity, not live-rank). Second candidate: the
concurrency birth/death schedule (e002/e004) fixes which pair a new rail
takes. This is the same A/B-phase bit open on the face side.

## §SIDE-BIT HUNT 2 (2026-07-11 Fable; side2_*.py) — "side" REFRAMED as fold
## identity; teacher key proven ~coin below margin 2; GT-free rule 90.5% on
## the reliably-labelled band

### Global-state hypotheses ALL WASHED (side2_tiling / side2_spatial /
### side2_physical / side2_alloc / side2_sform — do not retry)
- Round-robin live-rank (rank%2 by r_med or col, top/bot of live pack,
  above-live-median): 54–57% [teacher-forced].
- Temporal coherence: side in birth-gi order lag-1 = 51.9%; in rmed order
  55.2%; XY nearest-neighbour rail 52.1%; rails within 15 slots 55.1%.
  The bit has NO time or space banding.
- Frontier drift (slope of recent births' r_med), rmed-vs-prev: ~54%.
- Physical side vs local sweep direction (w-staircase drift): 46.7% — the
  alloc line is NOT consistently the un-swept side.
- Shingle-chain timing (mirror slots ref'd AFTER vs BEFORE): aggregate
  refutes (true n: 304 before / 297 after) — round-robin pipeline destroys
  before/after separation at turn granularity.
- S-form refs (230) do NOT announce the strip constant: r_A+r_S==S 1/108;
  they sit at birth(138)/mid(47)/last(45) — not a strip-open channel.

### THE REFRAME (side2_look window dump, decisive)
Rails sharing S≈921/922/923: refs walk 439→478 while mirrors walk 483→444 —
symmetric about slot ~461. **S = 2 × fold apex. The strip is the ZIP of one
serpentine fold** (pairs (a−k, a+k+1) around apex a). A rail's two geometry
peaks are the folds ABOVE and BELOW its line — BOTH real folds; the "side
bit" = WHICH fold the rail zips (not an A/B byte, not schedule state).
S values are GLOBAL: 56 of 152 distinct fitS are shared by 146 rails; the
apex set ≈ the serpentine fold list (median spacing 28.5 — matches the
~25-slot column pitch, NOT ~70).

### The teacher key is UNRELIABLE exactly where the rule is hardest
- Raw fitS margin (top vote − runner-up value) = 0 on ALL 81
  geometry-tied rails — but that conflates ±1 stagger with side ambiguity.
- Apex-clustered margin (votes summed within ±3, top apex − 2nd apex):
  every interior vertex has GT edges to BOTH adjacent lines, so below
  margin ~2 the label is the vote tie-break, not the mesh. Direct evidence:
  the strip5 quad check accepts BOTH diagonals (A or B) → local GT scoring
  passes for EITHER side choice; and no rule can beat ~50% against an
  arbitrary tie-break, yet accuracy rises monotonically with margin (below).
- An exact-cover teacher T2 (rails claim diagonal-checked GT triangles,
  ICM minimizes double-claims, side2_final) agrees with fitS 92.3%
  (95.3% on firm) but is itself sparse-claim-noisy on the ambiguous rails.

### GT-free rule (side2_score.py → side_rule.pkl {rid:(side, S)})
Two-sided mirror-geometry peaks (P_v11 XY + rails_v3 refs, col_probe10
vote) → cluster all peaks into a GLOBAL apex list (105 clusters; captures
121/152 distinct fitS at ±2; true S among a rail's ≤2 candidates 89.0%
[teacher check]) → assign each rail to one candidate by same-family
position-occupancy conflict + peak-strength tiebreak + ICM.
Scores vs apex-clustered teacher [teacher-forced check; event-weighted in
parens]; 239 rails predicted, 208 teacher-labelled overlap:
- apex-margin≥4 (45 rails): side **95.6%** (96.1%), S(±2) 80.0% (82.8%)
- apex-margin≥3 (74):       side **90.5%** (89.8%), S(±2) 81.1% (81.2%)
- apex-margin≥1 (145):      side 80.7% (82.2%),     S(±2) 73.1% (75.0%)
- all labelled (208):       side 61.5% (65.2%) — dominated by margin-0/1
  rails whose labels are tie-break artifacts (a variant solver scored 33%
  on margin-0: anti-correlated with an arbitrary coin = label noise).
Washed solver variants: cross-family attraction (57.9% on 2-cand),
apex-level (family-blind) occupancy (59.4%), fine geometry (dmean/dstd/
parallelism/step/dz: 48–62%), gi-proximity to apex activity (48.5%),
chain-adjacency, mirror-in-refs (50–52%).

### Honest state / what the wall actually is now
- The "one bit per rail" framing is RETIRED: the bit is fold identity, and
  the blocker is no longer finding a signal — it is that BOTH fold choices
  are locally GT-consistent, so neither the vertex-adjacency teacher nor
  per-quad scoring can even LABEL the hard rails. End-to-end honest gain:
  S(±2) event-weighted 62.4% (old formula, L2) → **75.0%** on the
  margin≥1 band, **81.2%** on the firm band [teacher-forced check].
- Gate for the strip-machine GT-free replay (≥90% overall side) NOT met on
  the full population; not re-run.
- To finish the side/S question the decode and the teacher must both go
  GLOBAL: full-machine replay with turn assignment for the 3944 idless
  groups + exact-cover of the face set (each face emitted once). That is
  remainder items 3+4, now joined: the ambiguous rails' sides are exactly
  the ones only an exact-cover replay can pin — on both sides of the
  scoreboard.

## §COVERAGE CEILING (2026-07-12 Opus; side3..side9) — first GT-free faces + the real cap

Ran the strip machine with GT-free S (side_rule) end-to-end and rendered it.
- GT-free faces viewer: `js/intercepts_faces.html` (side4_emit → side5_viewer).
- **Precision where checkable: 85.6%** (564/659 scorable tris GT-correct;
  BEATS noisy teacher 82.8% — fitS is fog on ambiguous folds). But that is a
  CONDITIONAL metric.
- **Honest coverage: 9.2% of the 5724-face mesh** (525 distinct GT faces),
  1078 tris emitted = 18.8%. DO NOT report 85.6% as progress.
- Extending S 239→311 rails (side8, global-apex snap) moved coverage almost
  nothing (1078→1113 tris): **S was NOT the bottleneck at this stage.**
- **THE CAP (side9): the per-quad machine tops out at ~18–37% of the mesh**
  because it only emits between CONSECUTIVE same-rail turns, and rails_v3
  fragments strips — 435/670 rails have ≤2 turns; 286 turns stranded in
  size-1 rails emit nothing.
- **The real path to full coverage: STITCH rail fragments into complete
  strips across folds, then emit one last-3-of-sequence face per group.**
  Math closes: 1716 ref + 3432 idless groups ≈ 5724 mesh faces. Stitching
  rule (candidate): at a fold, ref/mirror columns swap, so the next rail's
  ref-range ≈ this rail's mirror-range [S−r_hi, S−r_lo]; chain A→B on that
  overlap + apex/S transition. This is the next build (Opus, spec-shaped).

## WHAT REMAINS FOR A GT-FREE FACES DECODE (ranked)

1. **GT-free S** (the wall's core). S = r+n links the strip's two columns.
   Candidates: (a) coord-side fold boundaries (n0 = column boundary,
   RESUME-07-10 finding 3) fix n0 per column ⇒ S = n0 + r0; (b) the
   `00 pp<0x80` lo-channel (1425 events) — retest against rails_v3 turn/rail
   structure (refs_v2.pkl does NOT store pp values; re-tokenize with
   ma_refdecode.py's loop to capture them per group).
2. **Fan dn rule** (50% = coin-flip; phase-flip law from last-3 order).
3. **Turn assignment** for allocs after unassigned refs (593 refs outside
   ≥3-rails; S-form rail starts; the `cur=None` drops).
4. **A/B phase** = insertion order (alloc-before-ref vs after) — derive from
   zigzag state, verify flip-at-fan on rails_v3.
5. Map coverage ceiling: 2064 unmapped faces can't be scored either way —
   needs v11 pass-2 map extension (separate track).
