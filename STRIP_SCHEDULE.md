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
