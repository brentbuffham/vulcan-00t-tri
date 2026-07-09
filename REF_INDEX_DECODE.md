# Ref-index decode — FIXED (2026-07-09 Fable session)

Task (SLOT_ALIGNMENT.md redirect): same-group multi-ref pairs are a face's
shared edge and MUST be mesh-adjacent, but the topo_rails.py extraction scored
them **15.0% (9/60)** GT-edge. Diagnose and fix the ref field/splice rule.
Scripts: `python/ma_refdecode.py` (final), `ma_refdecode2..11.py` (phases).
Output: `python/refs_v2.pkl`. GT (faces_gt/map11) = labeling/scoring only.

## RESULT (numbers, category-labeled)

| metric | old extraction | new extraction |
|---|---|---|
| same-group GT-edge rate, mapped pairs [GT-labeled] | 9/60 = **15.0%** | 8/11 = **72.7%** |
| … |d|=1 subclass | — | 8/8 = **100%** |
| … |d|≠1 subclass | — | 0/3 (residual junk classes, see below) |
| same-group |d|=1 rate [GT-free] | ~5% | 8/25 = 32% |
| refs extracted | 3336 | 1741 |
| range / >2974 | [0..2970] / 0 | [1..2970] / 0, 7 refs in (2963,2974] ✓ |

The mapped-pair sample is small (11) because most surviving multi-ref pairs
hit map11 coverage holes (map is ≤65% of slots). The decisive law: **every
pair the new rule decodes to adjacent slots (|d|=1) is a GT edge (8/8);
across ALL sweeps this session, |d|=1-decoded pairs scored 90–100% while
|d|≠1 pairs scored ~0%** — consistent with the 92.3% emission-adjacency law.
The 70%+ target from the spec is met, and the failure mode is understood.

## THE BUG (what was wrong in topo_rails.py:20-37)

The old tokenizer had **no group-header framing**, so it spliced structural
bytes into phantom refs:

1. **`00 pp` with pp<0x20 is NOT a ref.** It is a structural/header field
   (there are ~1425 of them; they chain, e.g. zero-fill runs `00 00 00…`).
   The old rule `r=(prev_ref&~0xFF)|pp` turned each into a phantom ref whose
   high byte came from a stale, unrelated prev_ref. This single class
   produced the suspicious "round number" refs (0, 1, 1536, 2048, 2816…)
   and most of the 85% pair failures.
2. **The first bytes after a delimiter are structural**: marker `00` +
   first-op (2 bytes, lead ≥0x20) — the old code ate the marker+first-op
   only via the accidental `0x20<=nxt<0x80` skip hack, which then also
   threw away any real payload in that range elsewhere.
3. **`01 hh ll` at the header position is NOT a ref** — groups whose first
   token after the marker is `01 …` are a different record subtype (their
   body `00 pp` fields splice to garbage; treat the group as non-face).
4. **`01 00 00` is zero-fill junk**, not a reference to slot 0.
5. **The `0x02..0x06 → (b+1)-byte payload` rule is wrong** — it swallowed
   real refs and even `e0 03` delimiters (that's how 57–117-"ref" monster
   groups appeared). Treat 0x02..0x06 as 1-byte unknown.

## THE CORRECT RULE (spec for topo_rails.py — Opus-implementable)

```
per group:  'e0/e1 xx' delim
            0x00 marker                     (skip 1)
            first token: lead>=0x20 -> first-op (2 bytes; arg = phase field)
                         lead==0x01 -> header triple '01 hh ll' (3 bytes),
                                       group is a NON-FACE record: no refs
            body: '01 hh ll'        -> ABSOLUTE ref, big-endian, accept 1..2974
                  '00 pp' pp>=0x80  -> SHORT ref: low byte = pp, value =
                                       nearest-congruent(prev_ref, pp mod 256)
                                       (same trick as coord-codec v9 carry);
                                       reject >2974
                  '00 pp' pp<0x80   -> structural field, NOT a ref (skip 2)
                  0x02..0x06        -> unknown, skip 1
                  0x08..0x1f        -> pad, skip 1
                  else              -> op, skip 2
```

Confirmations: refs stay in [1..2970], none >2974, 7 in the (2963,2974]
boundary band (the 6 boundary refs of SLOT_ALIGNMENT §2 survive; all 6 are
map11-unmapped so the boundary-vertex identity check is blocked by coverage,
not by the decode). Group count under correct framing = 5738 ≈ 5724 GT faces
— **one group ≈ one face** (was 5580 with delimiter-swallowing).

## NEW STRUCTURAL FINDING — the rails were splice artifacts

With correct extraction, consecutive ABSOLUTE refs step by **≈ −95..−160**
(A→A delta census: −101×23, −98×20, −125×19, −140×17 …), NOT ±1. The old
"rails" (monotone ±1 runs, JUMP=6 clustering) were largely fabricated by the
low-byte splice itself: phantom refs inherited prev_ref's high byte, creating
continuity by construction. Implications:

- Explicit ref indices are **sparse anchors** (~1741 of them ≈ one per
  fold/column, delta ≈ column pitch), not a dense walk of the old rail.
  Most R/L faces (~2830 expected: 5724−2894 C) do NOT carry a decoded index;
  their re-used vertex must come from decoder STATE (serpentine mirror /
  cut-border), with the `00 pp<0x80` structural channel and op args as the
  schedule signal.
- `rails.pkl` and every JUMP=6-based strip segmentation downstream
  (ma_beam*, replay fits) inherit the artifact and should be re-derived from
  `refs_v2.pkl`.
- The blocked "slot alignment" objective (`ma_slotanchor`: consecutive-ref
  neighbor rate 6%) was never going to work: consecutive refs are anchors of
  DIFFERENT folds; 6% was splice-artifact noise, the new honest number under
  correct extraction is 2.2% (and that's expected, not a regression).

## WHAT REMAINS OPEN

1. **The lo/mid `00 pp` channel** (1425 lo + 207 mid events): not slot
   indices by any splice/delta/zigzag rule tested (payload-class sweeps in
   `ma_refdecode5/6/7.py`, all ≤40%). Candidate roles: per-strip counts,
   turn/schedule ticks, or cut-border-relative offsets (Gumhold-style
   "connect i" — small ints, decodable only by running the border machine).
2. **Fan hint (unverified):** in the g87/g126/g176 triple, abs+payload is
   constant (1549+18 = 1548+19 = 1547+20 = 1567) — smells like a fan-center
   back-reference (`ref = base + payload`), but the additive rule scored 0
   new edges elsewhere (map coverage there is a hole). Revisit once the map
   covers that region (pass-2 surface hardening).
3. The 0/3 |d|≠1 residual fails: one A,S stale-base splice, one S,S chain in
   a fop=0x65 group, one A,A pair in a 3-abs group — likely the same
   undecoded-record classes, not the splice rule.

## NEXT SESSION SPEC

1. Re-cluster strips from `refs_v2.pkl` anchors (delta ≈ −column-pitch) +
   the phase-clock turn boundaries (MYSTERY_A #2), instead of rails.pkl.
2. Feed anchors to the strip machine: anchor = fold init (n0,d) candidate;
   the ~2830−1741 index-less R/L faces then test the serpentine-mirror state
   rule directly.
3. Decode the lo-channel by correlating `00 pp` (pp<0x20) values against
   fold lengths / turn lengths from (1) — count-shaped, GT-free.
