# Reference-column hunt: the serpentine previous-column reference does NOT exist — the residue was PLACEMENT CONTEXT (2026-07-07)

Follow-up to VALUE_SPLICE_HUNT section 6 ("the reconstruction reference, not
the placement"). Verdict: **section 6's hypothesis is refuted and its title
inverted** — the residue is placement after all, but *context-conditional*
placement, not a better reference. Scripts: `python/refhunt1..10.py`
(diagnosis, GT for LABELING/SCORING only), `python/decode_v10_ref.py` (the
fix, GT-free).

PRIME DIRECTIVE held throughout: GT (each file's DXF) used only to pin/label
broken sites and to score. No GT in any decode path; no per-file constants;
rules are byte-role + stream-context only.

## 1. The previous-column (i−P) reference hypothesis: DEAD, cross-file

Tested exactly as specced (refhunt1, refhunt2):

- **GT-free lag scan** (median |v[i]−v[i−P]|, P=1..400) on the decoded X/Y/Z
  sequences: **monotone increasing in P on all three files** (intercepts,
  SYLVANIA, OB34; `lagscan.py`). Lag 1 is uniquely optimal; no lag beats it;
  no periodic minima at all. There is NO column period in emission order.
  (intercepts X: 2.29 m at lag 1, +2.29 m per lag — a smooth 1D walk.
  SYLVANIA X: 0.145 m at lag 1, same shape.)
- **GT-labeled best-lag histogram** at 828 pinned single-axis-wrong sites
  (2 axes bit-exact → unique GT vertex): FLAT. Top lag appears 4–6 times out
  of hundreds; lags scatter 1..400. "Some earlier vertex within half-window"
  rates (X 219/229 etc.) are chance-level: with the in-band spans and 400
  candidates, mean #in-half-window = 13 (X), 84 (Y) — no specificity.
- **Fold/row-start memory** (value adjacent to the previous large decoded
  jump): X 41/229, Y 125/189 (but Y is the chancy axis), Z 9/410. Not a rule.
- **ORACLE upper bound** (refhunt3): even the earlier vertex NEAREST THE TRUE
  3D position misses the Z half-window (0.0625 m) in 381/410 cases (median
  err 0.50 m); X 138/229 only. **No vertex-value reference of any kind — any
  lag, any topology — can reconstruct the Z residue.** The reference framing
  is exhausted, not merely "P unrecoverable".

## 2. What the residue actually is (refhunt4/5/9 teacher-forcing)

Teacher-forcing every (placement k0, hi-delta dh ±300) against the register
at all 828 pinned sites:

- Bit-exact (<1e-6): 2/828. The payload at residual sites is NOT a perfect
  byte-window of the DXF value over the register (fold-onset payloads land
  ~0.004–0.03 m off bit-exact — unexplained, see §5 open point — but well
  inside the 1 m scoring criterion).
- **At <1 m: 827/828 sites have a (k0,dh) reconstruction.** Framing is fine;
  the information is present. Census of the winning (k0,dh) at ONSETS
  (previous vertex bit-exact, register provably clean):
  - X onsets: 30× `k0=3 where rule said 2, dh∈{0,±1}`; 19× `k0=2 where rule
    said 3, dh=0`; only ~18 genuinely far-dh.
  - Z onsets: 25× `k0=3 where rule said 2, dh=0`; ~15 far-dh.
  - Y onsets: 17× `k0=2 where rule said 3, dh=0`; 30× rule-placement small dh.
  - **The dominant onset defect is the PLACEMENT RULE, with a trivial (last,
    dh≈0) reference once placement is right.** Everything else in the broken
    set (nb=4 dhFAR blocks etc.) is inherited episode corruption seeded by
    these onsets.
- Corroboration: raw V-tag census (refhunt8) — nb=6 records (byte 2
  transmitted) are essentially never broken (609 clean vs 1 onset). Breakage
  lives exactly where byte 2 must be reconstructed (nb=4/5), as the model
  predicts.
- Ruled out along the way: alignment slip (wrong decoded values are NOT other
  GT coords — control-level rates, refhunt6); missing info in skipped stream
  content (2-byte/e0-class token counts identical at broken onsets vs clean,
  refhunt7); payload escape-stuffing (escape-byte rates equal, refhunt5);
  arithmetic bit-delta payload semantics (0 hits, refhunt5).

## 3. Why "nearest-congruent placement competition" cannot work

Tried and measured (decode_v10 margin sweeps M=4..1024, intercepts): ALL
regress (18–49% vs v9's 52.1%). Arithmetic reason: the smaller-window
placement (k0=3) can always park within half a byte-2 unit (±4 m X) of the
reference, while a correct k0=2 value sits wherever its payload says (its
candidates are ~2048 m apart). Distance-to-reference therefore always prefers
plc3, right or wrong. This confirms VALUE_SPLICE_HUNT §2's "no geometric
arbiter" from the decoder side — placement must come from stream context, not
from value proximity.

## 4. The actual fix: CONTEXT-CONDITIONAL PLACEMENT (decode_v10_ref.py, GT-free)

One context rule survived cross-file validation (found by censusing flip
sites vs clean controls, refhunt9/refhunt10; byte-role + prev-record class
only):

- **Rule A** (= VALUE_SPLICE_HUNT §2's own fold observation, now operational):
  nb=5 record whose T-rule says plc2 (T1∈21-3F, or T1=20 & T2≥60) is placed
  at **plc3 when the previous V record was nb=6**. (Fold signature: fold rows
  are preceded by an nb=6 record; 14/17 in the old census.)

Everything else identical to v9 (k0_rule, nearest-congruent-to-last wrap,
span 4, fallback scan).

- **Rule B — REJECTED cross-file** (methodology catch, do not re-add): nb=5,
  no T token, immediately after a FULL → plc2. On intercepts it looked real
  (48 flip sites vs 4 clean controls, +37 net) but it regressed BOTH cold
  files (SYLVANIA 49.0→44.9%, OB34 11.0→10.2%). The post-FULL/T-less context
  evidently doesn't mean plc2 universally; an intercepts fingerprint.

### Scores (all GT-FREE decode; DXF scoring only; <1 m)

| file | v9 baseline | **v10 (rule A)** | net |
|---|---|---|---|
| intercepts (seen) | 1544/2964 (52.1%) | **1614/2964 (54.5%)** | +70 |
| SYLVANIA (COLD)   | 88296/214177 (41.2%) | **104905/214177 (49.0%)** | **+16,609** |
| OB34 (COLD)       | 26171/251858 (10.4%) | **27606/251858 (11.0%)** | +1,435 |
| first500 (i/S/O)  | 192 / 261 / 78 | 203 / 267 / 78 | |

Rule A: biggest absolute gain on the cold file — the SYLVANIA churn collapse
the section-6 lead predicted, delivered via placement, not reference. Not a
fingerprint.

## 5. Still open after v10

- The far-dh onsets (X ~18, Z ~15 on intercepts): genuinely need a reference
  beyond nearest-last (dh up to ±91 observed) AND are not explainable by any
  earlier vertex value (§1 oracle). Where their hi info lives is unknown —
  candidates: T2 hi-nibble semantics at folds (W2 state machine), or they are
  the 21-3F/20-class exceptions of yet another context.
- Fold-onset payloads reconstruct ~0.004–0.03 m off bit-exact even with the
  right (k0,dh). Sub-1m so it scores, but the byte-level semantics at folds
  are not fully understood (possibly a second splice source or rounding in
  the encoder's fold path).
- Remaining SYLVANIA/OB34 residue: OB34's bottleneck is still the FULL
  harvest/band quality (unchanged diagnosis from MISFRAME_CENSUS).

## 6. Next lead (one)

Iterate the SAME loop that produced rule A: re-pin the v10 residue, census
onset placement-flips vs clean controls on (prev-record class, T bytes), add
the next context rule, validate COLD BEFORE KEEPING (rule B shows why — an
intercepts-only census can lie; consider censusing flips on SYLVANIA pins
directly, its 110k residue gives far better statistics than intercepts' 828).
Each iteration is cheap (refhunt9/refhunt10 are reusable as-is). The loop
stops when onset flips stop separating on context — whatever remains then is
the true far-dh/W2-state residue (§5).
