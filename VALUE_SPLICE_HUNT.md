# Value-splice hunt: the k0/carry residue is a WRAP-RECONSTRUCTION defect (2026-07-07)

Follow-up to MISFRAME_CENSUS.md section 5 ("residual onsets are plain T·V spans,
nb=4/5 payloads on X = k0/carry VALUE model"). Scripts:
`python/label_v9_splice.py` (whole-file pinning + teacher-forcing + separation
scans on v8b), `python/decode_v9_k0.py` (the fix).

GT (each file's full-precision DXF, 17 sig digits = bit-exact doubles) used
ONLY to LABEL (pin/teacher-force) and SCORE. Never fed to any decode. No
fingerprinting; the fix is byte-role + codec-internal arithmetic only.

## 1. Re-labeling on v8b (whole file, intercepts)

- broken 1600 of 2964; **single-axis** (other two axes bit-exact <1e-6): 859
  strict / 1420 loose(<0.5m); multi-axis/cascade only 180. The damage is
  overwhelmingly single-register.
- pinnable (2 exact axes -> unique GT vertex, wrong-axis gap >=0.5m): 211.
- Teacher-force (all k0 x carry -4..4, BIT-EXACT <1e-6): whole set looks
  carry-scattered (54/211 exact, c in +-1..+-4) — the SELECTOR_HUNT trap again.
- **Onset restriction** (wrong axis bit-exact at vertex i-1, so Rbefore is
  provably clean): 36 onsets, 30 with bit-exact wins, ALL at `(k0=3, c=+-1..4)`
  where the rule said k0=2 or c=0. The 175 non-onset pins are inherited
  register corruption (24/175 exact, scattered) — episodes, not independent
  defects. nb=4 damage (('21-3F',4,'Z') 43 NOEXACT etc.) is 100% inherited.

### The byte-level fact (onset dumps)
Every nb=5 onset: payload == true bytes 3..7 (**placement k0=3**), true bytes
0..1 == register, true byte 2 == register byte 2 + d2 with d2 in
{+-1,+-3,+-4, +25, +44, +50 ...}. The "carry" was never a carry: byte 2 is
simply NOT transmitted, and the +-1..4 search with first-in-band acceptance
reconstructed it wrong (wrong sign / wrong magnitude / capped at 4).

## 2. Placement census + separation scans (why there's no clean k0 byte-rule)

Placement of payload inside CORRECT written values (v8b, intercepts), nb=5:

| T1 class | plc=2 (bytes 2..6) | plc=3 (bytes 3..7) |
|---|---|---|
| 0x20     | 29  | 189 (T2<0x60 subset ~=plc3, T2>=0x60 ~=plc2, ~9 exceptions each way) |
| 0x21-3F  | 1740 | 22 |
| 0x40-5F  | 0   | 20 |

- T1 separates at 97.5% — good but NOT deterministic: both cells 0x20 and
  0x21-3F contain both placements. 30-feature scan (T1/T2 bits, count byte
  high bits b=04/0C/14/1C, payload bytes, register bytes, prev/next token
  kind/nb...) found NO 100% separator (best conditional: prevV nb=6 -> plc3
  inside 21-3F, 14/17, not clean). The 21-3F plc3 exceptions cluster at fold
  sites (preceded by an nb=6 Z record).
- A pred-vs-pred chooser (pick placement whose value is nearest parallelogram
  prediction) FAILS: label-0 tail overlaps label-1 margins (5% of true-plc2
  records have d2v/d3v >= 390 vs plc3 min 8.7). No geometric arbiter for
  placement. **Placement stays on the existing k0_rule (T1/T2 byte-role).**

## 3. The actual defect and the fix (decode_v9_k0.py)

A V payload is a LOW window of the new value: it pins the value **modulo one
unit of the first un-transmitted byte** (nb=5: byte-2 unit = 8 m on X, 32 m on
Y, 0.125 m on Z at these exponents). The bytes above the window belong to the
*reconstruction*, not the register: the decoder must pick the congruent value
nearest its reference. v8b approximated this with "c=0 if in band, else first
in-band carry +-1..4" — first-in-band acceptance picks the wrong congruent
value whenever several are in band (bands are hundreds of meters wide), which
is what seeded every episode.

**v9 rule (GT-free, no per-file constants):** for every V record, at the
k0_rule placement (unchanged), build candidates hi(R)+dh (dh -4..+4, tail
bytes from R) and take the in-band candidate **NEAREST the register value**
(dh=0 wins ties); if none in band, same at the low-aligned placement (k0=8-nb);
else the old closest-to-prev scan. This subsumes the carry search (it is the
correct nearest-congruent-value arbiter) and replaces sign-order luck with
arithmetic. dh span is insensitive: 1,2,3,4,6,8 all give identical scores
(all wins come from dh in {-1,0,+1}) — not a knife-edge fit.

Parallelogram prediction (2*last - last2) was tried as the reference and is
WORSE than nearest-last (55775 vs 55880 class errors at fold-adjacent sites);
the 8 m X window needs a +-4 m-accurate reference and the register is the best
local one.

## 4. Scores (all GT-FREE decode; DXF for scoring only; <1m criterion)

| file | v8b baseline | **v9 (nearest-last wrap)** | gains | regressions |
|---|---|---|---|---|
| intercepts (seen) | 1362/2964 (46.0%) | **1544/2964 (52.1%)** | 211 | 32 |
| SYLVANIA (COLD)   | 74668/214177 (34.9%) | **88296/214177 (41.2%)** | 27512 | 13896 |
| OB34 (COLD)       | 25283/251858 (10.0%) | **26171/251858 (10.4%)** | — | — |
| first500          | 145 / 204 / 83 | **192 / 261 / 78** | | |

Net positive on both cold files; the rule is not a fingerprint (same
arithmetic, biggest absolute gain on the cold file). SYLVANIA churn (13.9k
regressions against 27.5k gains) = sites where v8b's first-in-band carry was
accidentally right and nearest-last is not — the residual reference-accuracy
problem below. OB34 barely moves and its first500 dips 83->78: its bottleneck
remains the junk-heavy FULL harvest / very loose bands (X band 37320..69627 vs
GT ~52000..58200), NOT the value model — unchanged conclusion from
MISFRAME_CENSUS.

## 5. Residue after v9 (intercepts): 1421 broken

- Z single-axis 554, X single-axis 416, Y single-axis 278, multi 173.
- Dominant known cause: the nb=5 Z window is 0.125 m but real Z steps are
  routinely larger, so nearest-LAST picks the wrong congruent value; on X the
  8 m window fails at serpentine folds (200 m jumps observed with NO byte-2
  info in the record — the encoder must be using a topology-aware reference,
  e.g. the previous-column neighbor, which a 1D decoder cannot reproduce).
- The 21-3F plc3 fold exceptions (~1%) still mis-splice but no longer seed
  long episodes (bytes 2..6 are rewritten every vertex; corruption no longer
  parks in kept high bytes for dozens of vertices).

## 6. Next lead (one)

**The reconstruction reference, not the placement.** The value model is now
"low-window + nearest-congruent-to-reference"; the remaining errors are
reference accuracy: X folds and Z steps exceed the half-window of the LAST
value. The encoder's reference is almost certainly the serpentine neighbor
(previous column, ~column-height back in emission order — cf. the fold/column
structure in RESUME-2026-07-10). A GT-free column-period estimate (e.g.
autocorrelation of the decoded X sequence, or the op-channel round-robin
schedule) feeding a previous-row reference into the same nearest-congruent
rule is the direct next experiment; Z (554) and X (416) singles are the
payoff pool on intercepts, and SYLVANIA's 13.9k churn regressions should
collapse for free.
