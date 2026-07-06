# k0 event-site rule extraction — intercepts v5-P2 → v5-P3 (2026-07-06, Opus)

Executed the spec in `DRIFT_BAND_FINDINGS.md` ("Spec-shaped next step").
Scripts: `python/k0_event_extract.py` (teacher-forced analysis),
`python/decode_v5p3.py` (GT-free amended decode + scoring).
GT (`intercepts_gt.csv`) used ONLY as teacher-forced target and for scoring —
never as decoder input. The final rule is GT-free and operates on byte roles only.

## RESULT: PARTIAL WIN — one deterministic rule found, GT-free, no regression.

**Locked rule (v5-P3), pure byte-role, no fingerprint:**
```python
def k0_rule(T, nb):
    if nb == 4:            # <-- NEW (v5-P3): 4-byte payloads always splice at k0=3
        return 3
    if T is not None:
        T1, T2 = T
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {5: 3, 6: 2}.get(nb, max(0, 8 - nb))
```
The old rule returned `k0=2` for `nb==4` whenever `T1∈0x21..0x3F` or
(`T1==0x20 & T2>=0x60`). For 4-byte payloads that is wrong: k0=2 overwrites a
HIGH mantissa byte, so the value stays inside `band()` (sanity gate can't catch
it) but lands metres off — the exact drift-band mechanism. k0=3 keeps the high
mantissa stable. `nb` is read from the SEP low bits (`(b&7)+1`), a byte role, so
this is not a fingerprint.

## GT-free scores (GT = scoring only)

| decode            | anchor <1m | anchor <2mm | XZ-exact map |
|-------------------|-----------:|------------:|-------------:|
| v5-P2 baseline    |        760 |         693 |          970 |
| **v5-P3 (nb==4→3)** |    **867** |     **702** |      **972** |
| Δ                 |       +107 |          +9 |           +2 |

No metric regressed. XZ-exact map floor (≥970) held (+2). +107 anchors from a
one-line change confirms the drift-doc thesis: fixing an onset mis-splice
rescues the whole downstream band, not just the onset point.

Rejected variants (also GT-free, scored): `v1` = apply k0=3 to ALL `T1 21..3F`
(any nb) → **collapse to 258 anchors / 284 map** (breaks the many good nb=5/6
points); `v3` = nb∈{4,5}→3 → same collapse. So the override is genuinely
`nb==4`-specific: nb==5 payloads really do want k0=2. `v2` (T1 21-3F & nb4) and
`v4` (add T1==0x20 & nb4) are strict subsets of `v5`; `v4==v5` numerically,
i.e. the uniform "nb==4→3" is the minimal closed form.

## Teacher-forced analysis (labeled TEACHER-FORCED; not a decode result)

253 bad bands (err>10m). Per band onset, recomputed the dominant-error axis
(largest |dec−gtNN|) and the token that last wrote that axis register
(write→emit token gap = 1 for all 245 V-sites — corruption is in the emitting
vertex's own cycle, not an inherited base). Swept k0∈0..8−nb, c∈{0,±1,±2,±3,±4},
splicing into the pre-token register.

- 253 onsets: **8** dominant axis written by FULL/init (no k0 fix possible),
  **245** written by a V token.
- **43 / 245 (17.6%)** V-sites explained by some (k0,c) landing <1m 3D or
  axis-exact. **202 / 245 (82%) NOT explained** by any single-axis (k0,c) —
  these onsets are multi-axis corruptions or a non-splice mechanism.
- Of the 43 explained: **win_k0 = 3 for 42** (1 was k0=4); decoder chose k0=2 in
  all 43. This is the clean signal that produced the rule.
- **win_carry is fully scattered** ({+4:12, +3:7, +2:5, −4:4, −2/−3/−1/+1/0:3}
  each) and **ZERO sites are axis-exact to 1e-9**. Only 30/43 land <1m in 3D.
  → The carry sweep is NOT a real encoded field; it is the search nudging a high
  byte until the point falls within 1m of an answer-key point (overfitting).
  Carry contributes no deterministic rule. Only the k0 (2→3) signal survives,
  and only for nb==4 does it generalise GT-free (the empirical test above).

Confusion (explained V-sites, decoder→teacher-forced winner), all mismatches:
```
dec k0=2 c=+0 -> win k0=3 c=+4  n=11      dec k0=2 c=+0 -> win k0=3 c=-1  n=3
dec k0=2 c=+0 -> win k0=3 c=+3  n=5       dec k0=2 c=+0 -> win k0=3 c=+2  n=2
dec k0=2 c=+0 -> win k0=3 c=-4  n=4       dec k0=2 c=+0 -> win k0=3 c=+0  n=2
dec k0=2 c=+0 -> win k0=3 c=-2  n=3       dec k0=2 c=+1 -> win k0=3 c=+3  n=2
dec k0=2 c=+0 -> win k0=3 c=+1  n=3       dec k0=2 c=+0 -> win k0=4 c=+0  n=1
dec k0=2 c=+1 -> win k0=3 c=+2  n=3       dec k0=2 c=+1 -> win k0=3 c=+4  n=1
dec k0=2 c=+0 -> win k0=3 c=-3  n=3
```
Mismatch cross-tab concentrated in `(T1_21_3F, nb=4)` (19) and `(T1_20, nb=4)`
(5+3) — exactly the classes the rule fixes; `(T1_21_3F, nb=5)` mismatches (7)
were the overfit ones (rejected by v3's collapse).

## What remains OPEN (input for a Fable detective session)

The k0 rule is only a partial fix. **82% of band onsets (202/245) are not a
single-axis k0/carry mis-splice.** Remaining after v5-P3, the bad-band
population is dominated by:
1. **Multi-axis onsets** — more than one register wrong at the same vertex; no
   single (k0,c) lands the point. Needs the axis/phase model, not k0.
2. **8 FULL/init-written dominant axes** — the wrong value came from a FULL
   record's own bytes or a stale init register, not a splice. k0 is irrelevant;
   these implicate FULL framing or the phase reset around FULLz.
3. **Carry has no deterministic form** — do NOT chase a carry rule; it was pure
   answer-key overfitting here (0 exact matches). If a real high-byte correction
   exists it is not expressible as `±1..±4` on byte k0−1.

Next detective question: for the 202 unexplained onsets, is the corruption a
**wrong axis assignment (phase)** rather than a wrong splice offset? The write→
emit gap of 1 says the corrupting token is the vertex's own emission token, so
the phase/axis-selection state at that token is the prime suspect — that is
Mystery E (axis overlap) resurfacing at the k0 layer, not a k0 problem.

## Artifacts
- `python/k0_event_extract.py` — teacher-forced extractor (prints all tables; saves `k0_sites.pkl`).
- `python/decode_v5p3.py` — GT-free decode with amended rule + variant scoring; saves `P_v5p3.npy`.
- `python/P_v5p3.npy` — final GT-free decode (867 anchors <1m).
