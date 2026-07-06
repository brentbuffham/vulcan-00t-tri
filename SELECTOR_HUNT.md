# Selector hunt — carry(−2) vs carry(0) on class `T1=21-3F, nb=5` (2026-07-06)

**Verdict: there is NO hidden per-token selector. The "carry" tokens are
contiguous episodes of INHERITED REGISTER CORRUPTION, and the real defect was
the axis BAND being too loose to reject the drifted register. Fixing the band
(GT-free, robust shorth statistic) more than doubles the decode:
first500 76 → 135, full 601 → 1242 (20.5% → 42.1%).**

Scripts: `python/selector_hunt.py`, `python/trace_register.py`,
`python/full_harvest_check.py`, `python/y_fulls_dump.py`,
`python/decode_v7_carry.py`.

## 1. Labeling (GT used ONLY to label/pin + score — never fed to the decoder)

File-wide pinning (all 2936 v6 vertices, not just first 500) on class
`T1∈[0x21,0x3F], nb=5`:

- **NEED(−2)**: 26 tokens (pinned single-axis breaks where splice(k0=2, c=−2)
  hits the pinned true value to <1e-6)
- **ZERO**: 821 tokens (exact-correct axes written by the same class via the
  plain k0=2/c=0 splice)
- residue: 14 pinned tokens with other exact (k0,c) wins, 200 with no exact win
  (multi-cause damage)

## 2. The separator — and why it isn't a hidden state

Automatic scan over ~30 GT-free features (T1, T2, SEP byte, payload bytes,
nibbles/parities, pre-token raw bytes, last e0-record, since-FULL counters,
emission parity, borrow probes `cmp(p0, R[2])`, low-6-byte compare, etc.):

| feature | separation |
|---|---|
| `r1` = register byte 1 (the byte the carry touches) | **100.0%** — r1=0x05 → all 26 NEED; r1∈{0x03,0x84,0xEB} → all 821 ZERO |
| everything else | ≤ 98.3% (and those are proxies of the same episodes) |

All 26 NEED tokens are **axis Y** in **two contiguous runs** (vtx 440–506 and
vtx 2743–2863). `r1=05` means the Y register held ≈179,000 while true Y is
≈163,000 (`r1=03`). The register was corrupted by ONE upstream mis-splice per
episode; every later nb=5 splice keeps bytes 0–1 and propagates the error. The
teacher-forced −2 was just un-doing the inherited +2·2⁴⁸ drift each time.
**That is why applying carry −2 class-wide cratered the decode (76→4): the
carry is not a property of the token class; it is a property of a corrupted
register.** Same story presumably explains the `T1=20 → +2` class (opposite
drift direction; not separately traced).

## 3. Root cause — the band was the broken part

`trace_register.py` + GT diagnostic:

- GT true extents: X [55620.9 .. 55988.5], Y [162890.3 .. 163107.5], Z [653.2 .. 667.8]
- v6 bands (min/max of a **sliding-window** FULL harvest, every byte offset
  tested): X [52457 .. 63958], Y **[142150 .. 185745]**, Z [599 .. 744]
- The Y band is contaminated by misframed junk "FULLs" (incl. negative c1xx
  reads). A drifted register at 179k is comfortably "in band", so `r2_value`'s
  existing carry search NEVER fired, and the corruption cascaded for dozens of
  vertices.

Framed FULLs (tokenizer-aligned): Y has 18, of which 12 form a tight real
cluster [162932 .. 163072]; the 6 junk ones are scattered (170k–186k, some
negative). Same pattern on X and Z (tight real bulk + ~20% scattered junk).

## 4. GT-free fix — robust shorth bands (decode_v7_carry.py)

- pass 1: loose v6 bands → tokenize → harvest **framed** FULLs
- per axis: band = shorth(50%) of framed FULLs (shortest interval containing
  half the points — classical robust estimator) expanded ± 5×width
- pass 2: re-tokenize + decode with tight bands. Out-of-band splices are now
  rejected and the pre-existing carry/k0 search recovers the in-band value —
  the corruption episodes self-heal mechanically. No GT input anywhere;
  constants (50%, 5×) are generic and declared, not tuned per file.

Derived bands (from the file's own bytes): X [54940.8 .. 56777.5],
Y [162688.8 .. 163338.4], Z [641.1 .. 684.2] — each covers the GT extent with
margin and excludes the drift zone.

## 5. Scores (all GT-FREE decode; GT for scoring only)

| decoder | first500 | full |
|---|---|---|
| v6-clean (baseline) | 76/500 | 601/2936 (20.5%) |
| class-wide carry a/b (old, rejected) | 4 / 3 | 41 / 16 |
| **v7 shorth bands** | **135/500** | **1242/2950 (42.1%)** |

(GT has 2975 unique vertices; v7 emits 2950.)

Margin sensitivity (diagnostic only — NOT used to pick the constant):
2w→1298, 3w→1271, 5w→1242, 8w→1218, 12w→1166 full-file correct. Monotone and
gentle: the win is not a knife-edge fit. 5w kept as the declared default;
tighter margins risk clipping true extents on files where FULL resets sample
the extent sparsely.

## 6. Honest caveats

- The shorth band assumes real FULL values cluster tighter than misframed
  junk. True here; must be validated on SYLVANIA / OB34 / HEAVE before it's
  called a format rule. If a real mesh's extent is huge, 50%-shorth could
  under-cover — the two-pass structure and margin are the guards.
- 58% of vertices are still broken. The carry episodes were a symptom, not the
  main damage; the remaining breaks need a fresh failure census on v7 output.
- The `T1=20, +2` carry class was not separately traced (expected same
  mechanism, opposite drift, likely X/Z registers). Worth a 10-minute check.

## 7. Next lead (one)

Re-run the failure census (`selector_hunt.py` labeling) on TOP OF v7: classify
the remaining ~1700 breaks (single-axis vs cascade, per-axis, per-class). With
corruption cascades now self-healing, the residue should expose the next
mechanical defect (mis-framing at Fe/escape records is the prime suspect —
the junk FULLs prove misframes exist).
