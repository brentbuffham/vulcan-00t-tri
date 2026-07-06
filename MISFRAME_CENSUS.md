# Misframe census + framing fix (2026-07-06)

Follow-up to COLD_VALIDATION.md ("misframed records pollute the FULL harvest →
loose bands → drift"). Task: find WHERE/WHY the v7 tokenizer misframes, fix it
GT-free, validate CROSS-FILE. Scripts: `python/census_misframe.py`,
`python/fe_probe.py`, `python/trunc_probe.py`, `python/decode_v8_frame.py`.

GT (each file's DXF) used ONLY to LABEL records for the census and to SCORE
decodes. No GT in any decode path; no fingerprinting — all rules are byte-role.

## 1. Census — where the misframes are, by tokenizer branch

FULL-harvest purity (pass-1 framed FULLs, GT-labeled in/out of true extents):

| file | branch | clean | junk | junk% |
|---|---|---|---|---|
| intercepts | F  | 268 | 23 | 7.9% |
| intercepts | Fe | 145 | 0  | 0.0% |
| SYLVANIA   | F  | 12472 | 1724 | **12.1%** |
| SYLVANIA   | Fe | 4108 | 4 | 0.1% |

- The junk enters through the **F branch**, and almost always right after a
  **truncated V** (an in-band 8-byte read that starts INSIDE a declared V
  payload): SYLVANIA pass-1 junk F = 1054 after-truncation + 670 not (most of
  the latter are downstream of an earlier misframe). Fe VALUES are essentially
  never junk — but Fe is the branch that *causes* desyncs (below).
- Decode-time GT-free suspects (v7): intercepts r2-failures 98, off-phase FULLs
  32/413; SYLVANIA r2-failures 2048, off-phase FULLs 1801/17172.
- Break onsets (correct→wrong, GT-labeled): intercepts 340, SYLVANIA 12245.
  Most onsets are plain T·V spans (value-model damage), but the *episode
  starters* trace back to two framing defects:

## 2. Diagnosis — the two byte-level defects

### Defect 1: Fe consumed a fixed 10 bytes; the trailer is an OPTIONAL SEP
v7 Fe = escape byte + 8-byte FULL + **always 1 trailer byte** (`pos += 10`).
Census of the actual byte at `pos+9` over every Fe:

- intercepts (145 Fe): 133 are SEP-class (`(b&7)==7`: 0x_7/0x_F), 11 are
  **0x40/0x41 = the lead byte of the NEXT real FULL**, 1× `0x20` (followed by
  `17 03…` = next TAG·SEP record), 1× `0x38` (followed by `ef` = TAG·SEP).
- SYLVANIA (4108 Fe): top trailer values 0x17,0x5F,0xA7,0xEF,0x77,0x97,… ALL
  SEP-class — except **0x40 ×172 / 0x41 ×7**, and `full_at(pos+9)` fires at 173
  of them (a real in-band FULL starts at the byte v7 swallowed).

So the grammar is: `escape · FULL(8) · [SEP trailer iff (b&7)==7]`.
When the next record is another FULL (or a TAG·SEP pair), there is NO trailer;
v7 ate its first byte → the FULL reset was lost → register kept a stale value →
the following V splices inherited the corruption (this is exactly the
"inherited register corruption" episode mechanism from SELECTOR_HUNT). Verified
by hand at intercepts vtx3: `a9 | 40eb…(X FULL) | 41 03e79934…(Y FULL)` — v7's
`+10` swallowed the `41`.

This also subsumes the escape case with escape byte < 0x20: v7 routed those
through the V branch (empty payload + truncation), consuming 9 bytes with no
trailer handling — same record type, inconsistent length.

### Defect 2: mid-payload V truncation manufactures junk FULLs
v7 truncated a V payload whenever an in-band 8-byte double appeared to start
inside it, then emitted that read as a FULL (register reset). GT labeling:

- SYLVANIA: 1695 truncation events → following F: 1120 "clean" / **575 junk**
  (band too loose to reject; each junk one resets a register to garbage).
- intercepts: 28 events, all "clean" — but these are real FULLs *rescued* after
  an upstream Defect-1 desync, i.e. a self-healing hack, not grammar.

With Defect 1 fixed, framing stays aligned and the rescue is unnecessary; the
remaining mid-payload hits are payload bytes that coincidentally read in-band.

## 3. Fix — decode_v8_frame.py (GT-free, byte-role rules only)

Tokenizer changes vs decode_v7_cold.py (everything else identical):
1. **escape+FULL**: any lead byte with `full_at(pos+1)` → Fe; consume 9 bytes,
   plus 1 more IFF the next byte is SEP-class (`(b&7)==7`).
2. **V records always take their declared nb bytes** (no mid-payload FULL
   truncation) — variant `b`; variant `a` kept truncation for comparison.

## 4. Scores (GT-free decode; DXF scoring only; <1 m criterion)

| file | v7 baseline | v8a (Fe fix only) | **v8b (Fe fix + no truncation)** |
|---|---|---|---|
| intercepts (seen) | 1241/2950 (42.1%) | 1363/2967 (45.9%) | **1362/2964 (46.0%)** |
| SYLVANIA (COLD)   | 41131/213321 (19.3%) | 44916/213817 (21.0%) | **74668/214177 (34.9%)** |
| OB34 (COLD)       | 19097/241376 (7.9%) | 21689/252217 (8.6%) | **25283/251858 (10.0%)** |

- first500: intercepts 136→145; SYLVANIA 180→204; OB34 first500 → 83.
- Vertex counts move toward GT (intercepts 2950→2964 of 2975; SYLVANIA
  213321→214177 of 214709) — fewer swallowed records.
- Bands: intercepts ~unchanged (already clean). SYLVANIA X tightened
  [39670..59095] → [41279..57166] (GT [48500..51600] still amply covered);
  the bigger win is direct: junk FULL resets no longer fire at all.
- The fix is not a fingerprint: same byte rules, both files improve, the COLD
  file improves MOST (junk-heaviest harvest had the most to lose).

## 5. Remaining damage / next lead

The dominant residual onset signature on both files is a plain `T·V` span with
nb=4/5 payloads on X — i.e. the k0/carry VALUE model (splice depth), not
framing. Next: re-run the selector_hunt labeling on v8b output; with framing
clean, the k0-rule residue (esp. `T1=0x20`/nb=5 classes) is the next mechanical
defect. OB34 note: it improves (7.9→10.0%) but its bands stay very loose
(X[37320..69627] vs GT ~[52000..58200]) — its FULL harvest is junk-heavy even
after the fix; OB34-specific harvest hygiene is the other open lever.
