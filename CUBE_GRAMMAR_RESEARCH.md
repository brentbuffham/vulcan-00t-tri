# Cube grammar research — toward a single decoder

User directive (2026-05-08): "Only decode the encoder. There would be one
decoder for one file. It would have a set of rules, and those rules would be
followed flawlessly every time."

## Confirmed invariants across cube1-5

### Coord region prefix
All 5 files share the **identical 27-byte pre-coord prefix** ending at `e0 0b 14`. The byte AFTER `14` (at `coord_start`) is the dispatcher to one of two encoding modes:

| First byte | Type | Mode | Files |
|---|---|---|---|
| `0x01`–`0x06` | count | Short FULL via count+stored bytes | tri-crack-solid, cube1 |
| `0x11` | non-tag/non-sep/non-count | 8-byte FULL run (Trigger A — Fan-style) | cube2, cube3 |
| `0x07`, `0x17`, `0x1F`, … | sep + FULL_IND | 8-byte FULL run (Trigger B) | cube4, cube5 |

In ALL cases, the encoder writes the 3 base coords (X, Y, Z) first. Then transitions to a TAG/SEP/DELTA stream.

### IEEE bytes for `Z = 10` are searchable in cube1, cube2, cube3
`40 24` (the IEEE prefix for `10.0`) appears in:
- cube1: offset 13 (count-encoded)
- cube2: offset 17 (8-byte FULL)
- cube3: offset 17 (8-byte FULL)

This confirms the encoder is identical across files; only the value-encoding granularity differs. The 4-byte cube1/cube2 offset gap reflects cube2's larger XY values needing more storage upstream — NOT a different encoder.

## Cube1 coord-region byte map (axis-aligned, ground truth known)

```
+0  02     COUNT=2 → 3-byte FULL = 49.99 (X=50)
+4  40 00  TAG 40:00 (lo=0)
+6  02     COUNT=2 → escape-strip stored from [fc,40,39] to [40,39] → FULL = 25.0 (Y=25)
+10 80 1d  TAG 80:1D (lo=D)
+12 01     COUNT=1 → 2-byte FULL = 10.0 (Z=10)
+15 a0 07  TAG A0:07 (lo=7)
+17 e0 07  TAG E0:07 (lo=7)
+19 17     SEP 0x17
+20 00 4e  COUNT=0, DELTA → 60.0 (Z=60, top plate) ← encoder says this is Z
+22 e0 06  TAG E0:06 (lo=6)
+24 17     SEP 0x17
+25 01 52 c0  COUNT=1, DELTA → 75.0 (Y=75) ← encoder says this is Y
+28 60 10  TAG 60:10 (lo=0)
+30 e0 08  TAG E0:08 (lo=8)
+32 2f     SEP 0x2F
+33 c0 17  TAG C0:17 (slot 1, lo=7)
+35 c0 2f  TAG C0:2F (slot 2, lo=F)
+37 00 58  COUNT=0, DELTA → 99.0 (X=100) ← encoder says this is X
+39 40 5e  TAG 40:5E (slot 5, lo=E)
+41 01 ff fe  COUNT=1, DELTA — NOT a real coord, see "G6 artifact" below
+44 e0 08  TAG E0:08
+46 5f     SEP 0x5F
... (slot-assignment TAG chain follows)
```

## Inter-coord transition patterns observed

### Same as solid cube
Both cube1 and the original solid cube produce 6 coord groups with axis pattern X-Y-Z-Z-Y-X. The byte structure between coords is:

```
TRANSITION       PRE-TAGS              SEP    NOTES
G2(Z)→G3(Z)      ...A0:07 + E0:07      0x17   "stay on Z" — preceding E0 lo=7
G3(Z)→G4(Y)      E0:06 (cube1)         0x17   "Z→Y cycle" — preceding E0 lo<7
                 E0:05 (solid)
G4(Y)→G5(X)      ...60:10 + E0:08      0x2F   "Y→X cycle" — SEP 0x2F
                 ...80:0F + E0:07 + C0:17 + C0:2F
```

### Tentative rule (NOT YET PROVEN UNIVERSAL)
- **SEP 0x17 + preceding E0:lo where lo ≥ 7** → STAY on current axis
- **SEP 0x17 + preceding E0:lo where lo < 7** → CYCLE BACK (Z→Y→X→Z)
- **SEP 0x2F** → CYCLE BACK 2 steps OR specific Y→X transition

This rule, if it holds:
1. For solid: G2 stays on Z (E0:07+0x17), G3 cycles Z→Y (E0:05+0x17), G4 cycles Y→X (0x2F). ✓
2. For cube1: G2 stays on Z (E0:07+0x17), G3 cycles Z→Y (E0:06+0x17), G4 cycles Y→X (0x2F). ✓
3. Must verify for cube2/3/4/5 (rotated — different value patterns but should follow same rule).

## What's still unknown

- The role of the OTHER tags (A0:07, 80:1D, 80:07, 60:10, 60:08, etc.) preceding each E0 — what do those encode?
- The "G6 artifact" in cube1 (decoded as 131040): bytes `01 ff fe` follow a TAG 40:5E. Solid doesn't have an equivalent decode at this position — its bytes go directly from C0:2F to A0:27 (TAG chain). Hypothesis: when the encoder emits a slot-set, certain TAG sequences shouldn't be followed by a count+stored DELTA; we're misreading the count byte. A "skip count byte if previous byte was a slot-assigner" rule may be the universal fix.
- The slot-assignment TAG chain semantics: C0:hi:lo, A0:hi:lo. The hi_nib is slot index, lo_nib selects which axis value? But cube2-5 don't follow the same structure since they have different unique-value counts.

## Next concrete steps (no special-cases)

1. **Verify the SEP+E0:lo rule across cube2-5 and solved files** — write a tool that walks each coord region, identifies transition events (SEP + preceding tags), predicts axis from the rule, and compares to closest-delta's answer. Where they disagree on solved files, investigate which is right.
2. **Find the "skip count byte" rule** for the artifact case. Hypothesis: after a TAG with hi_nib ≥ 5 (slot index ≥ 5), don't interpret the next byte as count+stored. Verify against all files.
3. **Build the universal axis state machine** based on confirmed rules. Replace closest-delta in `assign_axes` with the state machine. Verify all solved files still pass AND all 5 cubes get correct axes.

## Tool: byte-role labeling

The Python script `tools/label_cube_bytes.py` (TODO: extract from inline) walks a coord region and labels every byte by role: COUNT, STORED-FULL, STORED-DELTA, TAG-cls, TAG-b2, SEP, RUN-MARKER, UNK. Use this to align cube1 vs cube2 for byte-by-byte structural comparison.

## TEST attempt: count=0 misalignment guard (FAILED, reverted)

**Hypothesis:** In coord region, when `count=0` with stored=[X] where X is itself a separator byte, treat 0x00 as a misalignment marker (skip it).

**Tested:** Implemented rule, ran regression.

**Result:** PRISM dropped 4/4 → 2/4. Reverted.

**Why prism broke:** Prism +27 has bytes `00 b7` where 0xb7 is sep+TAG-class A0. The DELTA decode produces Z=5500.0 — a REAL prism Z value (apex Z). So `count=0 + stored[0]_is_sep` is a legitimate DELTA for prism but a misalignment for cube2.

**Differentiating context (raw bytes, NOT byte-pattern alone):**

```
prism +27 (legitimate Z=5500 DELTA):
  ...02 40 b3 88        (G2 base Z=5000)
     80 07              (TAG)
     01 62 c0           (DELTA G3=150)
     80 07              (TAG)
     01 97 70           (DELTA — produces another Z value)
     80 07              (TAG)
     00 b7              ← this count=0 stored=[b7] → DELTA producing Z=5500 (real)

cube2 +44 (artifact 15.73):
  ...01 4f 74           (DELTA G3=62.91)
     40 27              (TAG 40:27)
     08                 ← UNK byte (parser misalignment indicator)
     e0 40              (TAG E0:40 — BUT if 0x08 was a real count, what follows would differ)
     40 ce 48 1c 2a 0c
     ea e0
     00 2f              ← this count=0 stored=[2f] → DELTA producing 15.73 (artifact)
```

The cube2 case has a chain of "UNK" bytes (0x08 isn't count/sep/tag-class) and what look like multi-byte TAG sequences. The prism case has clean count→TAG→count→TAG flow.

**Implication:** The 0x00-as-misalignment rule needs CONTEXT — specifically, recognition of when the parser is in a "broken" state. Possibly:
- Track whether we've seen an UNK byte recently
- Or recognize that certain TAG sequences (multi-byte, no SEP between TAGs) are slot-assignment phases NOT coord-emission phases
- Or detect the "phase transition" from coord-emission to slot-assignment based on a specific byte pattern

**Next experiment:** investigate the UNK byte 0x08 in cube2 specifically. Is it a phase marker the encoder uses? Cube4 also has UNK bytes (0x14, 0x16). If these UNK values appear consistently, they're likely intentional markers we don't yet decode.

## TEST-054 attempts — both failed, documented

### Attempt 1: deactivate greedy 0x40-prefix-FULL after first DELTA
Hypothesis: the greedy "treat any 0x40-prefixed 8-byte sequence as FULL when full_run_active" rule (lines 214-225 of parse_coord_elements) creates cube2's 11.52 artifact by consuming `40 27 08 e0 40 54 ce 48` (TAG sequence) as a FULL.

**Result:** Cube2's 11.52 artifact eliminated, BUT Fan regressed 3/6 → 0/6. Fan needs the greedy rule to fire AFTER its DELTAs (Fan has interleaved FULLs and DELTAs). Reverted.

### Attempt 2: skip 0x00 if stored[0] is separator
Hypothesis: count=0 + stored[0]_is_separator is a misalignment marker.

**Result:** Cube2's `00 2f` artifact eliminated, BUT Prism regressed 4/4 → 2/4. Prism +27 has bytes `00 b7` legitimately encoding Z=5500 (apex Z). Reverted.

## What both failures teach us

The encoder uses MULTIPLE coord-encoding behaviors that depend on STATE/CONTEXT, not just on local byte patterns:
- Fan: emits FULLs throughout (greedy rule HELPS)
- Prism: 0x00 + sep can be a real DELTA producing 5500 (Z apex)
- Cube2: 0x00 + sep is a misalignment after the parser's gone off-track

Distinguishing these requires tracking encoder STATE — at which "phase" of the file the encoder is currently emitting:
- Phase A: base FULLs (X, Y, Z of corner 0)
- Phase B: more FULLs (additional unique values)
- Phase C: DELTAs from running prev (compact deltas)
- Phase D: slot-assignment TAGs (no more coord emission)

The encoder transitions through these phases via specific byte signals. We need to identify those signals.

## Hypothesis for next iteration

Maybe the long sequence of TAGs (with no SEPs between them) is the "Phase D entry signal". When we see ≥3 TAGs in a row without intervening SEPs/COUNTs, we're in slot-assignment phase, and any subsequent 0x00 should be treated as misalignment.

For cube2 +44: between TAGs 40:27, E0:40, 40:CE, 40:1C, 20:0C, E0:E0 (6 TAGs in a row, 12 bytes) we have NO SEPs. Then 0x00 misalignment. → Phase D entry triggered.

For prism +27: pattern is count→TAG→count→TAG (alternating). Phase D NOT triggered.

This is a context-sensitive rule that requires tracking "consecutive TAG count" or "bytes since last SEP/COUNT". Will test this in the next iteration.

## TEST-055 attempts: context-aware rules also failed

### Attempt 3: skip 0x00 if (stored is sep) AND (≥8 bytes since last COUNT)
Hypothesis: cube2's misalignment is detectable because there's a long gap since the last legitimate COUNT.

**Result:** Rule never fired because the greedy 0x40-prefix-FULL detection consumes those bytes BEFORE the parser reaches the 0x00. The artifact-emitting 0x40-prefix happens at +31 (cube2), well before the 0x00 misalignment at +44 — by the time we reach +44, the 0x00 has already been consumed as part of TAG E0:00 at +43.

### Attempt 4: require FULL-chain context for greedy 0x40-prefix-FULL
Hypothesis: only fire the greedy 0x40-prefix rule when the next 0x40-prefixed sequence ALSO starts at pos+8 (suggesting genuine FULL chain).

**Result:** Fan regressed 3/6 → 0/6. Fan's post-base FULLs are NOT in adjacent chains — they're isolated FULLs surrounded by TAGs. So the chain requirement breaks fan.

## Conclusive learning

The encoder uses STATEFUL phase tracking that simple local-context rules can't replicate:
- **Fan/NonRound mode:** isolated FULLs interspersed with TAG/SEP groups. The 0x40-prefix-FULL detection MUST fire even after TAGs.
- **Cube2-5 mode:** post-base bytes are mostly TAGs encoding slot-references, with occasional DELTAs. The 0x40-prefix-FULL detection MUST NOT fire after the initial DELTA stream begins.

Both modes use the same encoder; the BYTE SIGNAL distinguishing "FULL coming up" from "TAG coming up" is something we haven't decoded yet. The current parser can't tell them apart because the SIGNAL probably involves multi-byte context (perhaps a specific E0:lo TAG before the 0x40 indicating phase transition).

## Approach change for next iteration

Instead of trying to derive parser rules from byte-pattern observations, **reverse-engineer the encoder's phase transitions**. The encoder must emit a byte SEQUENCE that signals phase changes (e.g., "next is a DELTA stream", "next is a FULL stream", "next is slot-references"). Identify these phase-transition signals by:

1. For each known coord (where I have ground truth value), find the bytes that produced it.
2. For each artifact, find the bytes that produced it.
3. Look at the bytes IMMEDIATELY preceding each — what's invariant across "real" emissions vs invariant across artifacts?
4. The differing pattern IS the phase signal.

This is more intensive but data-driven. It might reveal that, say, "the bytes `E0:08 5F` always precede a FULL chain phase" or "the bytes `40:00 17` always precede a slot-assignment phase."
