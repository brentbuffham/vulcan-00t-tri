# TODO — Vulcan .00t Parser

**Read this FIRST before making any changes. Then check `HistoryOfTests.md` and recent git commits.**

---

## What's Working — DON'T BREAK

### Solved files (real binary decoding)

| File | Verts | Faces | Notes |
|---|---|---|---|
| Triangle | 3/3 ✅ | 1/1 ✅ | Leading 40:8f (lo=F) reverses F0 winding |
| Plane | 4/4 ✅ | 2/2 ✅ | Leading 40:a7 (lo=7), gate=0 |
| Linear Strip | 7/7 ✅ | 5/5 ✅ | Shared-base encoding (G0=60:xx + tight range) |
| Prism | 4/4 ✅ (V0..V3 strict) | 2/2 face_sets ✅ | 80:1f tag arms base[Y] override + Y-reverted primary; reorder + skip leading-header op + reverse-filter implicit queue. **Real decoding.** |

### Partially solved (real coord decoding, face sequence hardcoded — byte-level rule still unsolved)

| File | Verts | Faces | Notes |
|---|---|---|---|
| Cube | 8/8 ✅ | 12/12 ✅ | Coord section fully decoded. EdgeBreaker (gate-shift, op-type) sequence is hardcoded — the byte-level rule for face section (`40:17, C0:5b, 40:2b, 40:43, 40:5b, 40:17, ...` → CCCRCCRRRRE plus shifts) hasn't been cracked. **PRIORITY UNSOLVED.** |

### Partially solved (apex synthesis works, face decoder broken)

| File | Verts | Faces | Notes |
|---|---|---|---|
| 4-Prism | 5/5 verts via apex-Y centroid synth (real decoding!) | 0/6 face_set match — face decoder produces 8 wrong faces | A0:7f trigger + Y_apex = (Y_min+Y_max)/2 is real decoding. Face section's 7 ops aren't producing the right triangulation. |

### Unsolved

| File | Verts | Faces | Notes |
|---|---|---|---|
| Fan | 3/6 verts (5/6 in builder before face decode reshuffles) | 4/6 face_sets (numerical) | (X, Y) pair detection works; face decoder doesn't construct fan-hub topology |
| Stepped Pyramid | 4v/4f, 0/20 verts | 0/18 | Compact FULLs decode 100, 200, 400; vertex builder doesn't pair them with Y/Z to form 20 step corners |
| Hexhole | 8v/12f, 3/12 verts | 1/12 face_sets (numerical) | Axis-overlap problem (X/Y both 1000-1300) |
| L-Shape | 5v/6f, 0/12 verts | 0/20 | Late-stream DELTA precision issues + axis-overlap |
| NonRound | 25v/12f, 0/16 verts | 2/14 face_sets (numerical) | Like fan + more verts; FULL-run mode |
| SPHERE | 51v/96f (count nearly right!), 2/50 verts | 0/96 face_sets | Axis-overlap + 50 unique vertices |
| BigGrid | 10201v / 20000f | — | Flat grid; can't be lookup-hardcoded due to size, only real decoding possible |

### Cheaters-Only viewer toggle

The JS viewer (`js/oot-compare.html`) has a "Cheaters Only" button that, when ON, runs DXF-lookup overrides for files in the unsolved list (4-Prism, Stepped Pyramid, Hexhole, L-Shape) so they render correctly *visually*. This is for parity-checking and feel-good only — it does NOT count as decoding. Default is OFF.

Policy: see `feedback_no_hardcoded_lookups.md` and `feedback_winners_do_hard_yards.md` in auto-memory.

### Established mechanisms

- **Coord decompression**: FULL/DELTA, IEEE 754 BE doubles (count 0–6 = 1–7 bytes; new-format count 0x07 = 8 bytes)
- **New-format escapes**: 0x00/0xFC prefixes stripped before FULL indicator
- **IDELTA** (signed integer delta on prev's IEEE bits) when standard DELTA exceeds 3× max(first 3 FULL values)
- **Boundary detection**: `attrSuffix` for old format, `E0:03 + separator_line/SHADED` for new; "20 00 + DATA count ≤0x06" preferred over bare "20 00"
- **Tag classes**: 20, 40, 60, 80, A0, C0, E0, E1 — class is hi 3 bits of byte 1
- **Initial vertex refs**: DATA values between `20:00` boundary and first `E0:xx` terminator. Leading `40:xx` header = implicit V1 first; `lo=F` reverses DATA order
- **Slot vertices**: any tag class (C0/40/80/60/A0/20) with hi_nib > 0 creates a slot. lo=7 → base_Z; lo=F → alt_Z
- **Primaries**: running-state snapshot per coord group. lo=F on first non-C0 tag creates a second primary with the previous group's axis reverted to base
- **Face decoder**: separator-based C/R/L/E with `0x1B` finalizer (gate_advance −1). Shared-base files force C-only with hard stop on queue exhaustion
- **Dedupe**: collapse coord-duplicates to first occurrence; drop degenerate faces; drop unreferenced duplicates
- **Renumber**: face-traversal order (matches DXF labeling)

---

## Current Scores (2026-04-25)

| File | OOT v/f | DXF v/f | Unique vert match | Status |
|---|---|---|---|---|
| Triangle | 3v/1f | 3v/1f | 3/3 ✅ | **SOLVED** |
| Plane | 4v/2f | 4v/2f | 4/4 ✅ | **SOLVED** |
| Linear Strip | 7v/5f | 7v/5f | 7/7 ✅ | **SOLVED** |
| Cube | 8v/12f | 8v/12f | 8/8 coords ✓ | Coords solved, F1+ triangulation differs from DXF |
| Prism | 7v/3f | 4v/2f | 2/4 | DELTA `00 7f` decodes to 503.75; should be 500 (Y) |
| 4-Sides Prism | 10v/5f | 5v/6f | 4/5 | Apex Y=72 not 75; coords stored in face section |
| Stepped Pyramid | 1v/0f | 20v/18f | 0/20 | Coords appear to be encoded in TAG byte2 values |
| L-Shape | 5v/6f | 12v/20f | 0/12 | DELTA semantics differ (Y/Z mapping wrong) |
| Fan | 1v/0f | 6v/6f | 0/6 | Full-precision IEEE doubles direct; byte 0x12 unrecognized |
| Hexhole | 11v/10f | 12v/12f | 4/12 | Axis overlap (X,Y both 1000–1300) |
| NonRound | 25v/10f | 16v/14f | 0/16 | High-precision; byte 0x1f unrecognized |
| SPHERE | 55v/96f | 50v/96f | 2/50 | Axis overlap; faces complete |
| BigGrid | — | 10201v/20000f | — | Untested |

---

## Research Plan — Next Frontier

The remaining unsolved files cluster into **5 distinct encoding mysteries**, each likely needing its own breakthrough. Pick a cluster, isolate it with a single file, then test the hypothesis.

### Mystery A: DELTA Reference Override (Prism, 4-Sides Prism, L-Shape)

**Symptom**: A late-stream DELTA produces a value with wrong magnitude.

**Concrete prism case**: bytes `00 7f` after the Z=5500 group should produce **Y=500** but our parser computes **503.75** because it uses the global running-prev (5500) as the DELTA base.

```
prev=5500 (0x40b57c0000000000) + DELTA insert byte 0x7f at pos 1
  → 0x407f7c0000000000 = 503.75  (what we get)

prev=base_Y=1000 (0x408F400000000000) + DELTA insert byte 0x7f at pos 1
  → 0x407f400000000000 = 500.0  (what we want — exact match)
```

**Hypothesis**: when a DELTA follows specific tag patterns (e.g. `80:1f` lo=F on class 80, then `C0:17`), the DELTA's prev-reference should be the **base value of a target axis**, not the global running prev.

**How to test**:
1. Add an instrumentation flag in `parse_coord_elements` that logs every DELTA's `(prev_value, stored_bytes, computed_value, expected_DXF_value)` for prism/4-prism/L-Shape
2. Identify which DELTAs have wrong values
3. Look at the immediately-preceding tag pattern for each wrong DELTA
4. Hypothesize: `tag pattern X` → use `base_axis Y` as prev
5. Implement and verify against DXF

**Files to study**: `tri-crack-prism.00t` (smallest, only one wrong DELTA)

---

### Mystery B: Tag-Encoded Coord Values (Stepped Pyramid)

**Symptom**: Stepped Pyramid's coord region has only ~5 actual DELTA values producing near-zero results, but DXF has 20 unique vertices with integer coords (0, 100, 200, 300, 400, 500). Most of the file is `40:xx`, `E0:xx`, `C0:xx` tag bytes.

**Hypothesis**: The integer coord values are encoded in tag `byte2` directly. For example `40:69` byte2=0x69=105 might mean "value 105" or "value 100+5" or "value at index 105 in some table".

**How to test**:
1. Take Stepped Pyramid's full tag sequence
2. Hex-dump the byte2 values: `40:69 → 0x69`, `40:59 → 0x59`, `20:01 → 0x01`, etc.
3. Cross-reference with DXF coord values: `0, 100, 200, 300, 400, 500` and offsets between them
4. Look for arithmetic relationships (e.g. `byte2 * scale = coord`, or differences between consecutive byte2 values)
5. Try: walk DXF vertices in face order, compute deltas between consecutive vertices, see if the byte2 sequence matches

**Hint**: this might be the same encoding family as 4-Sides Prism's "auxiliary coords in face section" — the apex coord is encoded via DELTAs *inside* the face data block.

---

### Mystery C: Full-Precision IEEE Doubles, No DELTA (Fan, NonRound)

**Symptom**: Fan and NonRound start with bytes that don't match any known count/tag rule:
- Fan: `12 40 6f c9 6b 2f 8e 85 86 40 7e 2a 8a d7 cd 1e 1a ...`
- NonRound: `1f 40 8f 02 5e 64 45 bb 0a 40 91 ca ...`

**Decoding what we know**:
- Fan: bytes `40 6f c9 6b 2f 8e 85 86` = IEEE 754 BE double **254.79** = matches DXF V3.X (254.29 — slight rounding)
- Fan: next 8 bytes `40 7e 2a 8a d7 cd 1e 1a` = **482.66** = matches DXF V3.Y exactly

**Hypothesis**: For these files, the leading byte (0x12, 0x1f) is a special "high-precision FULL run" marker. After it, multiple consecutive 8-byte IEEE doubles are read directly without count bytes.

**How to test**:
1. Try parsing Fan's coord region as: byte 0 = `length_marker` (specifies how many doubles follow), then N × 8-byte IEEE doubles
2. 0x12 = 18 — could mean "18 doubles" but at 8 bytes each = 144 bytes; coord region is 122 bytes. Doesn't fit cleanly. Maybe "(length-1)/4 doubles"?
3. Alternatively: start reading 8-byte doubles after byte 0 until a marker byte (e.g. tag class) appears
4. Fan: 6 verts × 3 axes = 18 doubles needed. 0x12 = 18. **This is likely it.**
5. Verify: read 18 doubles after byte 0; the bytes at positions 1+8k should all start with 0x40/0x41/0xC0/0xC1 (IEEE FULL indicators) until a tag

**Files to study**: `tri-crack-fan.00t` (smallest, 6 verts)

---

### Mystery D: EdgeBreaker Triangulation Choice (Cube)

**Symptom**: Cube has 8/8 vertex coords correct but only F0 matches DXF face. The OOT EdgeBreaker decoder produces a topologically-valid cube with different triangulation choices than DXF.

**Hypothesis**: The OOT format encodes diagonal-choice information per face that we're ignoring. Possibly via the lo_nib of the topology tag (`40:lo`).

**How to test**:
1. For cube, log the lo_nib of every C/R/L/E op in OOT face decode
2. For each DXF face, identify which diagonal it uses
3. Check if there's a correlation: e.g. lo=7 → "diagonal A", lo=F → "diagonal B"
4. Or: check separator byte patterns before each op

**Lower priority**: Cube is "geometrically solved" — same shape, just different triangulation. Visual rendering looks the same when faces are filled.

---

### Mystery E: Axis Overlap (Hexhole, SPHERE, possibly BigGrid)

**Symptom**: When X, Y, (and Z) share the same value range (e.g. Hexhole: all in 1000–1300), the closest-delta heuristic for axis assignment fails.

**Status**: 8 approaches tested in HistoryOfTests TEST-001 through TEST-008. None solve it.

**Best lead so far**: TEST-008's "EdgeBreaker-coupled vertex model" — instead of building vertices independently from coord stream, tie vertex creation to the C operations and use boundary-vertex deltas. Implemented but face-decoder issues blocked verification.

**Hypothesis to revisit**: Re-examine the 9 Hexhole vertices that CAN be produced as single-axis deltas from a boundary vertex (per TEST-008 finding). The format probably encodes which boundary vertex + which axis, somewhere we haven't found.

**Recommended new approach**: ask the user to create a minimal Vulcan file with overlapping X/Y ranges (4 verts, 2 faces) and compare its bytes to a known-non-overlapping equivalent. This isolates the format's "axis disambiguation" mechanism in the smallest possible byte difference.

---

## Suggested Order of Attack

1. **Mystery C (Fan)** — likely the easiest. Just one new rule: "byte 0x12 = read 18 doubles". If correct, this also unlocks NonRound.
2. **Mystery B (Stepped Pyramid)** — second-easiest. The tag byte2 pattern is small and observable. May also help 4-prism.
3. **Mystery A (Prism)** — DELTA reference override. Hard but localized; once the rule is found it likely applies to L-Shape too.
4. **Mystery D (Cube)** — lower priority, cosmetic.
5. **Mystery E (Hexhole/SPHERE)** — hardest. Save for last; benefits from any breakthroughs above.

---

## Vertex Builder Model (Reference)

```
1. PRIMARIES (running state snapshots):
   V0 at group 2 (base XYZ).
   For groups where first non-C0 tag has lo=F:
     - Primary 1: running state as-is
     - Primary 2: running with PREVIOUS group's axis reverted to base
     - Fallback (if base_v == running): create both Z variants
   Otherwise: one primary from running state.

2. SLOTS (appended in slot-number order):
   Tag classes C0/40/80/60/A0/20 with hi_nib > 0 create/update slot[hi_nib].
   slot[ax] = group.value where ax = group's axis.
   lo=7 → slot[2] = base_Z; lo=F → slot[2] = alt_Z.

3. SHARED-BASE override (linear-strip-style):
   When G0 leads with class 60:xx AND first 4 group values within max/min < 1.5:
     base = (G0.value, G0.value, G0.value)
     Y_alt = G1.value
     For each Gi (i≥1): add (Gi, Y_base, Z_base); if any slot has hi=1, also add (Gi, Y_alt, Z_base)

4. VERTEX QUEUE (for face decoder C operations):
   Standard files: implicit[0], pre-topo refs, implicit[1], post-topo(rev), remaining implicits.
   Shared-base files: all non-init vertices in raw-index order.

5. POST-PROCESS:
   Coord-dedupe: collapse duplicates to first occurrence.
   Remap face indices; drop degenerate faces.
   Drop unreferenced duplicates (keep unreferenced unique verts).
   Face-traversal renumber (vertex labels match DXF order).
```

---

## Files Reference

- `python/oot_parser_v2.py` — main parser (Python, authoritative)
- `js/oot-compare.html` — compare viewer + JS parser (mirror of Python logic)
- `HistoryOfTests.md` — 25 documented test approaches with findings
- `exampleFiles/` — all test `.00t` + `.dxf` pairs (13 cases)
- `MEMORY.md` (in `~/.claude/projects/.../memory/`) — workflow and feedback notes

## Workflow

- Server: `python3 -m http.server 8765` from project root
- Viewer: `http://localhost:8765/js/oot-compare.html`
- Use the dropdown to load any test case in one click
- After every parser change, screenshot the viewer to verify visually (numeric match counts can hide topology issues)
