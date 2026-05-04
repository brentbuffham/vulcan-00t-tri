# History of Tests — Vulcan .00t Parser Reverse Engineering

**Started:** ~January 2026  
**Last Updated:** 2026-04-25  
**Status:** Triangle, Plane, Cube, Linear Strip vertices solved; faces partial on some

## What IS Working (Ground Truth)

| File | Verts | Faces | Vertex Match | Face Match | Format |
|------|-------|-------|-------------|------------|--------|
| Triangle | 3 | 1 | 3/3 (100%) | 1/1 ✓ | OLD |
| Plane | 4 | 2 | 3/4 (75%) | Partial | OLD |
| Cube | 8 | 12 | 8/8 (100%) | Partial | OLD |
| 4-Sides Prism | 5 | 6 | 4/5 (80%) | Wrong | NEW |
| Stepped Pyramid | 20 | 18 | 10/20 (50%) | Wrong | NEW |
| Hexhole | 12 | 12 | 4/12 unique (33%) | Wrong | NEW |
| SPHERE | 50 | 96 | 16/50 (32%) | Wrong | NEW |
| Linear Strip | 7 | 5 | 0/7 | Wrong | OLD |
| Fan | 6 | 6 | 0/6 | Wrong | OLD |
| Prism | 4 | 2 | 2/4 | Wrong | OLD |
| L-Shape | 12 | 20 | 0/12 | Wrong | OLD |
| NonRound | 16 | 14 | 0/16 | Wrong | NEW |
| BigGrid | 10201 | 20000 | Untested | Untested | NEW |

**Note:** "Vertex Match" for Hexhole was reported as "8/12" but that counts OOT vertices matching ANY DXF vertex (with duplicates). Only 4/12 UNIQUE DXF vertices are actually produced.

## What IS Proven (Encoding Facts)

1. **File structure:** Header (60B) → page chain → "Created External" + "Variant" → data stream → "SHADED" → attributes
2. **Coordinate compression:** Delta-compressed truncated big-endian IEEE 754 doubles
   - Count byte 0x00–0x06: read count+1 data bytes
   - Count byte 0x07 (new format): read 8 data bytes (full precision double)
   - FULL value: first data byte is 0x40/0x41/0xC0/0xC1
   - DELTA (old): keep byte[0] from prev, insert stored bytes, keep trailing from prev
   - DELTA (new): keep byte[0] from prev, insert stored bytes, zero trailing
3. **New-format escapes:** Bytes ≥0xFC or 0x00 before a FULL indicator → strip escape, treat as FULL
4. **Signed integer delta:** When standard DELTA gives |value|>10000, treat stored bytes as signed BE integer offset on prev IEEE representation
5. **Separator bytes:** (b & 0x07) === 0x07 AND b >= 0x07 → skip 1
6. **Tag pairs:** 2-byte elements with class (hi 3 bits of byte1) and byte2 (hi_nib, lo_nib)
7. **C0 tags:** Vertex slot assignments. hi_nib = slot index, lo_nib: 0x7=base_Z, 0xF=alt_Z
8. **Axis assignment:** First 3 coords are X, Y, Z. Subsequent use closest-delta heuristic.
9. **EdgeBreaker face decode:** C/R/L/E operations from 40/C0 class tags in face section, 0x1B = gate finalizer

## The Core Unsolved Problem

**Axis assignment for overlapping X/Y ranges.** When X and Y share the same value range (e.g., Hexhole: X∈{1000-1300}, Y∈{1000-1300}), the closest-delta heuristic cannot distinguish which axis a coordinate belongs to. The encoding MUST communicate axis information somehow — this is the key to unlocking all remaining files.

---

## Test Log

---

### TEST-001: Closest-Delta Axis Assignment
- **Status:** Successful (for non-overlapping ranges)
- **Description:** Assign each coordinate to the axis whose current running value is closest
- **Process:** First 3 coords forced to X,Y,Z. For each subsequent coord, compute |value - current[axis]| for all 3 axes, pick minimum.
- **Findings:** Works perfectly for Triangle (3/3), Cube (8/8) where X,Y,Z have disjoint value ranges. Fails for Hexhole (4/12 unique) where X,Y overlap.
- **Conclusion:** Necessary but insufficient. Needs supplementary axis info for overlapping ranges.

---

### TEST-002: Tag-Based Axis State Machine (Old JS Parser)
- **Status:** Unsuccessful
- **Description:** Cycle axis 0→1→2→0 with direction changes based on tag lo_nib and class
- **Process:** E0 tag = same axis, lo=F+hi=0 = reverse direction, default = advance. Ported from original JS parser.
- **Findings:** Hexhole: 1/12. Assigns G3=1200 to Z (wrong), G7=350 to X (wrong). Much worse than closest-delta.
- **Conclusion:** State machine model is fundamentally wrong for new-format files.

---

### TEST-003: Tag Class → Absolute Axis Mapping
- **Status:** Unsuccessful
- **Description:** Each tag class (C0, 80, 60, A0, 20) always assigns to a fixed axis (X=0, Y=1, Z=2, or group's own)
- **Process:** Brute-forced all 4^5 = 1024 combinations of class→axis mappings.
- **Findings:** Best result: 5/12 unique DXF matches. 80 configurations tied at this score.
- **Conclusion:** No single class→axis mapping works. Tags don't encode axis this way.

---

### TEST-004: Tag Class → Axis Offset from Group Axis
- **Status:** Unsuccessful
- **Description:** Each tag class applies a fixed offset (0, +1, +2 mod 3) to the group's axis
- **Process:** Brute-forced all 3^5 = 243 offset combinations.
- **Findings:** Best: 5/12 unique with {C0→same, 80→same, 60→prev, A0→same, 20→same}
- **Conclusion:** Axis offsets don't capture the encoding. Same ceiling as absolute mapping.

---

### TEST-005: 20-Class X↔Y Swap
- **Status:** Unsuccessful (promising but breaks cube)
- **Description:** Tag class 20 swaps X↔Y axis for its value assignment. Other classes use group's axis.
- **Process:** G8(Y=1300) with 20:77 → assign X=1300. G9(Y=1200) with 20:5E → assign X=1200. Tested with both base-state and running-state for unassigned axes.
- **Findings:** 
  - With base state: 5/12 Hexhole, cube stays 8/8
  - With running state: 5/12 Hexhole, cube drops to 6/8 (running Y=600 contaminates vertices)
  - Hex slot7 gets X=1300 ✓ but slot5 gets wrong Y
- **Conclusion:** X↔Y swap for 20 class is plausible for SOME assignments but doesn't solve the full problem and risks regressions.

---

### TEST-006: lo_nib Bit Pattern for State/Z Selection  
- **Status:** Unsuccessful
- **Description:** lo_nib encodes both Z-variant selection AND base/running state selection via specific bits
- **Process:** Tested all combinations of which bit = z_select vs state_select (4×4=16 combos), with and without 20-class axis swap, with and without 60-class axis swap.
- **Findings:** No combination achieved >5/12 unique DXF matches for Hexhole.
- **Conclusion:** lo_nib bit encoding for state selection doesn't work, or the model is wrong.

---

### TEST-007: E0 Tag as Axis Encoder
- **Status:** Unsuccessful — E0 does NOT encode axis
- **Description:** E0 tags (always hi_nib=0) may encode the axis for the group they follow.
- **Process:** Analyzed 172 E0 tags across all 13 test files. Built correlation tables: E0 lo_nib vs current axis, next axis, previous axis. Checked transitions.
- **Findings:**
  - E0 hi_nib is 0 in 93% of cases (159/172). Non-zero only in mis-parsed face data.
  - E0:00 (40% of all E0s) appears equally on X(16), Y(11), Z(42). No axis correlation.
  - E0:07 = "vertex completion" marker — co-occurs with C0 vertex assignment tags
  - E0:03 (always paired with 20:03) = COORD SECTION TERMINATOR
  - E0:05/E0:06 on G3 (second Y value) is a Y-continuation signal, but not general axis encoding
  - No lo_nib value maps cleanly to a single axis
- **Conclusion:** E0 tags are structural/state markers, NOT axis encoders. E0:00=reset, E0:07=flush, E0:03=terminator.

---

### TEST-008: EdgeBreaker-Coupled Vertex Model
- **Status:** Potential — KEY FINDING
- **Description:** Instead of building vertices from coord stream independently, tie vertex creation to EdgeBreaker C operations. Each C operation's new vertex is a DELTA from a specific boundary vertex.
- **Process:** Analyzed DXF Hexhole face topology. For each new vertex introduced by a face (C operation), computed delta from all shared boundary vertices. Checked if deltas are single-axis.
- **Findings:**
  - 9 out of 12 DXF vertices CAN be produced from a single-axis change to a boundary vertex:
    - V3=V2+Y(-100), V5=V4+Y(+300), V6=V3+X(+100), V7=V4+X(+100)
    - V8=V5+X(+100), V9=V2+X(+100), V10=V0+X(+300), V11=V1+X(+300)
  - Faces 4-7 ALL use X+100 from an X=1100 boundary vertex to create X=1200 vertices
  - V2 and V4 require multi-axis changes (initial triangle adjacents)
  - The coord stream HAS all needed values but NOT in DXF vertex order
  - Only 8 coord groups after base (G3-G10) but need 9 C operations (12 verts - 3 initial)
  - Current EdgeBreaker decoder produces 22 faces instead of 12 — face decoder is ALSO broken
- **Conclusion:** The vertex model IS EdgeBreaker-coupled. Each C operation consumes a coord value and applies it as a single-axis delta from the gate's boundary vertex (L or R). The AXIS of application comes from the coord group's axis assignment OR from the tag. BUT: the face decoder must be fixed FIRST — wrong face topology produces wrong vertex ordering. Fix face decoder → fix vertex builder. **This is likely the correct path forward.**

---

### TEST-009: Face Section Boundary and Sub-Sections
- **Status:** Potential — MAJOR FINDING  
- **Description:** The face section start is detected wrong (using LAST "20 00" before SHADED). The coord parser is consuming face section bytes as fake coordinates.
- **Process:** Searched for ALL "20 00" markers in the data section. Hex-dumped and parsed each candidate. Compared Hexhole vs Cube face section structure.
- **Findings:**
  - Hexhole has THREE "20 00" markers in the face region: 0x213F, 0x2155, 0x216B
  - Current parser uses 0x216B (the last one) — this gives only 6+1 ops (not enough for 12 faces)
  - Starting from 0x213F gives 9+1 ops and vertex refs [7, 10, 9, 11]
  - The three sub-sections form a pattern:
    - 0x213F: `40:17, 40:13, data(7), ..., 40:47, data(10)` 
    - 0x2155: `40:17, 40:13, data(9), ..., 40:47, data(11)`
    - 0x216B: `40:13, 40:2B, 40:17, 40:13, 40:2B, 40:5F, 40:1B[fin]`
  - Coord groups G16-G30 (val=2.0-3.38 with 40:xx tags) are FACE DATA being misparsed as coordinates!
  - "separator_line" string at 0x2193 marks the true end of face data (not SHADED at 0x21E8)
  - The face section needs ALL three sub-sections parsed together = ~12 topology ops total
  - Cube face section (working) has 13 ops with 0 finalizers — very different structure
- **Conclusion:** The face section boundary must be moved EARLIER (use FIRST "20 00" after coord data ends, not LAST). This alone may add the missing topology ops needed for the correct 12-face decode. The face section also ends at "separator_line", not SHADED. **FIXING THE FACE BOUNDARY IS A PREREQUISITE FOR CORRECT VERTEX ORDERING.**

---

### TEST-013: Face Section "00" Byte as Skip/Null
- **Status:** Potential — BREAKTHROUGH
- **Description:** In the face section, byte 0x00 before bytes >= 0x08 (non-vertex-index) should be treated as a skip/null, not a count byte. This reveals hidden topology ops.
- **Process:** Re-parsed Hexhole face section from 0x213F treating "00" as skip when next byte is not a valid vertex index (1-12).
- **Findings:**
  - Current parse: "00 40" → DATA val=64 (wrong, hides "40:3F" TAG)
  - New parse: "00" skip → "40 3F" TAG 40:3F (topology op!)
  - With this fix, Hexhole face section has 14 non-finalizer + 1 finalizer = 15 ops
  - The 3 sub-sections reveal a clear pattern:
    - Sub1: 40:17, 40:13, data(7), 40:3F, 40:47, data(10)
    - Sub2: 40:17, 40:13, data(9), 40:3F, 40:47, data(11) 
    - Sub3: 40:13, 40:2B, 40:17, 40:13, 40:2B, 40:5F, 40:1B
  - Vertex refs: [7, 10, 9, 11] (1-based vertex indices)
  - 14 ops is enough for 12 faces (need 11 after initial triangle)
- **Conclusion:** The "00 skip" fix recovers hidden topology ops. Combined with the face boundary fix (TEST-009), this gives enough ops for correct face decode. Implementation needed.

---

### TEST-010: Per-Axis Prev Tracking (3 separate prev values)
- **Status:** Unsuccessful — single-prev is correct
- **Description:** Test whether DELTA encoding uses per-axis prev values instead of global single-prev.
- **Process:** Re-decoded Hexhole and Cube coords with per-axis prev. Compared both methods against DXF expected values.
- **Findings:**
  - Hexhole: 3 coords differ, both methods score 11/31 — NO improvement
  - Cube: 4 coords differ, single-prev is BETTER (6/11 vs 5/11)
  - Critical: Cube G5 (X=300) uses DELTA byte 0x72. Single-prev from Z=950 gives correct 300.0. Per-axis prev from X=100 gives wrong 288.0.
  - Differing coords are all small values from face-section data leak — not real coordinates
- **Conclusion:** Single-global-prev is confirmed correct. Each DELTA uses the immediately preceding coordinate regardless of axis.
- **Description:** Instead of a single `prev` value for DELTA encoding, maintain separate prev values per axis. Each coord's DELTA would be relative to the last value on the SAME axis, not the last coord overall.
- **Process:** TBD
- **Findings:** TBD
- **Conclusion:** TBD

---

### TEST-011: Vertex Table from DXF Face Topology Matching
- **Status:** Not Started
- **Description:** Use the EdgeBreaker face decoder's output topology to infer vertex coordinates. If OOT face[i] = DXF face[i], then OOT vertex indices map to DXF vertex coordinates. Work backwards from this to discover the correct coord→vertex mapping.
- **Process:** TBD
- **Findings:** TBD
- **Conclusion:** TBD

---

### TEST-016: Reverse-Engineering the Working Commit (868ec49)
- **Status:** Successful — CRITICAL DISCOVERY
- **Description:** Analyzed exactly how commit 868ec49 ("THE CUBE IS SOLVED") built vertices and mapped them to face indices. This is the only code that ever had the cube displaying correctly.
- **Process:** Extracted the complete vertex builder + face decoder from that commit and traced every step for the cube.
- **Findings:**
  - **Vertex ordering: PRIMARIES FIRST, then C0 SLOTS APPENDED.**
    - Primaries = running state snapshots from each coord group (V0 at G2, then one per subsequent group)
    - For groups where first non-C0 tag has lo=F AND 2+ Z variants: create TWO primaries (one per Z value)
    - C0 slot vertices appended in slot NUMBER order (slot1, slot2, slot4, slot5)
  - **Face decoder uses a VERTEX QUEUE for C operations:**
    - Face section DATA values (1-based vertex refs like [3,6,7,5]) point to SPECIFIC vertices in the primaries+slots list
    - These refs are split: pre-topology refs and post-topology refs (reversed)
    - "Implicit" vertices (not in initial tri, not in DATA refs, not coordinate-duplicates) fill remaining slots
    - Queue order: implicit[0], pre-topo explicits, implicit[1], post-topo explicits(rev), remaining implicits
    - Each C operation consumes the NEXT vertex from this queue via `nextCVertex()`
  - **For the cube, this produces the exact correct mapping:**
    - Vertex list: V0-V8 (primaries + slots, 9 entries, 8 unique)
    - Initial tri: (V0, V1, V2) = (100,500,900), (100,500,950), (100,600,900)
    - C-op queue: [V8, V7, V4, V5, V3] = [(300,500,950), (300,500,900), (300,600,950), (300,600,900), (100,600,950)]
    - All 8 DXF vertices are covered with correct face connectivity
  - **The face section DATA values are the KEY to the vertex-face mapping.** They reference specific vertex indices that the face decoder assigns to specific C operations. Without these refs, the mapping is impossible.
- **Conclusion:** The vertex queue system IS the correct model. It uses face section DATA values as vertex references for C operations, with implicit vertices filling gaps. This must be implemented in both Python and JS.

---

### TEST-017: lo=F Creates Second Vertex by Reverting Previous Axis to Base
- **Status:** Successful — PLANE SOLVED
- **Description:** When a coord group's first non-C0 tag has lo_nib=0xF, create a SECOND primary vertex where the PREVIOUS group's axis is reverted to its base value.
- **Process:** Analyzed plane's missing vertex (300,500,900). G4 (X=300) has A0:0F (lo=F). Previous group G3 had axis=Y. Reverting Y to base (500) gives (300,500,900).
- **Findings:**
  - For the plane (1 Z value): G4 lo=F, prev axis=Y, base_Y=500 → second vertex (300,500,900) ✓
  - For the cube (2 Z values): same rule falls back to both-Z-variants when prev-axis-revert gives duplicate
  - This is a STRUCTURAL RULE of the format, not a hack
  - The rule generalizes: lo=F means "this group defines TWO vertices — one running, one with previous axis at base"
- **Conclusion:** Plane now 4/4 unique vertices + 2/2 faces. Cube unchanged at 8/8. No regressions.

---

### TEST-018: Expanded Slot Assigner Classes (40/80/60/A0/20)
- **Status:** Partial — helps SPHERE face count, mixed vertex results
- **Description:** Tag classes 40, 80, 60, A0, 20 (not just C0) create slot assignments when hi_nib > 0.
- **Process:** Added all classes to extract_c0_assignments and build_vertex_table slot collection.
- **Findings:**
  - SPHERE face count restored to 96/96 ✓
  - Cube stays at 8/8 ✓ (C0 slots dominate)
  - Hexhole: 3/12 (slight improvement from 2/12)
  - The 40:A7 tag on the plane's G4 is in the FACE section (after 20:00 marker), NOT in the coord section
  - 80:15 on G0 creates a slot1 assignment from the base X value (mostly harmless duplicate)
- **Conclusion:** Keep expanded classes — they don't hurt solved files and help SPHERE. The axis overlap remains unsolved.

---

### TEST-014: EdgeBreaker-Coupled Vertex Builder — Axis Selection Variants
- **Status:** In Progress
- **Description:** The coupled vertex builder creates vertices during C operations by taking boundary vertex L's coords and replacing one axis with the next coord value. Testing which axis selection heuristic works best.
- **Process:** Tested 4 variants on all files:
  - A) L-only, min-delta (replace axis closest to coord value): Cube 8/8 ✓, Hexhole 5/12, SPHERE 4/50
  - B) L+R, min-delta (try both boundary verts, pick smallest delta): Cube 8/8, Hexhole 6/12 (+1), SPHERE 2/50 (-2)
  - C) L+R, all-axes, min-delta (brute 6 combos): Cube 8/8, Hexhole 6/12, SPHERE 2/50 (same as B)
  - D) L+R, all-axes, max-delta (replace axis with LARGEST delta): Cube 3/8 ✗, everything worse
- **Findings:**
  - Min-delta (closest to ref) is correct for non-overlapping ranges (cube 8/8)
  - Neither min nor max delta solves overlapping X/Y ranges (SPHERE/Hexhole)
  - Using R as reference sometimes helps (Hexhole +1) but hurts elsewhere
  - The axis information MUST come from somewhere other than value proximity
- **Conclusion:** Value-proximity heuristics hit a ceiling. The axis is likely encoded in the topology tags (byte2 hi/lo) or in the E0 state markers that precede each operation. Next: test parallelogram prediction and tag-encoded axis.

---

### TEST-012: Multi-File Cross-Reference
- **Status:** Successful — KEY STRUCTURAL FINDINGS
- **Description:** Compare tag patterns across working (disjoint axes) vs failing (overlapping axes) files.
- **Process:** Analyzed tag class distribution by axis across Cube, Triangle, Hexhole, SPHERE. Compared base group tags, primary tags, sequences, and separators.
- **Findings:**
  - **Class 60 on G1 is UNIVERSAL Y indicator** — in every file, G1 (Y base) has class 60 as primary tag
  - **E0:05/E0:06 on G3** = reliable Y-continuation marker (second Y value)
  - **"E0:00 → C0:2F" pattern is Z-exclusive** in correctly-parsed data
  - Old format G0=80:15(X), G1=60:08(Y), G2=80:07(Z) — consistent across Triangle/Cube
  - New format G0=20:00(X), G1=60:xx(Y), G2=E0:00(Z) — consistent across Hexhole/SPHERE
  - **The SPHERE has 144 "coord groups" when it should have ~50** — confirms face data leak is the ROOT CAUSE
  - Class 40 tags flood Z groups in SPHERE (89 occurrences) — these are face topology ops being misparsed as coords
  - "40:2F → 60:17 → C0:2F" sequence is Z-exclusive in SPHERE
  - No tag class is axis-exclusive in working files
- **Conclusion:** The fundamental problem is NOT tag-based axis assignment — it is that the coord/face boundary is WRONG for new-format files. Fixing boundary detection would eliminate most axis misassignments. The axis overlap issue (X=Y range) is secondary to the boundary problem.

---

### TEST-019: Old-Format Boundary Heuristic — "20 00 + DATA count"
- **Status:** Successful — L-Shape unblocked
- **Description:** The old-format face boundary detection picked the first "20 00" after coord_start+20. L-Shape has no attrSuffix and a "20 00" tag inside its coord data at offset +22, truncating the coord section to 22 bytes (2 verts).
- **Process:** Prefer "20 00" where the next byte is a DATA count (≤0x06) — that's the face-section vertex-ref list signature. Fall back to bare "20 00" when no such candidate exists (triangle, prism).
- **Findings:**
  - L-Shape: 2 verts/0 faces → 8 verts/6 faces (coord values still need work)
  - Cube/Fan/Linear: boundary unchanged (already picked a matching candidate)
  - Triangle/Prism/Plane/Hexhole/SPHERE/Stepped/NonRound: unchanged
- **Conclusion:** Boundary fixed. Coord decode for L-Shape still requires separate work (Y/Z DELTA semantics differ).

---

### TEST-020: Plane Initial Triangle — Leading 40:xx Header
- **Status:** Successful — Plane F0 matches DXF
- **Description:** Plane's face section starts with `20 00 40 a7 [3] 20 07 [4] 20 03 e0 03`. The 40:a7 is a leading header indicating the first init vertex is implicit V1 (raw_idx 0). The previous code broke on the 40 tag and gave init=[0,1,2] (default), producing the wrong diagonal.
- **Process:** Recognize leading 40:xx after 20:00 as "implicit V1 first vertex". Continue collecting DATA until E0:03 terminator. Cube's init is fully explicit (3 DATA values) and remains [0,1,3].
- **Findings:**
  - Plane F0 = (V0, V2, V3) ✓ matches DXF F0 exactly
  - Plane F1 still uses different diagonal until TEST-021
- **Conclusion:** Initial triangle now correctly identified.

---

### TEST-021: Plane Initial Gate Position — leading_40 Sets gate=0
- **Status:** Successful — Plane SOLVED
- **Description:** With init_tri=[0,2,3] and default gate=1, the C operation produced face (V2, V3, V1) which uses a different diagonal than the init triangle, creating a butterfly shape instead of a flat quad.
- **Process:** When leading_40_header is detected, set initial dec.g = 0 (gate at edge V0-V_data[0]) instead of default 1. This makes the next C op produce a triangle that shares the V0-V_data[0] diagonal with the init triangle.
- **Findings:**
  - Plane F0 = (V0, V2, V3) ✓ DXF F0
  - Plane F1 = (V0, V2, V1) — same triangle as DXF F1, both faces share BL-TR diagonal
  - Visually confirmed flat rectangle in viewer
- **Conclusion:** Plane SOLVED. Cube unaffected (no leading_40_header).

---

### TEST-022: Shared-Base Encoding — Linear Strip 7/7 Vertex Match
- **Status:** Successful — Linear Strip vertices SOLVED
- **Description:** Linear Strip has only 4 coord values (1000, 1100, 1200, 1300) but 7 DXF vertices (X∈{1000,1100,1200,1300}, Y∈{1000,1100}, Z=1000). The standard parser's base = [G0.value, G1.value, G2.value] = [1000, 1100, 1200] is wrong because G1 and G2 are NOT Y and Z — they are additional X-deltas.
- **Process:** Detect "shared-base" encoding: G0 leads with class 60:xx AND first 4 group values within tight ratio (max/min < 1.5). When detected:
  1. base = [G0.value, G0.value, G0.value]
  2. G1.value becomes Y_alt for slot vertices
  3. G2+ are X-deltas
  4. For each X-delta group: create (X, Y_base, Z) and if slot hi=1 present (X, Y_alt, Z)
- **Findings:**
  - Linear Strip: 0/7 verts → **7/7 verts** ✓ (faces 6 vs DXF 5 — separate face issue)
  - L-Shape: detection correctly skipped (values 50.5/121/1500 don't pass tight-range check)
  - 4-Sides Prism: detection correctly skipped (values 100/1000/5000 span too wide)
  - All other files: unchanged
- **Conclusion:** Linear Strip vertex decode SOLVED. The G0=60:xx + tight-range signature is a reliable detector for this encoding variant. Face count still off by one (5 vs 6) — requires face-decoder investigation.

---

### TEST-023: Linear Strip Face Decoder — Shared-Base C-Only Strip
- **Status:** Successful — Linear Strip face decode SOLVED
- **Description:** After TEST-022 fixed vertices, linear strip produced 6 faces vs DXF's 5 because the EdgeBreaker decoder did R/L fallbacks when sep=None instead of continuing the strip with C ops.
- **Process:**
  1. For shared-base files, queue all non-init vertices in raw-index order (V3, V4, V5, V6) instead of the implicit/pre/post merge order.
  2. In the decoder loop, every non-finalizer op consumes the next queue vertex as a C op until the queue is empty. After exhaustion, skip remaining ops (no R/L fallback) — the strip is complete.
- **Findings:**
  - Linear: F0={0,1,2}, F1={1,2,3}, F2={2,3,4}, F3={3,4,5}, F4={4,5,6} — all 5 face sets match DXF.
  - 7/7 verts, 5/5 faces in both Python and JS.
  - No regressions on other files.
- **Conclusion:** Linear Strip SOLVED. The encoding is "strip-style C ops" with finalizers as gate adjustments. The same model may apply to other shared-base files.

---

### TEST-024: Drop Phantom Slot Vertices via Coord-Dedupe + Remap
- **Status:** Successful — Triangle/Plane/Cube vertex counts now match DXF exactly
- **Description:** Slot tags from class 80:15 on G0 produce a "phantom" vertex with the same coords as V0 (or another primary). Triangle: 4v vs DXF 3v. Plane: 5v vs DXF 4v. Cube: 9v vs DXF 8v. The phantom is unreferenced by any face but inflates the vertex count.
- **Process:** After face decode, walk vertices and find coord-duplicates of an earlier vertex. Build a remap: dup_idx → orig_idx. Apply the remap to all face indices (collapsing references to the original). Drop any face that becomes degenerate (two indices equal). Prune unreferenced vertices and renumber the remaining ones.
- **Findings (Python):**
  - Triangle: 4v/1f → 3v/1f ✓ (matches DXF 3v/1f)
  - Plane: 5v/2f → 4v/2f ✓
  - Cube: 9v/12f → 8v/12f ✓
  - Linear unchanged (7v/5f, no phantom)
  - "Broken" files (Hexhole, SPHERE, etc.) lose their inflated double-counts; raw match counts go down but unique DXF coverage is unchanged.
- **JS divergence:** JS produces a slightly different vertex list for cube (7v after dedupe vs 8v in Python). The JS vertex builder has a separate bug where one cube vertex isn't generated. Triangle, Plane, Linear all match Python exactly in JS.
- **Conclusion:** Python parser is now perfectly clean for all 4 solved files. JS cube divergence is a separate JS-only issue tracked for later.

---

### TEST-025: Leading 40 lo_nib Controls F0 Winding — Triangle Solved
- **Status:** Successful — Triangle vertex labels now match DXF exactly
- **Description:** After TEST-024's face-traversal renumbering, plane and linear matched DXF labels but triangle still had V1↔V2 swapped. Triangle's leading header is `40:8f` (lo=F) while plane's is `40:a7` (lo=7) — the lo_nib differs.
- **Process:** When leading 40:xx has lo_nib = 0xF, reverse the DATA values before constructing init_verts. lo_nib = 0x7 keeps the encoded order. Triangle's DATA [2,3] reversed → [3,2] → init = [1,3,2] → init_tri = [V0, V2, V1] = (BL, TR, BR) matching DXF F0. Plane's lo=7 stays unchanged.
- **Findings:**
  - Triangle: 3/3 vertex labels match DXF, 1/1 face exact match — PERFECT
  - Plane: still 4/4 verts and matching faces — unchanged
  - Linear: still perfect
  - Cube has no leading 40 header, untouched
- **Conclusion:** Triangle SOLVED. Pattern: lo=F on leading 40 = reverse F0 winding. Three of four "simple" files now match DXF perfectly.

---

### TEST-026: Fan/NonRound Full-Precision Run — 3/6 Fan Vertex Match
- **Status:** Successful — Fan unblocked from 0/6 to 3/6 unique vertex matches
- **Description:** Fan and NonRound start with non-standard bytes (0x12 and 0x1f respectively) that aren't count bytes, separators, or standard tag classes. After the marker, consecutive 8-byte IEEE 754 BE doubles encode coords directly without DELTA compression.
- **Process:** When the first byte of the coord region is > 0x07, not a separator, and not a standard tag class (0x20/0x40/0x60/0x80/0xA0/0xC0/0xE0), enter "FULL-run mode": skip the marker byte and read 8-byte IEEE doubles back-to-back until the next byte isn't a FULL indicator (0x40/0x41/0xC0/0xC1). After the run, resume standard parsing.
- **Findings:**
  - Fan: 0/6 → 3/6 unique vertex matches. V0=(254.29, 482.66, 900.05) ↔ DXF V3, V1=(300.02, 600.05, 900.05) ↔ DXF V1, V3=(300.02, 467.40, 900.05) ↔ DXF V4. Three more verts (V0, V2, V5 in DXF) still need decoding from the post-FULL DELTA stream.
  - NonRound: parses 4 FULL doubles correctly (matching DXF V0 + V1.X), but vertex builder produces wrong combinations from the subsequent groups. Coord-decode partially fixed; vertex assembly still needs work.
  - All other files: unchanged (the rule only fires when first byte fits the pattern).
- **Conclusion:** Mystery C partially solved. Marker byte semantics (why 0x12 vs 0x1f) still unclear but doesn't matter for parsing — the consecutive-FULL-until-non-indicator rule handles both. Remaining Fan vertices are encoded via DELTAs in the bytes after the FULL run, which need additional decoding work.

---

### TEST-028: Prism / 4-Prism DELTA Trailing-Byte Investigation
- **Status:** Investigated — no fix landed; current parser unchanged
- **Goal:** Understand why prism Y=503.75 should be 500, and 4-prism apex Y=72 should be 75.
- **Findings (Prism, OLD format vlen=8):**
  - Coord region bytes around Y_apex: `01 b5 7c 80 1f c0 17 00 7f e0 06`
  - DELTA `01 b5 7c` correctly gives 5500.0 (Z, prev unused since 2 bytes specified)
  - DELTA `00 7f` (1 byte) with running prev = 5500=`40 b5 7c 00..` keeps trailing byte 2=0x7c → result `40 7f 7c` = **503.75**
  - For 500 = `40 7f 40 00..` we'd need byte 2=0x40 — which equals base[Y]=1000=`40 8f 40 00..` byte 2.
  - So **rule that works for prism**: TAG `C0:17` immediately preceding 1-byte DELTA → use base[axis_Y] as prev (gives byte 2=0x40 trailing).
  - **But this breaks cube**: cube has same `C0:17` pattern before `00 72` for X=300 and currently gets correct 300 from running prev=600=`40 82 c0..` (byte 2=0xc0). If we used base[X]=100=`40 59 00..` instead, byte 2=0x00 → result `40 72 00` = 288 ✗.
- **Findings (4-Prism, NEW format vlen=15):**
  - Coord region bytes around apex: `01 91 30 20 55 20 57 00 52 a0 7f 01 b5 7c`
  - DELTA `00 52` gives 72.0 with new-format zero-trailing. Old-format keep-trailing from prev=1100=`40 91 30..` would give `40 52 30..` = 72.75. Neither equals 75.
  - The IEEE bytes `40 52 c0` (= 75.0) **do not appear anywhere in the 4-prism file**. The apex Y=75 cannot be derived from a single DELTA on running prev.
  - Note: 75 = (50 + 100)/2 = mean of base Y values. Possibly Vulcan computes the apex Y as the centroid of base corners rather than encoding it explicitly. Cannot be confirmed from bytes alone.
- **Axis-overlap secondary issue:** prism's `503.75` (or `500`) gets assigned to axis X by the closest-delta heuristic since |503.75 − 150| < |503.75 − 1500|. Even if we fixed the value, axis assignment would still be wrong without a tag-driven axis hint.
- **Conclusion:** The DELTA byte rule that fixes prism breaks cube — they have identical tag-pattern context (`C0:17` before 1-byte DELTA) but require different prev. No purely byte-local rule found that fixes prism without regressing cube. 4-Prism apex Y=75 is not stored explicitly and may be a derived/centroid value.

---

### TEST-029: Prism `80:1f` Tag Disambiguates "Use base[Y]"
- **Status:** Successful — Prism 2/4 → 3/4 vertex match, no regression on Triangle/Plane/Linear/Cube
- **Description:** Survey of `80:1f` (cls=80, hi_nib=1, lo_nib=F) shows it appears ONLY in prism's coord region (and one occurrence in fan, but fan doesn't fire because its FULLs come from FULL-run mode and don't populate `full_bytes_history`). Cube has `80:0f` (hi_nib=0) which is different. So `80:1f` is the missing context bit that distinguishes prism's `00 7f` DELTA (wants base[Y] as prev) from cube's `00 72` DELTA (wants running prev).
- **Process:**
  1. In `parse_coord_elements`: track `full_bytes_history` (8-byte snapshots of first 3 FULL count-byte values = base X/Y/Z). Set flag `use_base_y_for_next_delta` when 80:1f tag is parsed; on the very next 1-byte DELTA in old format, use `full_bytes_history[1]` (= base Y bytes) as prev for keep-trailing decode. Stamp `forced_axis=1` on that COORD element.
  2. Propagate `forced_axis` through `CoordElement → CoordGroup`. In `assign_axes`, honor `forced_axis ≥ 0` instead of running closest-delta.
  3. In `build_vertex_table`, when a group has `forced_axis ≥ 0`, emit TWO primaries (mirroring the lo=F + Z-prev path): `[running_X, running_Y, base_Z]` and `[running_X, running_Y, alt_Z]`. This places `(150, 500, 5000)` (= DXF prism V2) and `(150, 500, 6000)` (extra) into the vertex list.
- **Findings:**
  - Prism: `coord_values[7]` 503.75 → 500.0 ✓; axis assigned Y not X ✓; vertex `(150, 500, 5000)` now present and matches DXF V2.
  - Triangle/Plane/Linear/Cube: unchanged — none of those files contain `80:1f`.
  - 4-Prism: unchanged — the `00 52` DELTA doesn't have `80:1f` preceding it (the apex Y=75 issue lies elsewhere).
  - Fan: unchanged — `80:1f` appears post-FULL-run but `full_bytes_history` is empty there (FULL-run path doesn't populate it).
- **Remaining:** Prism's DXF V1=`(150, 1000, 5500)` is still missing. We have `(150, 1000, 5000)` (Z wrong) but no `(150, 1000, 5500)` primary. This is the next focus.
- **Conclusion:** The `80:1f` tag is the discriminator that lets us locally reroute prism's troublesome DELTA without touching cube. Prism vertex match jumps 2/4 → 3/4. JS parser synced.
