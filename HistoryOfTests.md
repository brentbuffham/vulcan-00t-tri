# History of Tests — Vulcan .00t Parser Reverse Engineering

**Started:** ~January 2026  
**Last Updated:** 2026-04-03  
**Status:** 3 formats fully solved (Triangle, Plane, Cube), 4 partially working, 5 broken

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
