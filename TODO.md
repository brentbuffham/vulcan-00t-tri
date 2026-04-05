# TODO — Vulcan .00t Parser

**Read this FIRST before making any changes. Then check HistoryOfTests.md and recent git commits.**

## What's Working (DON'T TOUCH)

- **Triangle**: 3/3 verts, 1/1 faces ✅ SOLVED
- **Plane**: 4/4 verts, 2/2 faces ✅ SOLVED (lo=F prev-axis-revert)
- **Cube**: 8/8 verts, 12/12 faces ✅ SOLVED (vertex queue + primaries-first)
- Coordinate decompression (FULL/DELTA/IDELTA, IEEE 754 BE doubles)
- New-format: 0x07 as 8-byte coord, escape prefix stripping, signed integer delta
- Dynamic IDELTA threshold (3× max of first 3 FULL values)
- Separator-based EdgeBreaker face decoder (C/R/L/E from separator bytes)
- Vertex queue system (face DATA values → vertex refs for C operations)
- Primaries-first vertex builder (running state + lo=F double-create)
- C0 slot accumulator (appended in slot number order)
- Boundary: attrSuffix for old format, E0:03+separator_line for new format
- JS compare viewer with debug overlay, Z-color, faces toggle

## Current Scores (2026-04-05)

| File | Verts | Faces | Status | Problem |
|------|-------|-------|--------|---------|
| Triangle | 3/3 ✅ | 1 ✅ | SOLVED | — |
| Plane | 4/4 ✅ | 2 ✅ | SOLVED | — |
| Cube | 8/8 ✅ | 12 ✅ | SOLVED | — |
| Prism | 2/4 | 3 | Close | Z precision (5500/6000 instead of correct values) |
| 4-Sides Prism | 4/5 | 5/6 | Close | Missing 1 vertex |
| Linear Strip | 0/7 | 3 | Broken | Axis overlap (X,Y,Z all 1000-1300) |
| Fan | 0/6 | 0 | Broken | Zero-value coords → all (0,0,0) |
| Stepped Pyramid | 1/20 | 1/18 | Broken | Needs investigation |
| Hexhole | 3/12 | 10/12 | Broken | Axis overlap (X=Y range) |
| SPHERE | 2/50 | 96/96 ✅ | Partial | Face count perfect, axis overlap |
| L-Shape | 0/12 | 4/20 | Broken | Needs investigation |
| NonRound | 0/16 | 12/14 | Broken | High-precision byte collision |
| BigGrid | — | — | Untested | Multi-byte header counts |

## Priority TODO

### 1. Fan — zero-value coord decoding (NEW BUG)
- All vertices decode as (0,0,0)
- Fan coordinates are near zero → 0x00 bytes get interpreted as count bytes or escapes
- The FULL/DELTA detection fails for values near 0.0 (IEEE byte[0] = 0x00 or 0x3F)
- Fix: investigate how near-zero coordinates are encoded in the fan's hex data

### 2. Prism — Z value precision
- Shape is close but Z=6000 and Z=5500 instead of correct values
- Likely a DELTA decode error or wrong Z-select from lo_nib
- Should be a quick fix — check the coord group values and Z value collection

### 3. Axis overlap — the HARD problem (Linear, Hexhole, SPHERE)
- When X and Y share the same value range, closest-delta can't distinguish them
- 15+ approaches tested (see HistoryOfTests.md), none solve it
- The format MUST encode axis info somewhere — likely in a tag pattern we haven't decoded
- **Recommended approach**: create a minimal test file (4 verts, overlapping X/Y) in Vulcan to isolate the problem in the fewest possible bytes

### 4. Face-vertex index mapping
- Vertex queue system works for cube (proven)
- For other files, face indices reference wrong vertex positions
- Connected to the axis overlap problem — once vertex coords are right, face mapping follows

## Vertex Builder Model (Proven)

```
1. PRIMARIES FIRST (running state snapshots):
   - V0 at group 2 (base XYZ)
   - For groups with first non-C0 tag lo=F:
     - Primary 1: running state
     - Primary 2: running with PREVIOUS group's axis reverted to base
     - Fallback: if 2+ Z values, create both Z variants
   - Otherwise: one primary from running state

2. C0 SLOTS APPENDED (in slot number order):
   - All tag classes with hi_nib>0 create slot assignments (C0/40/80/60/A0/20)
   - Each slot accumulates axis values across groups
   - lo=7 → base_Z, lo=F → alt_Z

3. VERTEX QUEUE (for face decoder C operations):
   - Face section DATA values (1-based) → vertex references
   - Split into pre-topology and post-topology refs (post reversed)
   - Implicit vertices (not in initial tri, not in refs, not coord-dupes) fill gaps
   - Queue order: implicit[0], pre-topo, implicit[1], post-topo(rev), remaining implicits
   - Each C operation consumes next vertex from queue
```

## Files Reference

- `python/oot_parser_v2.py` — Main parser (Python, authoritative)
- `js/oot-compare.html` — Compare viewer with debug overlay
- `js/oot-parser.js` — Standalone JS module (behind Python, needs sync)
- `HistoryOfTests.md` — 16 documented test approaches with findings
- `exampleFiles/` — All test .00t + .dxf pairs
