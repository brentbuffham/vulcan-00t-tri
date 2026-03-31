# TODO — Vulcan .00t Parser

**Read this FIRST before making any changes. Then check recent git commits.**

## What's Working (DON'T TOUCH)
- Triangle, Plane, Cube, Fan, Prism, Linear — coordinate extraction and face decode for old-format files
- File header / magic / page chain navigation
- Coordinate decompression (FULL/DELTA, IEEE 754 BE doubles)
- Separator detection, tag pair parsing
- Axis state machine (old format)
- C0 vertex slot assignments + Z-variant (lo=7/F)
- EdgeBreaker face decode (group-based C/R/L/E for open meshes)
- Cube: 6/8 vertices, 12 faces decoded

## What's New (2026-03-31)
- 5 new test files added: BigGrid, Hexhole, L-SHAPE, NonRound, SPHERE
- New-format file support: `Variant/C:...` path handling, `43 E0 0E` anchor header, SHADED-based section boundaries
- New-format coordinate rules: 00-escape (stored[0]==0x00 → strip and treat as FULL), zero-trailing (DELTA zeros trailing bytes)
- Closest-delta axis heuristic (works better than state machine for new-format files)
- 4-sides prism: all 8 coordinate values decode correctly

## Priority TODO

### 1. HEXHOLE / SPHERE — garbage 2nd coordinate value
- First coord decodes ~1000 correctly
- Second coord decodes as 115721 (wrong, should be ~1000-1300)
- Likely a FULL/DELTA detection issue for 4-byte stored values in new format
- Start by hex-dumping the first 5 coords of Hexhole, compare with DXF expected values

### 2. NonRound — high-precision byte collision
- Coordinates like 32307.853 have 7-8 significant IEEE 754 bytes
- Data bytes collide with tag byte values causing misparsing
- Known limitation, may need a different disambiguation rule
- Compare hex of NonRound coord section with DXF expected values

### 3. BigGrid — multi-byte header counts
- 10201 vertices / 20000 faces overflows single-byte header fields
- Vertex count at anchor+7 as uint16_BE = 0x27D9 = 10201
- Face count at anchor+15 as uint16_BE = 0x4E20 = 20000
- Need multi-byte count detection (check if count > 255 or header structure differs)

### 4. Vertex table building (all files)
- Current builder only creates V0 + C0-tagged slots
- Missing vertices that should come from EdgeBreaker C operations
- The C0 accumulation model works (tested on cube: 8/8) but needs integration
- Don't rewrite the existing builder — extend it

### 5. JS parser port
- `js/oot-parser.js` is far behind Python
- Needs: Variant/C: handling, anchor header, SHADED boundaries, new-format rules
- Port AFTER Python parser is stable for new files

## Test Files

| File | Format | Verts | Faces | Status |
|------|--------|-------|-------|--------|
| tri-crack-triangle | OLD | 3 | 1 | Working |
| tri-crack (plane) | OLD | 4 | 2 | Partial (3/4 verts) |
| tri-crack-linear | OLD | 7 | 5 | Broken (overlapping axis values) |
| tri-crack-solid (cube) | OLD | 8 | 12 | Working (6/8 verts) |
| tri-crack-fan | OLD | 6 | 6 | Broken (zero-value coords) |
| tri-crack-prism | OLD | 4 | 2 | Partial (2/4 verts) |
| tri-crack-4sides-prism | NEW | 5 | 6 | Coords OK, vertex building WIP |
| tri-crack-Stepped-pyramid | NEW | 20 | 18 | Partial coords |
| tri-crack-L-SHAPE | OLD | 12 | 20 | Broken |
| tri-crack-Hexhole | NEW | 12 | 12 | Garbage 2nd coord (115721) |
| tri-crack-NonRound | NEW | 16 | 14 | High-precision collision |
| tri-crack-SPHERE | NEW | 50 | 96 | Same as Hexhole |
| tri-crack-BigGrid | NEW | 10201 | 20000 | Multi-byte header needed |
