# TODO — Vulcan .00t Parser

**Read this FIRST before making any changes. Then check HistoryOfTests.md and recent git commits.**

## What's Working (DON'T TOUCH)

- **Cube**: 8/8 vertices, 12/12 faces — FULLY SOLVED
- **Triangle**: 3/3 vertices — coordinates fully decoded
- **Plane**: 3/4+ vertices — mostly working
- File header / magic / page chain navigation
- Coordinate decompression (FULL/DELTA, IEEE 754 BE doubles)
- New-format: 0x07 as 8-byte coord, escape prefix stripping, signed integer delta (IDELTA)
- Separator-based EdgeBreaker face decoder (C/R/L/E from separators)
- EdgeBreaker-coupled vertex builder (vertices built during C operations)
- E0:03 terminator for new-format coord/face boundary
- separator_line as face section end marker

## Current Scores (2026-04-03)

| File | Verts | Faces | Status |
|------|-------|-------|--------|
| Triangle | 3/3 | 3 | ✅ Working |
| Plane | 5/4 | 4 | ✅ Mostly working |
| Cube | **8/8** | **12/12** | ✅ **PERFECT** |
| 4-Sides Prism | 3/5 | 5/6 | Partial |
| Stepped Pyramid | 13/20 | 13/18 | Partial |
| Hexhole | 6/12 | 10/12 | Partial — axis overlap |
| SPHERE | 4/50 (50 verts) | **96/96** | Face count PERFECT, vertex coords wrong |
| Linear Strip | 0/7 | 6 | Broken |
| Fan | 0/6 | 7 | Broken |
| Prism | 2/4 | 4 | Broken |
| L-Shape | 0/12 | 6 | Broken |
| NonRound | 0/16 | 12 | Broken (high-precision collision) |
| BigGrid | untested | untested | Multi-byte headers needed |

## THE BOTTLENECK: Vertex Coordinate Accuracy

The EdgeBreaker-coupled vertex builder produces **correct vertex COUNTS** (cube 8/8, sphere 50/50) but wrong **coordinates** for files with overlapping X/Y ranges.

### What's proven NOT to work (see HistoryOfTests.md):
- Tag class → axis mapping (1024 combos tested, TEST-003)
- Tag class → axis offset (243 combos, TEST-004)
- 20-class X↔Y swap (TEST-005)
- lo_nib bit patterns for axis/state (TEST-006)
- E0 tags as axis encoders (172 tags analyzed, TEST-007)
- Per-axis DELTA prev tracking (TEST-010)
- L-only vs L+R reference, min vs max delta (TEST-014)

### What's still worth investigating:
1. **Tag byte2 on face ops** — the 40:xx byte2 value might encode axis for the C operation. Untested.
2. **Face section DATA values** — vertex refs [7,10,9,11] in Hexhole may hint at vertex reuse patterns
3. **00-skip face parse** — reveals hidden 40:3F and 40:47 ops (TEST-013). Needs face decoder upgrade first.
4. **Parallelogram prediction** — L+R-O model for new vertex coordinates
5. **Multi-value C operations** — some C ops may consume 2+ coord values (cube face 3 needs 3-axis change)

### The pattern from cube analysis:
- Some C ops: new vertex = L + single axis change (value from coord stream)
- Some C ops: new vertex = R + single axis change
- Some C ops: need MULTIPLE axis changes from any reference
- The choice of L vs R vs multi-axis varies per operation

## Other TODO (lower priority)

### NonRound — high-precision byte collision
- Coordinates like 32307.853 have 7-8 significant IEEE 754 bytes
- Data bytes collide with tag byte values causing misparsing

### BigGrid — multi-byte header counts
- 10201 vertices / 20000 faces overflows single-byte header fields
- Vertex count at anchor+7 as uint16_BE = 0x27D9 = 10201

### JS parser port
- `js/oot-compare.html` has separator face decoder but NOT the coupled vertex builder
- Port AFTER vertex accuracy is solved in Python
