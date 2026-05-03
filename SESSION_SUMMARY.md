# Session Summary — Pick-Up Notes

**Last working state:** commit `c9b0297` (and JS sync). Push to origin/main pending.

## TL;DR

Triangle, Plane, Linear Strip are **PERFECT** (vertices, labels, and faces all match DXF). Cube has all 8 unique vertex coordinates correct and **7/12 face triangles** matching DXF face sets — the historical best. Five cube triangles still cut through the volume due to undecoded C/R/L decision rules.

## Quick Re-Orient

Run these to get oriented next time:

```bash
# 1. Read the TODO and history
cat TODO.md
cat HistoryOfTests.md | tail -100

# 2. Start the viewer dev server (background)
python3 -m http.server 8765 &

# 3. Open viewer in Chrome
open http://localhost:8765/js/oot-compare.html

# 4. Run regression check
python3 python/oot_parser_v2.py 2>&1 | grep -E "OOT:|Vertex match"
```

The viewer has a **dropdown** at top to load any test case in one click. After every parser change, load the affected file and screenshot to verify visually.

## Current Scores Snapshot (2026-05-03)

| File | OOT | Unique | Labels | Face_sets | Status |
|---|---|---|---|---|---|
| Triangle | 3v/1f | 3/3 | 3/3 ✓ | 1/1 ✓ | **SOLVED** |
| Plane | 4v/2f | 4/4 | 4/4 ✓ | 2/2 ✓ | **SOLVED** |
| Linear Strip | 7v/5f | 7/7 | 7/7 ✓ | 5/5 ✓ | **SOLVED** |
| Cube | 8v/12f | 8/8 ✓ | 4/8 | **7/12** | Faces best-ever, labels swapped |
| Fan | 5v/4f | 3/6 | 1/6 | 0/6 | FULL-run partial; coord post-run not decoded |
| Prism | 6v/3f | 2/4 | 1/4 | 0/2 | DELTA reference override unsolved |
| 4-Sides Prism | 10v/5f | 4/5 | 1/5 | 0/6 | Apex Y=72 should be 75 |
| Stepped Pyramid | 1v/0f | 0/20 | 0/20 | 0/18 | Tag-encoded coords (compact FULLs detected but builder needs rewrite) |
| L-Shape | 5v/6f | 0/12 | 0/12 | 0/20 | DELTA semantics differ |
| Hexhole | 10v/10f | 3/12 | 2/12 | 0/12 | Axis overlap |
| NonRound | 25v/10f | 0/16 | 0/16 | 0/14 | FULL-run partial |
| SPHERE | 51v/96f | 2/50 | 2/50 | 0/96 | Axis overlap |

## What This Session Achieved

1. **Linear Strip SOLVED** — shared-base encoding (G0=60:xx + tight value range): all axes start at G0.value, G1.value becomes Y_alt, slot tags create (X, Y_base, Z) and (X, Y_alt, Z) vertices. Strip-style face decoder (every op is a C until queue empty).

2. **Triangle SOLVED** — leading 40:xx header lo_nib controls F0 winding. lo=7 keeps DATA order (plane), lo=F reverses (triangle).

3. **Plane SOLVED** — leading 40:xx header signals "implicit V1 first vertex" + initial gate=0.

4. **Vertex-label face-traversal renumbering** — vertices are labeled in the order they first appear in faces, which matches DXF's labeling for Triangle/Plane/Linear.

5. **Phantom slot dedupe** — drop unreferenced coord-duplicate vertices (the 80:15-on-G0 phantom).

6. **Fan partial** — 0/6 → 3/6 unique vertex match by detecting non-standard byte-0 markers (0x12, 0x1f) and reading consecutive 8-byte IEEE doubles ("FULL run").

7. **Compact FULL** — tags `40:49`, `40:59`, `40:69`, `40:79` decode as IEEE values 50, 100, 200, 400 (and negatives via C0:XX) when treated as 2-byte FULL with implicit zero trailing. Helps Stepped Pyramid coord identification.

8. **Cube** — all 8 unique vertex coordinates correct; 7/12 face triangles match DXF face sets (historical best).

## The Cube Trade-off (KEY INSIGHT)

There's a **fundamental trade-off** between cube vertex labels and face triangulations:

| Configuration | Cube Labels | Cube Face_sets |
|---|---|---|
| OLD queue (current) | 4/8 wrong | **7/12** ✓ |
| NEW queue (refs sorted) | 8/8 ✓ | 4/12 |

The face decoder's C op picks `(L, R, v)` where `v` comes from the vertex queue. Different queue order → different vertex coords at C op → different triangle. Either correct labels OR more matching triangles, not both — they trade off because changing the queue changes which triangle each C op produces.

To get both we'd need to decode the byte/pattern that controls each C/R/L op choice (Mystery D below) — that pattern hasn't been cracked yet.

**Reverted to OLD queue** (current state) because the user prioritized visual cube quality over label match.

## Open Mysteries (in suggested attack order)

### Mystery A: Cube C/R/L Decision Rule (NEW — affects cube face fix)

The face decoder picks C, R, L, or E for each topology op. Currently uses separator-byte heuristics. The 5 wrong cube faces happen because some ops should be R when we pick L (or similar).

**Hypothesis to try**: `byte2.lo_nib` of `40:xx`/`C0:xx` tags controls the op type. Tested briefly with `lo=7→C, B→R, 3→L` — broke cube. Needs more careful analysis tied to gate position.

**How to investigate**: trace cube ops one-by-one with debug logging, compare expected DXF op sequence (5 C + 6 R/L) to what we produce.

### Mystery B: Tag-Encoded Coord Values (Stepped Pyramid)

DXF coords are clean integers (0, 100, 200, 300, 400, 500). OOT coord region has only ~5 actual COORD elements (all near-zero) and many tag bytes. **Compact FULL detection** (committed) identifies `40:59=100`, `40:69=200`, `40:79=400` correctly — but the vertex builder doesn't know how to USE these as deltas from an implicit-zero base.

**Hypothesis**: Stepped uses an implicit-zero base + per-group deltas encoding. Need a new vertex builder path for this family.

### Mystery C: DELTA Reference Override (Prism, 4-Prism, L-Shape)

Late-stream DELTAs decode to wrong values (e.g., prism DELTA `00 7f` produces 503.75 but DXF wants 500). Bytes math out exactly when `prev = base_Y (1000)` instead of running-prev (5500). Some tag pattern must signal "use base of axis Y as prev".

**How to investigate**: instrument every DELTA in prism/4-prism with `(prev_value, stored_bytes, computed, expected)`. Find the preceding tag pattern for wrong DELTAs.

### Mystery D: Fan Post-Run DELTAs

After the FULL-run gives us 3-4 anchor vertices, the remaining Fan vertices are encoded via DELTAs in bytes after the run. We get `01 72 c0` correctly decoding to 300 (DXF V1.X) but the broader pattern of FULL/DELTA mix isn't solved.

### Mystery E: Axis Overlap (Hexhole, SPHERE)

When X, Y, Z share value range (1000–1300), closest-delta heuristic fails. **8 prior approaches tested in HistoryOfTests TEST-001..008**, none solve it. The format must encode axis info in tag patterns we haven't found.

## Files Reference

- `python/oot_parser_v2.py` — main parser (Python, authoritative)
- `js/oot-compare.html` — viewer + JS parser (mirror of Python)
- `HistoryOfTests.md` — 26+ documented test approaches
- `exampleFiles/` — 13 test `.00t`+`.dxf` pairs
- `TODO.md` — research plan with hypotheses
- `MEMORY.md` (in `~/.claude/projects/.../memory/`) — workflow notes

## Workflow Reminders

- **Always screenshot the viewer after parser changes** — numeric counts can hide topology issues. Use the dropdown to load test cases.
- **Python is authoritative**, JS mirrors. After Python change, sync to JS or note divergence.
- **Don't break solved files** — always run the regression check before committing.
- The viewer URL needs `?v=<timestamp>` cache-buster after JS edits.

## Known Bugs / Smaller TODOs

- JS Fan shows 1v/0f while Python shows 5v/4f — JS-only divergence, not chased
- Browser Chrome MCP connection sometimes flakes — use `switch_browser` to re-bind
- Chrome auto-blocks multi-file downloads from localhost — use combined-canvas-into-one-PNG approach for screenshots
