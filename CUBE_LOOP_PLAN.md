# CUBE Decoding Loop — Plan

> **Started 2026-05-08** after pivoting from SPHERE.

## Targets
`exampleFiles/cube1.00t` through `cube5.00t` — 5 rotated cube variants. All
share `n_verts=8 n_faces=12` (same topology, different orientations). User
is building DXFs separately; until those arrive, success is measured by:
- Parsed `n_verts == 8` and `n_faces == 12`
- Parsed vertex coords that form a valid 8-corner box (geometric self-check)
- Sub-section structure correctly handled (cubes 1-4 are multi-section, cube5 is single)

## Why cubes (vs continuing SPHERE)
1. **Same topology, different rotations** → byte-level invariants pop out by diff.
   Whatever bytes are SAME across cube1-5 are structural (op codes, gate shifts,
   separators). Whatever bytes DIFFER are coord-specific (rotated values).
2. **Existing solved cube uses a hardcoded `CUBE_SEQ`** (TEST-027) — the
   gate-shift/op-type byte rule is still unsolved. Cracking it on cube1-5 lifts
   that hardcode.
3. **SPHERE's coord-decode artifacts (TEST-045, TEST-046) won't be fixed by
   axis rules.** It needs a deeper DELTA/prev-tracking fix — likely informed by
   what we learn from new-format cubes.

## Universal structural finding (TEST-047 baseline)
All 6 cube files share an identical **27-byte pre-coord prefix** ending at
`e0 0b 14`. The byte AFTER `14` diverges per file:

| File | Byte | Sub-sections | Parser baseline |
|---|---|---|---|
| tri-crack-solid (orig) | 0x01 | 2 | **8v/12f** ✓ (via hardcoded CUBE_SEQ) |
| cube1 | 0x02 | 2 | 7v/10f |
| cube2 | 0x11 | 3 | 10v/8f |
| cube3 | 0x11 | 2 | 9v/12f |
| cube4 | 0x17 | 2 | 21v/12f |
| cube5 | 0x1f | **1** | 5v/6f |

The byte after `14` is a STRUCTURE-CONTROL byte — likely a count or section
header signal. Cracking what it means is hypothesis #1 below.

## Hypothesis queue

1. **Decode the post-`e0 0b 14 XX` byte.** Compare cube1's `02` (count 2 →
   3 stored bytes) vs cube5's `1f` (separator-pattern). Look at the 16 bytes
   that follow each and infer what `XX` controls (number of FULL coords,
   coord size, sub-section type, etc.).
2. **Crack cube5 first** (1 sub-section, simplest). Coord region begins
   `40 47 f0 46 7b b3 d8 1d 40 52 2a 17 ae 2d b3 70 ...` — sequential 8-byte
   IEEE FULLs. Get all 8 vertices decoding cleanly before touching anything else.
3. **Validate cube5's face section** independently — decode the 12 faces
   without reusing the `tri-crack-solid` hardcoded `CUBE_SEQ`.
4. **Diff cubes 1-4 face bytes** for gate-shift / op-type invariants. Same
   topology means same op count and same op sequence (modulo encoder choice).
   Whatever bytes are identical across all 4 multi-section cubes are the
   topology operators; whatever differ are likely separators or vertex refs.
5. **Identify the byte rule for op-type classification** (C/R/L/E/S). The
   current cube fast-path emits a hardcoded sequence; cube1-5 give us multiple
   independent encodings of the SAME 12-face cube topology. The byte pattern
   that's invariant across rotations IS the op-type encoding.
6. **Apply learnings back to other unsolved files** (Hexhole, L-Shape, 4-Prism)
   once the cube generalization works.

## Each iteration

1. Read this plan + iteration counter at `.cube_loop_iter` (create with "1" if missing).
2. Pick next pending hypothesis (skip those already in HistoryOfTests.md as TEST-NNN).
3. Implement in `python/oot_parser_v2.py`, gated behind a clear experimental flag.
4. Run regression: verify Triangle, Plane, Linear, Cube (orig), Prism still pass.
5. Score the cubes:
   - cube1-5 vert count == 8 AND face count == 12 → STRUCTURAL WIN
   - + valid 8-corner box geometry → GEOMETRIC WIN
   - + DXF match (when DXFs arrive) → FULL WIN
6. Document as TEST-NNN — WIN, FAIL with byte reason, or PARTIAL.
7. If improved AND no solved-file regression, commit. Else revert.
8. Increment counter.
9. Stop conditions:
   - All 5 cubes structurally correct (8v/12f) AND original cube still passes → CUBES STRUCTURAL CRACK, write summary
   - Iteration ≥ 12 without progress → stop, summarize
   - Solved-file regression that can't be cleanly reverted → stop, ask user

## Anti-patterns (same rules as SPHERE plan)

- **No `if filename == "cubeN.00t"` shortcuts.** Rules must be byte-derived.
- **No DXF lookup tables.** When DXFs arrive, they're for SCORING only, never decoding.
- **No `n_verts == 8 and n_faces == 12` signature shortcuts.** Both apply to
  the original solved cube too — they aren't byte-derived rules.
- **No "Cheaters Only" toggle for cubes.** If we can't decode it, we can't decode it.
