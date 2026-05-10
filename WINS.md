# Vulcan .00t — Real Structural Wins

Crystallized list of byte-derived rules and discoveries that are **proven**.
Each entry: the rule, byte signature, where it lives, the test that found it.

> **Anti-rule reminder:** None of these are file fingerprints. None gate on
> filename, header counts, or n_verts/n_faces. Every rule operates on byte
> roles or byte values that the encoder emits as part of its grammar.

## Structural Discoveries

### W1. Multi-section file structure
- **What:** Vulcan emits multiple `e0 03 14 20 00 40 17` sub-section markers per file (not just one face section).
- **Evidence:** SPHERE has 13 sub-section markers. cube1-5 each have ≥1.
- **Tests:** TEST-040 (discovery), TEST-041 (confirmed across 5 cube variants + SPHERE), TEST-042 (parser warns on detection).
- **Status:** Detected. Parsing not yet fully exploiting the structure (TEST-044 attempt to use it for SPHERE faces did not improve match).
- **Generalization:** Applies to all multi-section .00t files (sphere, biggrid, possibly hexhole/nonround).

### W2. SEP+E0:lo axis state machine
- **What:** Inter-coord transition signal carried by the LAST SEP and FIRST E0:lo of the previous coord group.
- **Rule:**
  - SEP `0x17` + first E0:lo == 7 → STAY on previous axis
  - SEP `0x17` + first E0:lo == A → STAY (TEST-058 refinement)
  - SEP `0x17` + first E0:lo < 7 → CYCLE BACK once (Z→Y→X→Z)
  - SEP `0x17` + first E0:lo ≥ 8 → CYCLE FORWARD once (X→Y→Z→X)
  - SEP `0x2F` → CYCLE BACK
  - SEP `0x5F` → CYCLE FORWARD
- **Where:** `python/oot_parser_v2.py` `assign_axes()`.
- **Test:** TEST-058. Validated on solid cube, cube1, prism, 4-prism with NO solved-file regression.
- **Generalization:** Universal axis-cycle rule for files where SEP/E0 transitions exist; falls back to closest-delta heuristic when neither is present.

### W3. Escape stripping is universal
- **What:** When DELTA stored bytes start with `0xFC..0xFF` or `0x00`, strip them until reaching a FULL indicator. The previous `new_format`-only gate was wrong.
- **Where:** `python/oot_parser_v2.py` `parse_coord_elements()`.
- **Test:** TEST-049. Unlocked all 6 of cube1's real coord values (50, 25, 10, 60, 75, 99).
- **Generalization:** Encoder rule, not format-specific.

### W4. Misalignment detection via non-standard TAG class
- **What:** TAG classes are always one of `{0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0}`. Anything else means the parser is reading bytes that weren't designed as TAGs — i.e., misaligned.
- **Behavior:** While misaligned, suppress greedy 0x40-prefix and long-FULL fall-throughs. Re-anchor on next SEP or standard TAG.
- **Where:** `python/oot_parser_v2.py` `parse_coord_elements()`.
- **Test:** TEST-056. Eliminated cube2's 55040 artifact.

### W5. Sane-sequel lookahead for greedy FULL emission
- **What:** When greedy FULL fall-through consumes 8 bytes, the byte at `pos+8` must be a sane parser byte (count ≤0x06, separator, standard TAG class indicator, or FULL_IND). Otherwise reject the FULL.
- **Where:** `python/oot_parser_v2.py` `_sane_sequel()` and the two greedy fall-throughs.
- **Test:** TEST-057. Eliminated 2 cube2 artifacts (11.52 and 33282).

## Solved File Formats

| File | Verts | Faces | Structural mode |
|---|---|---|---|
| `tri-crack-triangle` | 3/3 | — | basic FULLs |
| `tri-crack` (plane) | 4/4 | — | plane mode |
| `tri-crack-linear` | 7/7 | — | linear strip |
| `tri-crack-solid` (cube) | 8/8 | 12 | axis-aligned box, full SEP/E0 grammar |
| `tri-crack-prism` | 4/4 | — | prism mode |
| `tri-crack-4sides-prism` | 5/5 | — | 4-sided prism |

## Partial Wins (real progress, not yet 100%)

| File | Status | What's working | What's missing |
|---|---|---|---|
| cube1 (axis-aligned) | 5/8 corners (after TEST-060 revert) | All 6 unique coord values decoded; axis state machine assigns 5/8 correctly | Slot-assignment phase doesn't generate 3 missing corners from existing values |
| cube2 (-25°) | 1/8 corners, 8/10 distinct values | Decoder emits 41.78, 62.91, 87.09, 16.78, 37.91, 108.23 (rotated coords) | 2 missing values (Y=62.09, Y=83.22), Z=60 missing, axis assignment wrong |
| cube3 (-75°) | 1/8 corners, 7/10 distinct values | Similar — most rotated values decoded | Y=19.38, Y=80.62 missing, Z=60 missing |
| Hexhole | 3/12 | Some decode | Multi-section unhandled |
| NonRound | 2/16 | Some decode | Decoder mode unknown |
| SPHERE | 3/50 | TEST-058 axis state machine helped | Multi-section + axis overlap |
| Fan | 3/6 | Mode partially derived | Pairing of values into vertices |

## Anti-Patterns (rejected and reverted, kept here so we don't repeat them)

| Anti-pattern | Test | Why rejected |
|---|---|---|
| Cube-layout axis enforcement (force `[0,1,2,2,1,0]` on signature match) | TEST-050 → reverted in TEST-053 | 4-condition byte signature followed by hardcoded answer = fingerprint check |
| Trim cube-signature files to 6 groups | TEST-051 → TEST-053 | Same fingerprint pattern |
| Dual-Z primary emit on signature | TEST-052 → TEST-053 | Same fingerprint pattern |
| Axis-aligned cube completer (geometric 2×2×2 → 8 corners) | TEST-060 → TEST-061 | Geometric inference, not byte decoding. The decoder doesn't actually emit those 8 corners. |
