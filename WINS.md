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

### W6. 3-byte short FULL detection in FULL-run mode
- **What:** Clean round values (900.0, 500.0) are stored as just 3 bytes (sign+exp+leading mantissa) — the trailing 5 IEEE bytes would be all-zero, and the encoder omits them in favor of subsequent TAG/SEP bytes. Detect by comparing `val_3` (read 3 bytes + 5 zeros) against `val_8` (read 8 bytes): if `val_3` is an exact integer AND `val_8` is within 0.5 of it, prefer `val_3` and advance 3 bytes.
- **Where:** `python/oot_parser_v2.py` init FULL-run loop and standard-parsing FULL extension; mirrored in `js/oot-compare.html`.
- **Test:** TEST-062. Cracked fan: 900.0/500.0 exact (was 900.05/500.03), and recovered 273.24 (was eaten by 900 over-read).
- **Generalization:** Encoder rule for any file with `full_run_active`. Will likely apply to NonRound too.

### W7. Snap-prev-to-3-bytes before DELTA in `full_run_active`
- **What:** In FULL-run mode, before computing a DELTA, zero out `prev[3:8]`. The encoder assumes DELTAs are stacked on "clean" prev values where bytes 3..7 are zero; if `prev` was a real 8-byte FULL with mantissa data, leaving those bytes in causes the DELTA result to inherit mantissa noise.
- **Where:** `python/oot_parser_v2.py` DELTA reconstruction, gated on `full_run_active`; mirrored in JS.
- **Test:** TEST-062. Fan 300 DELTA from prev=476.34 → exact 300.0 (was 300.05); 600 DELTA from clean 300 prev → exact 600.0 (was 600.05).

### W8. Gate `80:1f` prism rule on `not full_run_active`
- **What:** Prism's "use base[Y] for next 1-byte DELTA" rule mis-fires in fan/NonRound (also have 80:1f tags but with clean running prev). Gate the rule so it only applies outside FULL-run mode.
- **Where:** `python/oot_parser_v2.py` use_base_y_for_next_delta branch; mirrored in JS.
- **Test:** TEST-062.

### W9. ~~Gate `prism_pattern_post` dedup-drop on `not _fan_pattern_post`~~ (REVERTED — was a fingerprint cheat)
- **Reverted:** This was a per-file pattern gate (Z-flat + ≥4 Y-axis groups), not a universal byte-level rule. Per the "winners do hard yards" rule, removed. See HistoryOfTests TEST-063.

### W10. Post-DELTA block: greedy/long-FULL must be SEP-anchored
- **What:** In `full_run_active` mode, after a DELTA the encoder emits a TAG cluster (some bytes possibly misaligned) that ends with a SEP re-anchoring the parser. Greedy 8-byte FULL and long-FULL marker (0x08–0x0e) must NOT fire while inside this post-DELTA region.
- **Rule:** Track `post_delta_block`. Set to True when emitting a DELTA/IDELTA, reset to False on the next SEP. Guard greedy/long-FULL paths on `not post_delta_block`.
- **Where:** `python/oot_parser_v2.py` `parse_coord_elements()` and mirrored in `js/oot-compare.html`.
- **Test:** TEST-075. cube2's junk 92.14 from bytes [40 57 08 e8 40 4f 0b ce] right after DELTA 108.22 is correctly suppressed — those bytes are TAGs (40:57, 08:e8, 40:4f, 0b:ce; the 08/0b are non-standard/misaligned) followed by the block-end marker, not a FULL. NonRound's only post-DELTA artifact dropped (49v → 48v); cube3 went 10 coords → 9.
- **Generalization:** Universal full_run_active rule. Verified to not regress fan (all deep FULLs are SEP- or FULL-preceded), SPHERE (no DELTA→FULL), Stepped Pyramid (only compact 2-byte FULL after DELTA — unaffected). Encoder grammar discovery.

## Solved File Formats

| File | Verts | Faces | DXF Match | Mode | Structural mode |
|---|---|---|---|---|---|
| `tri-crack-triangle` | 3/3 | 1/1 | 3/3 v, 1/1 f | A | basic FULLs |
| `tri-crack` (plane) | 4/4 | 2/2 | 4/4 v, 2/2 f | A | plane mode |
| `tri-crack-linear` | 7/7 | 5/5 | 7/7 v, 5/5 f | A | linear strip |
| `tri-crack-solid` (cube) | 8/8 | 12/12 | 8/8 v, 12/12 f | A (cube fast path) | axis-aligned box, SEP/E0 grammar |
| `tri-crack-prism` | 4/4 | 2/2 | 4/4 v, 2/2 f | A | prism mode |
| `tri-crack-4sides-prism` | 5/5 | 6/6 | 5/5 v, **6/6 f** | **D** (TEST-073) | rectangular prism, 4 sides + 2 base |
| `tri-crack-fan` | 6/6 | 4/4 | 6/6 v, 4/6 f | **C** (TEST-067) | flat fan, canonical CCCRR ceiling |
| `cube1` (axis-aligned) | 8/8 | 12/12 | (no DXF) **8/8 GT** | **E** (TEST-074) | axis-aligned 2×2×2 cube lattice |

## Partial Wins (real progress, not yet 100%)

| File | Status | What's working | What's missing |
|---|---|---|---|
| cube1 (axis-aligned) | 5/8 corners (after TEST-060 revert) | All 6 unique coord values decoded; axis state machine assigns 5/8 correctly | Slot-assignment phase doesn't generate 3 missing corners from existing values |
| cube2 (-25°) | 1/8 corners, 7 clean coord values (post TEST-075) | Decoder emits 41.78, 37.91, 10.25, 62.91, 87.09, 16.78, 108.23 — all GT-matching, no junk artifact | 3 missing values (Y=62.09, Y=83.22, Z=60.25), axis assignment misclassifies 87.09 as Z |
| cube3 (-75°) | 1/8 corners, 9 coord values (was 10 with TEST-075) | Most rotated values decoded; one junk artifact eliminated | 2 missing values (Y=80.62 + 1 more), Z=60 missing, residual junk in decoder output |
| Hexhole | 3/12 | Some decode | Multi-section unhandled |
| NonRound | 2/16 | Same encoding family as fan; 3-byte short FULL + DELTA snap apply but X-reuse rule unknown | Pairing |
| SPHERE | 3/50 | TEST-058 axis state machine helped | Multi-section + axis overlap |

## Anti-Patterns (rejected and reverted, kept here so we don't repeat them)

| Anti-pattern | Test | Why rejected |
|---|---|---|
| Cube-layout axis enforcement (force `[0,1,2,2,1,0]` on signature match) | TEST-050 → reverted in TEST-053 | 4-condition byte signature followed by hardcoded answer = fingerprint check |
| Trim cube-signature files to 6 groups | TEST-051 → TEST-053 | Same fingerprint pattern |
| Dual-Z primary emit on signature | TEST-052 → TEST-053 | Same fingerprint pattern |
| Axis-aligned cube completer (geometric 2×2×2 → 8 corners) | TEST-060 → TEST-061 | Geometric inference, not byte decoding. The decoder doesn't actually emit those 8 corners. |
