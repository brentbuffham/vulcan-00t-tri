---
name: vulcan-00t
description: >-
  Reverse-engineering the Maptek Vulcan .00t triangulation binary format (decode
  vertices + EdgeBreaker faces, and build vulcan00TParser.js for Kirra). Trigger
  whenever the work touches: .00t files, Vulcan/Maptek triangulation, the
  oot-parser / vulcan00TParser, EdgeBreaker/CLERS face decode, the coord TAG/SEP/
  count/DELTA grammar, axis state machine, the toy test files (cube/fan/prism/
  sphere/hexhole/nonround/linear/plane/triangle), or the production HEAVE .00t.
  Loads 9 MONTHS of proven rules + dead ends so we DON'T re-derive them.
---

# Vulcan .00t reverse-engineering

**Read this FIRST. Do not re-derive what is already known. Nine months of
testing live in this repo — stand on it.**

> **▶ RESUMING? READ `reference/RESUME-2026-07-12.md` FIRST, then
> `STRIP_SCHEDULE.md`.** 2026-07-11: **rail schedule structure CRACKED** —
> refs_v2 refs form ~10–13 CONCURRENT ±1 rails (one per live strip, spacing ≈
> column pitch ~70), round-robin turns (modal turn = 1 ref + 1 idless = one
> quad); the −95..−160 "anchor steps" were switches BETWEEN strips, NOT
> per-fold pitch (07-11's sparse-anchor framing superseded; refs_v2.pkl itself
> stands). Strict ±1 clustering → `rails_v3.pkl`; strip machine teacher-forced
> **quad rate 82.3%** (was 56.3%), mirror n=S−r edges 92.7%, clean rails
> 90–100%. REFUTED: free-running alloc counter (must mirror-resync per turn),
> 1:1 group↔DXF face order. NEXT (Fable): GT-free S — lo-channel `00 pp<0x80`
> vs clean rails, coord-side fold boundaries, e002/e004 push/pop on long
> rails. Scripts: `python/strip*.py`.
> Prior: RESUME-2026-07-11 (ref decode cracked, phantom-splice bug), 07-10
> (channel=global phase clock), 07-09/08 (allocation rule), 07/06/05/04.

## MODEL ROUTING (cost control — user directive 2026-07-05)
Fable is expensive; use it ONLY for detective work. Route sessions:
- **Fable**: cracking NEW grammar/structure (hypothesis space open), reframing
  stuck walls, triaging ambiguous evidence, deciding what's a dead end.
- **Opus** (`/model opus`): executing a WRITTEN spec — building/fitting a
  decoder against a resume-doc model, running validation ladders, regression
  tests, brute-force sweeps, porting to js/vulcan00TParser.js, cold-file runs.
- To make this work, every resume doc MUST end with a spec-shaped next step
  (state machine + validation ladder + file paths) so an Opus session can
  execute without re-deriving. If an Opus session finds the spec is WRONG
  (bookkeeping violations, model doesn't fit), it should STOP and write up
  the failure precisely — that failure report is the input for a Fable
  detective session, not something to push through.

## THE PRIME DIRECTIVE (read before anything)
1. **We do NOT make things up.** No invented values, no plausible-sounding decode.
2. **No hero jobs. No ground-truth cheating.** Using the DXF/CSV to place vertices
   is NOT a decode — DXF/CSV are for SCORING ONLY. A "win" that needs the answer
   isn't a win. **And never SHOW answer-key-assisted output as decode results**
   (the 2026-07-03 "all-green 2923/2975" viewer incident): every viewer/report
   displays GT-free decode only, with provenance labeled
   (`generate_compare.py` argv[4]); scoreboard numbers state their category —
   teacher-forced / candidate-recall / GT-free are different things and only
   GT-free counts.
3. **It must decode ANY file with NO ground truth.** Ground-truth-free or not solved.
4. **No defeatist narration.** State findings and decisions plainly; keep moving.
5. **Full backlog index: `reference/backlog-index.md`** — every MD, every passed and
   failed test, every brute-force already run, every dead end. CONSULT IT before
   proposing an experiment; most have been tried.

## Canonical knowledge (the backlog — consult before any new experiment)
- **`HistoryOfTests.md`** — the LESSONS-LEARNED / TESTS-CONDUCTED log. 124 entries
  (TEST-001 → TEST-081+). EVERY hypothesis tried, what passed, what was reverted,
  and WHY. Search it before proposing any experiment — odds are it was tried.
- **`WINS.md`** — proven byte-grammar rules W1–W15 (coord section). The decoder
  rules that actually hold.
- **`DECODING.md`** — the step-by-step format spec (header → pages → coord → faces
  → attributes).
- **`EDGEBREAKER_RESEARCH.md`** — CLERS / Draco cross-reference; the face-op model.
- **`CUBE_GRAMMAR_RESEARCH.md`** — coord-region byte maps, the SEP+E0 axis rule,
  the phase model, multiple failed context-rules (documented so we don't repeat).
- **`SESSION_SUMMARY.md`** — solved-file scoreboard + the cube (gate-shift, op)
  breakthrough sequence + brute-force results.
- **`CUBE_LOOP_PLAN.md`, `SPHERE_LOOP_PLAN.md`, `TODO.md`** — brute-force plans.
- Parsers: `python/oot_parser_v2.py` (AUTHORITATIVE, toy files) and
  `js/oot-compare.html` (JS mirror). `js/vulcan00TParser.js` (production scaffold).
  `js/spirale-reversi-sketch.js` (CLERS stack decoder).
- Memory: `[[project_vulcan00t_parser_buildspec]]`, `[[project-production-format-breakthrough]]`,
  `[[project_00t_container_structure]]`, `[[project_edgebreaker_findings]]`.

## Hard-won METHODOLOGY (the user's rules — follow them)
1. **NO FINGERPRINTING.** Never gate behavior on filename, header counts, or
   n_verts/n_faces. Rules must operate on byte ROLES the encoder emits. (See WINS
   "Anti-rule reminder" + the reverted TEST-050/051/052/060.)
2. **DON'T BREAK SOLVED FILES.** Triangle, Plane, Linear, Cube, 4-Prism are solved.
   Run the regression before committing any toy-file change.
3. **It is NOT textbook EdgeBreaker.** It's a non-standard CLERS variant. The
   textbook stack model (E=push/S=pop) does NOT balance on this stream — confirmed.
4. **Brute force has been done** on the small files (cube C/R/L/E search, gate
   shifts). Check SESSION_SUMMARY / HistoryOfTests before re-running searches.
5. **Python is authoritative; JS mirrors.** Screenshot the viewer after changes —
   counts hide topology errors.
6. **Drop the defeatist commentary.** Report findings and decisions plainly.

## Format in brief (all SOLVED on production + toy)
- Header: magic `EA FB A7 8A` + `vulZ`; 15× int32. **`dir[11]` = geometry-end /
  attribute-start pointer** (bounds geometry). Container = 2048-byte page chain;
  geometry starts at offset 8252 (`Created External` @ 8261). De-paging is a DEAD
  END (no page headers inside geometry).
- Sections: coord `[8328 .. ~26.25M]` → topology/faces `[~26.25M .. dir[11]]` →
  attributes + PNG thumbnail `[dir[11] .. EOF]`.
- Coord grammar: record = `TAG · SEP · COUNT · payload`. `TAG 0x20`=new primary,
  `TAG 0x60`=refine-previous-axis. SEP `(b&7)==7`. FULL when payload[0]∈
  {40,41,C0,C1} else DELTA (splice prev high bytes + payload low bytes).

## Coord-section PROVEN rules (WINS.md — summary)
- **W1** multi-section markers (`e0 03 14 20 00 40 17`). **W2** SEP+E0:lo axis
  state machine (0x17+E0:lo≥7→STAY; <7→CYCLE BACK; ≥8→CYCLE FWD; 0x2F→back;
  0x5F→fwd). **W3** escape-strip 0xFC..FF/0x00 to FULL_IND. **W4** non-standard TAG
  class ⇒ misalignment, suppress greedy. **W5** sane-sequel lookahead for FULLs.
  **W6** 3-byte short FULL in full-run. **W7** snap prev[3:8]=0 before full-run
  DELTA. **W8** prism 80:1f gate (not full-run). **W10** post-DELTA block: greedy/
  long-FULL must be SEP-anchored. **W11–W13** escape-prefixed FULLs (`08:E?`,
  `0x6A`, `count 6A`) carry inner-Y. **W14** escape-FULL axis pin → Y. **W15**
  long-FULL axis pin → X for rotated cubes. (W9 reverted as a fingerprint.)

## Face/CLERS — what's KNOWN vs OPEN (the hard part, never fully cracked)
- Op semantics (Draco, EDGEBREAKER_RESEARCH): C update; R/L update+splitflag;
  **E=stack PUSH (branch start); S=stack POP (branch end)**. Toy decoder never
  modelled S → fails on branching meshes (sphere/hexhole).
- **Cube SOLVED only via a HARDCODED (gate-shift, op) sequence** (SESSION_SUMMARY):
  `init bnd=[0,1,2] gate=1`; 5 C + 6 R/E with shifts
  `(-1,-1,+1,0,0,-1,-2,-1,0,0,0)`. The 12 cube ops' lo_nibs
  `(7,B,B,3,B,7,7,3,3,F,3,B)` were NEVER mapped to (shift,op) — that byte rule is
  THE open mystery (Mystery A). Brute force: plain C/R/L max 7/12, +E+shifts max
  9/12 (`5C+6R`, shifts `(0,-1,1,0,-1,1,1,1,-1,0,0,0)`).
- Partial cube op-type rule (cube-only, does NOT generalize): lo∈{7,B}&c>0→C;
  lo∈{7,B}&c=0→R; lo=3→R/E; lo=F→R.
- Production faces `[~26.25M..dir[11]]`: ~3.18M records ≈ 3.23M triangles (1 per
  triangle, VERBOSE — carries per-triangle data, not 2-bit CLERS). Lead-tag
  0xE0-class = C ≈ vertex count. Payload size by op: C=4B, E=7B, R/L/S=1–2B. The
  textbook stack does not balance ⇒ non-standard variant (matches toy lesson).

## OPEN MYSTERIES (do not "discover" these again — they're known-open)
- **A. C/R/L/E/S op-type + gate-shift byte rule** — never decoded. The crux of faces.
- **B. Tag-encoded coords** (Stepped Pyramid) — implicit-zero base + per-group deltas.
- **C. DELTA reference override** (prism/L-shape) — "use base axis as prev" signal.
- **E. Axis overlap** (hexhole/sphere; production Y) — when axes share range, no
  local byte selects axis. 8+ approaches failed (TEST-001..008). Production Y is the
  same wall: X+Z decode (~24% 2D) but per-vertex Y/axis needs encoder STATE, not
  local bytes.
  - **REFRAMED 2026-06-26 (`[[project_coord_order_breakthrough]]`):** axis is
    POSITIONAL — coords stream vertex-major in **X→Y→Z** order; axis = cycle position,
    never a local byte. That's WHY T001-008 failed. PROVEN on toys via
    `python/order_probe.py` (triangle `XYZXY`, fan, prism `XYZXYZ`, 4-prism). Toy
    files DEDUP repeated coords (origin/axis-aligned), which scrambled the visible
    cycle. Value-based axis labelling is impossible (splice keeps high bytes → all
    axes in-band; `decode_label.py`). The wall is now CONCRETE engineering, not a
    mystery: (1) robust record framing `[tag][sep][count][payload]` through the ~17%
    escape/FULL records (`frame_check.py` = 83% clean), (2) exact tag→axis grammar +
    dedup/skip detection. New decoders: `decode_v7.py`, `decode_pos.py`. v6's
    `b<=0x06` gate MISFRAMED every long record — abandon it.

## Solved scoreboard (toy)
SOLVED: triangle, plane, linear strip, cube (hardcoded seq), prism, 4-sides prism.
PARTIAL: fan, cube1/2/3, stepped pyramid, hexhole, nonround, SPHERE.

## Production status (HEAVE 50MB)
Container/sections/vertex-0/coord VALUE model = solved. Vertex assembly blocked on
axis/Y (Mystery E at scale). Faces = verbose EdgeBreaker, C=0xE0, op sub-grammar
open (Mystery A at scale). Ground truth: `HEAVE_CSV.csv` (face-ordered triples).

## Anti-patterns (rejected — see WINS/HistoryOfTests, don't retry)
Cube-layout axis enforcement, trim-to-6-groups, dual-Z emit on signature,
geometric cube completer — all fingerprint/geometry cheats, all reverted.
