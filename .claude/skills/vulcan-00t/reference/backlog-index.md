# .00t backlog index — every doc, every test, every dead end

Built from the repo MDs + all 185 git commits + HistoryOfTests TEST-001..081.
Short bullets only. The detail lives in the named files — go there.

## CORE PRINCIPLES (non-negotiable — the user's rules)
- **We do NOT make things up.** No inventing values, no plausible-sounding decode.
- **No hero jobs / no ground-truth cheating.** A "win" that uses the DXF/CSV to
  place vertices is NOT a decode. The DXF/CSV is for SCORING ONLY, never decoding.
- **It must consume ANY file with no ground truth.** The decoder is ground-truth-
  FREE or it is not solved. (BigGrid 10201v can't be hardcoded — only real decode.)
- **No fingerprinting** (filename, n_verts/n_faces, header counts) — byte ROLES only.
- **Don't break solved files** — regression-check before every commit.
- The JS "Cheaters Only" toggle = DXF lookup for visual parity only; NOT decoding.
  See auto-memory `feedback_no_hardcoded_lookups`, `feedback_winners_do_hard_yards`.

## MD FILES (one line each)
- **HistoryOfTests.md** — THE test log. 124 entries TEST-001..081: every hypothesis,
  pass/fail/revert + byte reason. Search before any new experiment.
- **WINS.md** — proven coord byte-rules W1–W15 + solved scoreboard + anti-patterns.
- **DECODING.md** — format spec: header→pages→coord(FULL/DELTA, axis SM, C0 slots)→
  faces(EdgeBreaker C/R/L/E)→attributes.
- **EDGEBREAKER_RESEARCH.md** — CLERS bit table + Draco op semantics (E=push,S=pop);
  cube lo_nib→op partial map (doesn't generalize).
- **CUBE_GRAMMAR_RESEARCH.md** — coord byte maps, SEP+E0 axis rule, phase model
  (A base FULLs / B more FULLs / C deltas / D slot-assign), many failed context rules.
- **CUBE_LOOP_PLAN.md** — cube1-5 plan; 27-byte pre-coord prefix; post-`e0 0b 14 XX`
  structure byte; diff-rotations-to-find-invariants strategy.
- **SPHERE_LOOP_PLAN.md** — sphere loop (paused, 2/50); coord DELTA artifacts blocker.
- **SESSION_SUMMARY.md** — solved scoreboard; cube (gate-shift,op) hardcoded seq;
  brute-force results (plain 7/12, +shifts 9/12).
- **TODO.md** — 5 mysteries (A DELTA-ref-override, B tag-coords, C full-run, D cube
  triangulation, E axis-overlap), attack order, vertex-builder reference model.
- **README.md** — project overview / journey.

## TESTS THAT SUCCEEDED (real, byte-derived, kept)
- T016 vertex-queue reverse-engineered; T017 lo=F 2nd-vertex → **PLANE**; T020/021
  Plane leading-40 header + gate=0; T025 leading-40 lo_nib winding → **TRIANGLE**.
- T022/023 shared-base + strip C-ops → **LINEAR STRIP**.
- T029–T033 80:1f base[Y] override + reorder + reverse-filter → **PRISM**.
- T071/072/073 Mode D rectangular-prism branch → **4-SIDES PRISM 6/6 faces**.
- T062 full-run 3-byte short FULL + DELTA snap → **FAN 6/6 coords** (W6/W7).
- T040/041/042 **multi-section structure** discovered + confirmed (W1).
- T049 escape-strip universal → cube1 6/6 values (W3). T056 misalignment guard (W4).
- T057 sane-sequel FULL lookahead (W5). T058 **SEP+E0:lo axis state machine** →
  cube1 5/8 (W2, the first real cube cracking). T058-refine lo=A → STAY.
- T074 Mode E → cube1 8/8 GT corners. T075 post-DELTA block (W10). T076 `08:E?`
  escape FULL → cube2 inner-Y (W11). T078/079 `0x6A` escape → cube3 (W12/W13).
  T080 escape-FULL→Y pin (W14). T081 long-FULL→X pin (W15).
- Container (commit 63756ca): 2048-byte paged archive; header[11]=geo-end. Production
  (9c1de10): coord VALUE model on 50MB file.

## TESTS THAT FAILED / WERE REVERTED (do NOT retry — known dead ends)
- **Axis overlap (Mystery E):** T001 closest-delta, T002 tag-SM, T003 class→axis,
  T004 class→offset, T005 20-class swap, T006 lo_nib bits, T007 E0→axis, T008 EB-
  coupled — ALL FAIL on hexhole/sphere. Tag/sep/class does NOT carry axis.
- **SPHERE:** T037 class→axis, T038 hi_nib mod3, T039 Z-filter(neutral), T044 multi-
  section decoder (reverted), T045 sep0x2F→Z (breaks cube), T046 per-axis-prev
  (proves encoder uses RUNNING-prev, not per-axis). T070 IDELTA→STAY (fails hexhole).
- **Cube fingerprint cheats:** T050 layout-axis-enforce, T051 trim-to-6-groups,
  T052 "cube1 solved" — all REVERTED in T053 (signature shortcuts, not rules).
  T060 geometric cube completer REVERTED in T061 (geometry inference, not decode).
- **Context-rules for count=0 misalignment:** T054 (2 attempts), T055 (2 attempts)
  all FAIL — local context can't distinguish cube2 misalign from prism real Z=5500.
- **Fan cheats:** T063 REVERT fan_pattern_post + Y-only X-reuse (honesty revert).
  T065/066 Mode C cheap fixes fail (c_ops & vertex_table entangled).
- **"Fast path" SOLVED commits** (HEXHOLE 024c7e2, L-SHAPE b66342f, STEPPED 03250e1,
  4-PRISM 7805651) = DXF-lookup fast paths, gated behind Cheaters-Only — NOT decodes.

## BRUTE FORCE ALREADY DONE (don't re-run blind)
- Cube C/R/L search: plain max **7/12**, +E+gate-shifts max **9/12**
  (`5C+6R`, shifts `(0,-1,1,0,-1,1,1,1,-1,0,0,0)`). 3M+ attempts.
- Hardcoded cube seq that hits 12/12: shifts `(-1,-1,+1,0,0,-1,-2,-1,0,0,0)`,
  ops 5C+6R/E. Byte rule for (shift,op) from lo_nibs `(7,B,B,3,B,7,7,3,3,F,3,B)`
  NEVER cracked = Mystery A/D.
- Spirale Reversi reverse decoder ported (`js/spirale-reversi-sketch.js`,
  commit f211ecd); apply harness 0/6→1/6 fan. Forward EB encoder (38defd1) for
  canonical-vs-Vulcan CLERS compare; fan ceiling 3/6 faces.
- Autonomous Ollama agent harness (`OL_GW_*.py`, commit 7ea054b+) tried to crack
  the parser via local LLM hill-climbing — limited results.

## KEY COMMIT MILESTONES (185 total; `git log` for full)
- 4005386 init → 868ec49 "CUBE IS SOLVED" (first standalone decode) →
  c5ef144 CUBE 12/12 (hardcoded seq) → d454915 brute-force findings →
  e87dc32 T058 SEP+E0 axis SM (real cracking) → b7e9b64 add WINS.md →
  642769c FAN solved → 70e0271 T063 honesty revert →
  f211ecd Spirale Reversi → 3d966bd 4-sides prism 6/6 →
  63756ca container=paged archive → 9c1de10 production value model →
  9258c3c..f41fbf7 production L5/L6 diagnosis (this session).

## STATUS NOW
- SOLVED (real): triangle, plane, linear, prism, 4-sides prism. Cube = coords solved,
  faces via hardcoded seq (byte rule open).
- PARTIAL: fan (coords 6/6, faces 4/6), cube1/2/3, stepped, hexhole, nonround, sphere.
- THE TWO OPEN WALLS (toy AND production, same root): **(A) face op-type/gate-shift
  byte rule**, **(E) axis disambiguation when ranges overlap** — neither is in local
  bytes; both likely need encoder STATE / a minimal isolating test file from the user.
