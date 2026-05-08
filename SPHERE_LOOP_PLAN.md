# SPHERE Decoding Loop — Plan

> **Status (2026-05-08): PAUSED.** User requested pivot to a focused effort on
> cube1.00t–cube5.00t. See `CUBE_LOOP_PLAN.md`. Cron job 4f18b0f4 cancelled.
> Last iter: 9. Last score: 2/50. Resume by reinstating the cron with this plan.

## Target
`exampleFiles/tri-crack-SPHERE.00t` — 50 DXF vertices, 96 faces.

## Current state (commit 044f424, post-revert)
- OOT: 51 vertices, 96 faces
- Vertex match: 2/50 (positions mostly wrong)
- Face count: 96/96 exact match — face decoder is doing real work
- Issue: axis assignment is wrong (X/Y/Z values overlap, closest-delta heuristic puts coords in wrong axes)

## DXF coord ranges
- X: 13 unique values, 1000–1300
- Y: 4 unique values, 1000–1300 (overlap with X!)
- Z: 13 unique values, 150–450

## Strategy
Try byte-level rules that disambiguate axis assignment. Each hypothesis applies a different rule for which coord group goes to X, Y, or Z. Score = DXF positions matched (out of 50).

**Hard rule: NO DXF lookup tables.** Hypotheses must be byte-derived rules from the .00t file content. If a hypothesis works for SPHERE, verify it doesn't break the 4 currently-decoded files (Triangle, Plane, Linear Strip, Prism).

## Hypothesis queue

Pending — each iteration takes the next one:

1. **Tag class → axis**: Each coord group's first non-C0 tag class (20/40/60/80/A0/C0/E0) maps to an axis. Try mappings: 60→Y, 80→Z, etc. Survey what classes appear in SPHERE.
2. **Tag hi_nib mod 3 → axis**: hi_nib in tag's byte2 mod 3 = axis index.
3. **E0 tag pattern delimits axis cycles**: between consecutive E0:xx tags, count groups → axis cycle (e.g., E0 marks "next 3 are X, Y, Z").
4. **Z-range filter**: any value in [150, 450] AND distinct from base[2] is Z. Eliminate Z first, then disambiguate X/Y.
5. **Sep byte signals axis switch**: specific separator byte values (0x07, 0x17, 0x2F, 0x47, 0x5F) trigger axis change.
6. **lo_nib parity**: lo_nib of preceding tag's byte2 is even → keep axis, odd → cycle.
7. **Position-in-stream regime**: alternating XY pairs with periodic Z, like fan but extended.
8. **Two-byte signature lookup**: scan tag(class,byte2) pairs in coord region; same pair reliably indicates same axis transition across the file.
9. **DELTA size hint**: nb=1 vs nb=2 vs nb=3 correlates with axis (X vs Y vs Z) given range differences.
10. **Per-axis prev tracking**: instead of running prev, maintain prev[X], prev[Y], prev[Z] separately; the parser identifies which is closest after each DELTA (with extra signal from tag).
11. **Tag-byte difference**: compute byte2 ^ prev_byte2 for each TAG; group by hash → axis class.
12. **Brute-force search**: enumerate all 3-axis assignments for first 6 groups; pick assignment that yields most DXF matches downstream.

## Each iteration

1. **Read state**: iteration counter at `.sphere_loop_iter`; latest entries in `HistoryOfTests.md`.
2. **Pick next hypothesis** from the queue not already attempted.
3. **Implement** in `python/oot_parser_v2.py` — gate the experimental rule behind a flag like `if sphere_experimental_rule_N:`. Do not break solved files.
4. **Run** `python3 python/oot_parser_v2.py 2>&1 | grep -E "OOT:|Vertex match"` — verify Triangle/Plane/Linear/Prism still solved, count SPHERE vertex match.
5. **Score**: SPHERE_match / 50. Note byte evidence supporting the hypothesis.
6. **Decide**:
   - Score improved AND solved-file regressions = 0 → commit, mark hypothesis "WIN" in TEST-NNN.
   - Score regressed or solved-file regression → REVERT, mark "FAIL" with byte-level reason.
7. **Append TEST-NNN** entry to `HistoryOfTests.md` either way (FAIL entries are research, not waste).
8. **Increment counter, write back to `.sphere_loop_iter`**.
9. **If score ≥ 45/50** (90% match): write summary to `SESSION_SUMMARY.md`, declare "SPHERE CRACKED — rule found", stop loop.
10. **If iteration ≥ 12 with no improvement**: write summary listing all hypotheses tried + their byte evidence, stop loop.

## Anti-patterns

- **No `if filename == "tri-crack-SPHERE.00t"` shortcuts.** Rules must be byte-derived.
- **No emitting hardcoded DXF vertices.** The whole point is decoding.
- **No `n_verts == 50 and n_faces == 96` signature lookups.** Same as above.
- **No incremental "almost there" claims** — only commit on real measurable improvement, and only call it solved at ≥45/50.

## Stop conditions

- Score ≥ 45/50 → CRACKED, stop.
- Iteration count ≥ 12 → stop, summarize, no more hypotheses on this run.
- Solved-file regression that can't be cleanly reverted → stop, ask user.
