# TRIAGE — Vulcan `.00t` reverse-engineering project

**Date:** 2026-07-13 · **Status:** format SOLVED; repo being consolidated onto the
new parser and old work retired.

---

## 1. Executive summary

The `.00t` format is **solved**. A `.00t` is a `vulZ` **FastLZ-compressed, paged
container**; decompressing it yields a plain fixed-stride binary image:

```
120-byte header · vertex_count (BE u32 @0x48) · face_count (BE u32 @0x60)
N × (3 × BE f64) absolute vertices
M × (3 × BE u32 + 12-byte payload) 1-based face-index triples
trailing ASCII attributes + optional PNG thumbnail
```

(Container header is little-endian; geometry fields are big-endian.)

This was cracked by the Incline Rust reference decoder `tri00t.rs` (kept in
`ROSETTA/`) and ported to JS (`js/vulcan00TParser.js`) and Python
(`python/vulcan00t_parser.py`). It reproduces **100% of vertices and 100% of face
topology** on every fixture in `exampleFiles/`, including the 10,201-vertex /
20,000-face grid — files that defeated ~9 months of prior work.

| Fixture | Decoded (new parser) | Ground truth |
|---|---|---|
| cube | 8 v / 12 f, v0 = (27170, 157410, 1000) | 8 / 12 ✅ |
| SPHERE | 50 v / 96 f | 50 / 96 ✅ (was 2/50) |
| BigGrid | 10,201 v / 20,000 f | 10,201 / 20,000 ✅ |

---

## 2. Why we failed to find the format for ~9 months

**Root cause: we reverse-engineered the *compressed* byte stream as if it were the
data model.**

- For ~9 months the only inputs were tiny toy files (4–8 vertices) with clean
  integer coordinates. After the `Variant`/object header we read the raw page
  bytes directly — but those bytes are a **FastLZ-compressed stream**, never
  decompressed.
- FastLZ's control bytes and back-references *look* like a structured grammar:
  - control byte high bits → what we called **tag classes** `0x20/0x40/0x60/0x80/…`
  - literal runs → what we called **FULL / DELTA coordinate values**
  - match operations (copy-from-earlier) → what we called the **EdgeBreaker /
    CLERS** connectivity ops and "separator" (SEP) bytes.
- So an entire apparatus was built to model compression opcodes: an axis state
  machine, DELTA reference overrides, slot vertices, primaries, gate rotation, a
  `0x1B` finalizer, etc. It fit the toy files only with **per-file special cases**
  (Mode A/B/C/D branches), a **hardcoded DXF "Cheaters" lookup**, and it never
  generalized — the "axis overlap" problem (X/Y/Z in the same numeric range) was
  declared unsolvable after 8 approaches. Those were all symptoms of **fitting
  noise**: you cannot assign a stable coordinate axis to a FastLZ control byte.
- The `vulZ` magic was seen from the start but read as a "format signature," not as
  **"this is a compression container that must be inflated first."**
- **Confirmation bias sustained it:** each partial "win" (triangle, plane, cube
  coordinates) came from short compressed streams that happened to be mostly
  literals, so the raw bytes coincidentally resembled the real doubles. That
  reinforced the wrong model instead of exposing it.

**What broke the logjam:** treating `vulZ` as FastLZ, decompressing the pages, and
discovering plain IEEE-754 doubles + integer index triples underneath. The Incline
`tri00t.rs` decoder proved it end-to-end; the byte "grammar" evaporated.

**Lesson for next time:** when a binary format shows a magic string and your decoded
"grammar" needs per-file exceptions and won't generalize, **suspect a compression
or container layer before inventing a value grammar.** Get real production data and
ground truth early — the toy files were actively misleading.

---

## 3. Current repository state

### Canonical / keep
- `ROSETTA/tri00t.rs` (+ `ROSETTA/README.md`) — reference decoder, source of truth.
- `00T_FORMAT.md` — format spec.
- `js/vulcan00TParser.js`, `js/vulcan00TWriter.js` — JS runtime.
- `python/vulcan00t_parser.py` — Python runtime (dependency-free; implements the
  full pointer-tree walk + FastLZ level 1/2 + recovery paths).
- Viewers: `js/oot-read.html`, `js/oot-compare.html`, `js/oot-viewer.html`,
  `js/oot_to_dxf.html`, `js/intercepts_compare.html` — all now import the new parser.
- `python/oot_to_dxf.py` — CLI/GUI converter, repointed to the new parser.
- `exampleFiles/` — fixtures + DXF ground truth.

### Retired (see `RETIRED.md`)
- Old parser entry points → `RETIRED/` (`oot_parser_v2.py`, `oot-parser.js`,
  `spirale-reversi-sketch.js`).
- ~330 Python research scripts + 44 data artifacts in `python/` — historical.
- 23 root research `.md` docs — historical, superseded by `00T_FORMAT.md`.

### Ratio
Roughly **95% of the repo is now dead research** (334 `.py` + 44 data + 23 docs)
versus a handful of canonical files. This is normal for a long reverse-engineering
effort but should be consolidated.

---

## 4. What this means for the Git

1. **`main` is correct.** The breakthrough arrived via branch
   `claude/pensive-curie-rihLQ`, fast-forward-merged into `main` (now at the vulZ
   parser). No divergence.
2. **Uncommitted work exists in the tree** (not yet committed or pushed): the five
   viewer repoints, `python/vulcan00t_parser.py`, `ROSETTA/`, the `RETIRED/` moves,
   `RETIRED.md`, and this `TRIAGE.md`.
3. **Recommended git actions (pending your go-ahead):**
   - Commit the consolidation on a branch (e.g. `chore/adopt-vulz-parser`) with a
     clear message, then PR/merge to `main`.
   - After confirming `main` contains it, delete the merged remote branch
     `origin/claude/pensive-curie-rihLQ`.
   - **Decision needed:** how to physically handle the ~330 retired research
     scripts — leave them in `python/` (declared retired in `RETIRED.md`) or move
     them to `python/retired/` (clean tree, but a large diff and it breaks the
     documented repro commands). See the open question below.
   - Consider tagging the pre-consolidation commit (e.g. `research-archive`) so the
     history is easy to find if ever needed.
4. **Nothing has been pushed** during this session; the remote is unchanged.

---

## 5. Open questions / decisions for the owner

- **Wiki target:** this repo's own GitHub wiki
  (`github.com/brentbuffham/vulcan-00t-tri` — not cloned locally) vs a section of
  `Kirra.wiki` (since this feeds Kirra). Which should the write-up go to?
- **Bulk research relocation:** declare-retired-in-place (done via `RETIRED.md`) or
  physically move ~330 scripts to `python/retired/`?
- **Kirra integration:** port `vulcan00TParser.js` into Kirra's `.00t` import path
  (Kirra was hands-off until the decode was proven — it now is).
