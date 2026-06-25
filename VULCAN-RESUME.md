# VULCAN-RESUME — Production .00t decode (hold point)

**Date:** 2026-06-25 (updated)
**Status:** Container + coordinate VALUE model cracked. Vertex ASSEMBLY now
DIAGNOSED: the 0% 3D wall is caused by Y-row advancement, NOT the value model —
**2D (X,Z) recall = 23.65%** proves X/Z assembly is substantially correct. The
blocker is Y. This document is the pick-up point.

---

## SESSION UPDATE 2026-06-25 (read this first)

The earlier "recall 0.00%" was misleading. New, validated diagnosis:

- **Drop Y, test 2D (X,Z) pairs → recall 23.65%, precision 41.9%** (`decode_2d.py`,
  163k of 690k GT (X,Z) pairs). So the X/Z value model AND pairing are mostly right;
  **Y-row advancement is the dominant blocker.** Crack Y → 3D recall should approach
  the 2D ceiling.
- **Surface = gridded DTM**: X step ~0.15 m, Y step 0.25 m, ONE Z per (X,Y) column
  (1,206,979 columns ≈ 1.21M verts), ROW-MAJOR scanline, irregular boundary. (The
  prior "0.45 m X step" was every-3rd column; true grid is 0.15.)
- **Clean grammar:** record = `TAG · SEP · count · payload(count+1 bytes)`.
  `TAG 0x20` = NEW primary coord; `TAG 0x60` = REFINE the previous primary's axis.
  SEP constant 0x17 in clean runs. ~3.43M coord records ≈ 3 per vertex.
- **Refine-binding bug fixed:** a 0x60 Z-refine, prepended with X high bytes, hits the
  X grid → greedy "try X first" mis-tagged it. Bind 0x60 to last primary axis
  (`decode_v3.py`).
- **Y is IMPLICIT / marker-driven**, not a per-row coord (only 1,086/2,907 rows
  recovered greedily, with many false positives — see `profile_y.py`). The
  X/Y/Z primary selector is NOT in the record's own bytes; it is structural/stateful.
- **Escapes ARE present** (contradicts §4 "absent"): clusters like
  `0c e4 f5 c3 03 b5 40 80 1d 29 0e 58 e6 f9` sit at SPARSE-ROW boundaries and carry
  FULL-precision coords (`40 80` = Z-double prefix). Prime candidate for row-advance.

## SESSION UPDATE 2026-06-25 (part 4) — L6 started: it IS EdgeBreaker, C = 0xE0-class

Topology section `[~25.0M .. header[11]]` characterized:
- Sharp regime change ~25–26M (entropy 7.4→6.0). **3,182,837 records ≈ 3,232,403
  triangles = 1 record/triangle.**
- **Lead TAG = CLERS opcode. 0xE0-class = 55.6% ≈ vertex count = C (create).**
  0x20-class+no-lead ≈ 28% = candidate R; 0x40/60/80/F0 tail = L/E/S. Textbook
  EdgeBreaker distribution (C≈50%, R≈30%, rest L/E/S).
- The 0xE0 record's trailing bytes embed tag/sep sub-structure (not flat payload) —
  the per-op sub-grammar (vertex ref / edge selector) is the next thing to reverse.
- `js/spirale-reversi-sketch.js` is the ready CLERS stack decoder.
- **L6 may unlock Y**: CLERS traversal = the vertex C-order = coord-group order, so
  topology should pin per-vertex Y. New scripts: `topo_probe.py`, `topo_values.py`,
  `topo_tokens.py`, `e0_payloads.py`.

---

## SESSION UPDATE 2026-06-25 (part 3) — vertex = GROUP; X+Z solved; Y is the only wall

Cracked the framing. Supersedes the "dense codec" worry in part 2:

- **A VERTEX = a GROUP of records** (~2.8 rec/vertex), typically
  `[0x20 primary][0x20 primary][0x60 refine]`. The 1-record-per-vertex assumption
  was wrong and corrupted all prior delta/codec analysis.
- **The two primaries are Z then X.** Second primary SPLICE-decodes X EXACTLY
  (clean grid values); first primary splices Z (refine fixes low bytes to 0.01).
  **X and Z are SOLVED** by splice given correct grouping + per-axis prev update +
  refine.
- **The "dense codec" was a mirage** — two bugs: (1) OFF-BY-ONE emit (emitting on
  the Z record before that vertex's X primary was read → wrong pairing; this is why
  decode_v4/2d hit 24% and not higher), (2) fabricated-Z (force-splicing seed Z high
  bytes onto unclassified records → fake 515.6 plateau; also fabricated the fake
  "constant-X column"). Both fixed in `decode_v5.py`/`decode_v6.py`.
- **Y is the SOLE remaining blocker.** Carried (implicit) along a segment; with X+Z+
  group correct it resolves ONLY the top row (recall 4 verts). Traversal is
  mesh-ordered (top row, then jumps) so the Y sequence likely tracks the EdgeBreaker
  traversal. Next: decode L6 topology to recover vertex order → derive Y, OR find the
  explicit Y-row-marker. New scripts: `tag_pattern.py`, `group_align.py`,
  `decode_group_values.py`, `decode_v5.py`, `decode_v6.py`.

---

## SESSION UPDATE 2026-06-25 (part 2) — traversal is COLUMN-MAJOR + delta-coded

Pushed on Y. Major reframe (supersedes the row-major assumption above):

- **Traversal is COLUMN-MAJOR.** X is the SLOW axis = exactly **3134 columns**
  (= the unique-X count). The decoded stream shows long runs of CONSTANT X
  (e.g. pos 8904–8983 all X=60660.69) while Z/Y vary. Each GT column has ~387 pts
  (median 99) spanning the full Y range; within a column **Y is irregular** (steps
  0.25/0.5/1.0/2.0 — sparse 0.25 grid, a TIN). So Y must be encoded per-vertex.
- **My 3D recall stays ~0% because of two coupled bugs:**
  1. Within a column the decoder can't classify the per-vertex records, so it
     **fabricates a fake Z ≈ 515.6** by force-splicing the seed Z high-bytes
     (`40 80 1c`) onto them. The ~515.6 plateau in the output is this artifact, not
     real Z. (This is why 2D recall was only 24% — it mostly caught top-of-column
     points where real Z really is ~515.6, plus the sparse header records.)
  2. Y never advances inside the column (no Y record is recognized), so every
     vertex gets the stale entry-Y.
- **The splice value model is only PARTIALLY right.** It reproduces the sparse
  column-header / boundary coords, but the DENSE within-column records do NOT
  splice to GT Y or Z (off by ~0.07 on Z; Y nowhere close). Their **first payload
  byte is centered on 0x80** (Gaussian-ish, high nibbles 5–12 dominant) = the
  signature of **signed DELTA coding**, not byte-splicing. The bulk of the 3.43M
  records are delta-coded and this model is NOT yet cracked.
- SEP byte does NOT cleanly encode the Y-step (tested on an aligned column run:
  SEP 0x17 appears with Y-steps 0.25 / 0.5 / 1.0). The Y-step is likely in the
  delta payload itself.

**Honest status now:** SOLVED = container, sectioning, vertex 0, column-major
traversal structure (X = 3134 columns), sparse/header coord splice model.
OPEN (the real bulk) = the within-column **delta value model** (Y-step + Z per
vertex) — crack this and recall should jump. The earlier "coordinate VALUE model
cracked" claim was over-stated: it's the sparse records only.

**Do next (revised):** crack the within-column signed-delta encoding. Use
`brute_payload.py` / `align_sep_ystep.py` on a clean constant-X run (e.g.
8904–8983) against the GT column (`debug_colmajor.py`). Determine: is the 5-byte
payload a single signed delta (added to prev Z?), or packed (dY,dZ)? What is the
scale/zero-point (0x80=0)? New scripts this part: `debug_colmajor.py`,
`brute_payload.py`, `align_sep_ystep.py`, `trace_y_truth.py`, `boundary_hunt.py`,
`marker_census.py`, `y_changes.py`, `decode_v4.py`.

---

(Earlier part-1 note — partly superseded by the column-major finding above:)
**Do next:** decode the Y-row-advance / escape-cluster grammar at row boundaries
(use `debug_tokens.py <start> <end>` across a boundary like 8412..8470, and
`debug_gtrows.py` for the GT row structure). New scripts this session: `decode_2d.py`,
`decode_v3.py`, `profile_y.py`, `debug_tokens.py`, `debug_gtrows.py`, `debug_column.py`,
`debug_emit.py`, `count_markers.py`, `decode_recall_snap.py`, `sanity_v0.py`.
GT caches regenerate via `csv_axis_cache.py` + `gt_tupleset.py` (scratchpad is wiped
between sessions). Below is the original (pre-diagnosis) hold-point.

---

## 0. The big shift this session

For 9 months we worked only on tiny toy `.00t` files (4–8 vertices). This session
we finally got **real production data**, and it reframed everything:

- **Input `.00t`:** `C:\Users\brent\OneDrive\00AA-CURSOR_WORK\KirraChecks\Files\20200904_H1C1-0516-6334 Blast Heave.00t` (50,178,699 bytes)
- **Ground truth CSV:** `C:\Users\brent\OneDrive\Test Files\POINTCLOUDS\HEAVE_CSV.csv` (378,191,112 bytes) — a **face-based XYZ dump** (3 rows per triangle, shared verts repeated, `\r` line endings).

### Ground-truth numbers (from the CSV)
| Quantity | Value |
|---|---|
| Rows | 9,697,208 |
| Unique vertices | 1,212,592 (1,212,272 keys @ 0.01 rounding) |
| Triangles (rows/3) | ~3,232,403 |
| X | **3,134 unique** values, 60347.797 .. 60819.844 (gridded DTM) |
| Y | **2,907 unique** values, 213957.500 .. 214684.750 (gridded DTM) |
| Z | 28,012 unique values, 512.701 .. 541.988 (continuous heave height) |

X and Y are a coarse grid; Z is the real continuous data.

---

## 1. CONFIRMED (verified on production bytes)

### 1a. Container is header-directory-driven
60-byte int32 header. For the big file:
`(-1968702486, 1517057398, 2, 4, 1, 25600, 60, 0, 87289824, 0, 2, 50159345, 0, 10540, 0)`
- `[0],[1]` = magic (constant across ALL files).
- **`[11]` = geometry-end / attribute-start pointer** (= 50,159,345 here; was 10,938
  in SPHERE). Use it to BOUND the geometry blob. Scales.
- `[8]` = 87,289,824 (meaning TBD — ~9× rows, ~72× verts; not exact).
- Front of file = 4 reserved 2048-byte **directory pages** (linked-list: each page's
  first 2 bytes are an LE pointer to the next page, e.g. `3c08`=2108, `3c20`=8252).
  Payload zero-filled. **Geometry always starts at offset 8252** (object header) with
  the literal Pascal string `Created External` at **offset 8261 in EVERY file**, size
  irrelevant.

### 1b. De-paging is a DEAD END (tested and killed)
There are NO 2048-byte page headers woven through the geometry. The only paging is the
4 front directory pages, already skipped. Inside the geometry the 2048 strides are
plain `0x0000` padding. Don't revisit this.

### 1c. The geometry blob is SECTIONED (not interleaved)
```
[ 8328 ... ~25,000,000 ]   COORDINATE section (dense X/Y/Z)
[ ~25,000,000 ... 50,159,345 ]   TOPOLOGY / face section (EdgeBreaker), Z-records collapse here
[ 50,159,345 ... EOF ]   attributes (ASCII: SHADED/WIREFRAME/NAME/colour_by/LAYER...) + embedded PNG thumbnail (89 50 4E 47 ... IEND)
```
Proven by binning: Z-coordinate emission drops from ~150k/bin to ~7k/bin at bin 10
(offset ~25.08M), while topology markers jump. Coord section ≈ **3.38M coord records
≈ 3 × 1.2M verts** — the count matches.

### 1d. Vertex 0 = three full big-endian doubles
At offset 8328: `40 ed 9e 36 35 7b d9 11` / `41 0a 34 e6 28 ee 3e e7` / `40 80 1c df 53 94 c2 ac`
= **(60657.694, 214684.770, 515.609)**. All within the CSV ranges.

### 1e. Coordinate VALUE model (records produce on-grid values)
Walk the coord section. Record framing:
- `b <= 0x06` → count byte, `nb = b + 1` payload bytes follow.
- SEP bytes: `(b & 7) == 7`.  TAG bytes: `(b & 0xE0) in {20,40,60,80,A0,C0,E0}`.
- A coord record updates ONE axis:
  `new_double = BE( prev[axis][:8-nb]  ++  payload )`
  (high `8-nb` bytes from that axis's previous value; payload = low `nb` bytes).
  Then `prev[axis]` is updated. Per-axis running prev, seeded from vertex 0.
- The payload's first byte indexes the X grid: `19`→60656.79, `27`→60657.24,
  `36`→60657.69, `49`→60658.29 (even ~0.45 m steps). So X values decode EXACTLY.
- `0x60`-tag records (nb=3) are **low-byte refinements** of the current coordinate
  (decode to the same value as the preceding record), NOT new coords.

### 1f. The existing toy parser is dead for production
`python/oot_parser_v2.py` on the big file → **0 verts / 0 faces**. It reads the vertex
count as a SINGLE BYTE (`raw[anchor+7]`=129) and bounds sections by scanning ASCII
keywords. It is a toy-only parser. Do NOT try to patch it — write a new reader.

---

## 2. NOT SOLVED (the wall)

### 2a. Vertex ASSEMBLY — recall 0.00%
The killer test (`decode_recall.py`): decode the coord section with greedy grid axis
assignment, assemble (X,Y,Z) verts, intersect with the 1.2M GT vertex set.
**Result: 17 matches / 816,845 decoded. RECALL 0.00%.**

Individual X/Y/Z values land on the GT grids, but the (X,Y,Z) **triples are wrong** —
the axis assignment mis-pairs which record is X vs Z, so we pair the wrong X with the
wrong Z. "In-range" ≠ "correct." This is the same wall the toy work hit (Mystery E:
vertex pairing / axis overlap).

### 2b. The axis selector is unknown
- **SEP byte does NOT select axis** — tested on the clean coord section, every SEP is
  ~50% STAY / 25% FWD / 25% BACK = noise. The toy W2 SEP rule is toy-specific. Dead.
- **TAG byte is only partial** — `0x60`/`0x80`/`0xfd` → X at 93-100%; the `0x2x`
  family leans Z but only 55-68% pure (low-nibble gradient 0x20→Z56% .. 0x2a→Z68%).
- Neither tag, count, nor payload byte cleanly classifies X vs Z. The axis is likely
  determined by SEQUENCE/STATE (a fixed traversal cycle), not the record's own bytes.

### 2c. Topology / faces — not started
The `0x2x.. e?/f?` records in [25M..50M] are the EdgeBreaker CLERS connectivity ops.
Untouched.

---

## 3. WHERE I WAS WHEN PAUSED (the next experiment)

`python/decode_cycle.py` — testing the hypothesis that the coord stream follows a
fixed AXIS CYCLE rather than byte-determined axes:
- `0x60`-family tag → low-byte refinement of current axis (no toggle, no emit).
- Y when the Y-candidate hits the sparse Y grid (reliable, since Y grid is sparse).
- Otherwise **alternate X ↔ Z**.
- Emit a vertex on each Z; measure recall vs GT.

This was about to run (variants A/B) when we paused. **This is the first thing to run
on resume.** If recall jumps, the alternation-cycle model is right and we tune it
(Y-change handling, refinement detection). If still ~0%, the grouping is more complex
(per-scanline columnar X-run then Z-run, or a marker delimits vertices).

---

## 4. LESSONS FROM THE TOY WORK THAT TRANSFER

- **EdgeBreaker is the face model.** CLERS bits: C=`0`, R=`110`, L=`101`, E=`100`,
  S=`111`. Draco semantics: **E = branch start (stack push), S = branch end (pop)**.
  The toy decoder failed on sphere because it never modelled S. The 3.2M-triangle
  production surface WILL branch — model the stack from the start. (`EDGEBREAKER_RESEARCH.md`)
- **Never dedup before face decoding.** Faces reference exact vertex SLOTS including
  duplicates. The ~1.45-1.51M stored verts vs 1.21M unique gap is real duplicate slots
  (consistent with header offset 8296 = 1,450,044).
- **Production AVOIDS the hardest toy problem.** Toy "axis overlap" (X/Y/Z all in
  1000-1300) defeated 8 approaches. Production X≈60k, Y≈214k, Z≈515 are in DIFFERENT
  magnitude bands — non-overlapping. Easier here.
- **Leave behind the toy escape zoo.** W11–W15 escape FULLs, FULL-run mode, compact
  FULLs, escape-stripping — all artifacts of clean-integer tiny files. CONFIRMED ABSENT
  in production. Don't port them.

---

## 5. NEXT STEPS (priority order)

1. **Run `decode_cycle.py` (alternation-cycle hypothesis).** Measure recall. This is
   the live experiment. Iterate axis-cycle / refinement / Y-change rules until recall
   climbs. Target: reproduce the 1.2M vertex set.
2. **If cycle fails, study vertex grouping directly** — dump 200 records with the
   GT-confirmed axis label (via grid) and find the deterministic boundary between
   vertices (look for a per-vertex marker tag, or columnar X-run/Z-run structure per
   scanline).
3. **Lock the axis selector** so the decoder is GROUND-TRUTH-FREE (the real goal: decode
   files that have no CSV). Validate axis rule against the 1.5M labelled records.
4. **Decode the topology section [25M..50M]** with stack-based EdgeBreaker (C/L/E/R/S)
   → faces, referencing un-deduped vertex slots.
5. **Output streaming.** Only after decode works: stream verts/faces to OPFS scratch
   (`Kirra/src/helpers/ScratchBinaryFile.js` pattern) for the ~4 GB DXF/CSV export.
   Scratch disk belongs on the OUTPUT side, not input (input fits in RAM).
6. Port the working grammar into Kirra's `Maptek/oot-parser.js` (currently broken).
   **Kirra is read-only / hands-off** until the sandbox decode is proven.

---

## 6. SCRIPT INVENTORY (all in `python/`, run against the big file + CSV)

| Script | Purpose |
|---|---|
| `page_detect.py` | front page-directory probe (de-paging — dead end) |
| `depage_probe.py` | proved no page headers inside geometry |
| `section_probe.py` | ASCII runs + `e0..40 17` markers in small files |
| `bigfile_probe.py` | full structural probe of an arbitrary big `.00t` |
| `find_counts.py` | search file for GT counts + base coord (found BE doubles) |
| `decode_stream_probe.py` | first attempt to read the vertex stream |
| `count_records.py` | record framing counts |
| `csv_stats.py` | GT row/unique/range stats |
| `csv_axis_cache.py` | build per-axis sorted-unique GT arrays (gt_x/y/z.npy) |
| `gt_tupleset.py` | build GT vertex key set (gt_keys.pkl) for recall |
| `fit_harness.py` | per-axis prefix hypothesis test |
| `greedy_decode.py` | per-axis running-prev greedy decoder (94% "in-range") |
| `tag_axis_xtab.py` | tag/sep → axis cross-tab |
| `sep_transition.py` | SEP → transition (proved SEP is NOT the selector) |
| `coord_topo_position.py` | proved coord/topology SECTIONING |
| `clean_axis.py` | axis analysis on the clean coord section |
| `annotate.py` | **annotated record dump — best tool to SEE structure** |
| `decode_recall.py` | **the honest test: recall vs GT (0.00%)** |
| `decode_cycle.py` | **alternation-cycle hypothesis — RUN THIS NEXT** |

### Repro
```bash
SP="<scratchpad>"   # holds gt_x.npy gt_y.npy gt_z.npy gt_keys.pkl (regenerate via csv_axis_cache.py + gt_tupleset.py)
F="/c/Users/brent/OneDrive/00AA-CURSOR_WORK/KirraChecks/Files/20200904_H1C1-0516-6334 Blast Heave.00t"
python3 python/annotate.py "$F" "$SP" 45                       # see structure
PYTHONIOENCODING=utf-8 python3 python/decode_recall.py "$F" "$SP" 25300000   # honest recall
PYTHONIOENCODING=utf-8 python3 python/decode_cycle.py "$F" "$SP" 25300000 A  # next experiment
```
The `.npy`/`.pkl` GT caches live in the scratchpad (not committed); regenerate with
`csv_axis_cache.py` and `gt_tupleset.py` against `HEAVE_CSV.csv`.

---

## 7. ONE-LINE SUMMARY

Container, sectioning, vertex 0, and the coordinate value model are **cracked** on real
50 MB production data; the **vertex-assembly axis/pairing grammar is the open blocker**
(recall 0.00% despite on-grid values) — resume by running `decode_cycle.py`.
