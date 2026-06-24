# VULCAN-RESUME — Production .00t decode (hold point)

**Date:** 2026-06-25
**Status:** Container + coordinate VALUE model cracked on a real 50 MB production
triangulation. Vertex ASSEMBLY is NOT solved (recall 0.00% — see below). This
document is the pick-up point.

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
