---
name: vulcan-00t
description: >-
  Maptek Vulcan .00t triangulation binary format. SOLVED: the file is a vulZ
  FastLZ-compressed paged container; decompress then read plain big-endian f64
  vertices + u32 face-index triples (see 00T_FORMAT.md; parser is
  js/vulcan00TParser.js; authoritative write-up in the vulcan-00t-tri GitHub
  wiki). Sibling Vulcan formats are cracked too: .dgd.isis design DBs (same vulZ
  container) and .bmf/.bdf block models — see ROSETTA/{tri00t,isis,bmf}.rs and the
  js/vulcan{Isis,Bmf}Parser.js ports. Trigger whenever the work touches: .00t
  files, Vulcan/Maptek triangulation, .bmf/.bdf block models, .dgd.isis design
  DBs, vulcan00TParser, or building Vulcan-format support for Kirra. NOTE: the old
  coord TAG/DELTA grammar, axis state machine, and EdgeBreaker/CLERS face decode
  are DISPROVEN historical context — do not resume them; go straight to
  00T_FORMAT.md.
---

# Vulcan .00t reverse-engineering

> **✅ FORMAT SOLVED — STOP. Read [`00T_FORMAT.md`](../../../00T_FORMAT.md) first.**
> The `.00t` is a `vulZ` **FastLZ-compressed paged container**. Decompress it
> (8-byte-record pointer-tree walk → FastLZ-inflate each page → reassemble at
> `page_number × page_size`) and the geometry is plain fixed-stride binary:
> absolute **big-endian f64** vertex triples + explicit **big-endian u32**
> face-index triples. There is **no** coordinate TAG/DELTA grammar, **no** axis
> state machine, and **no** EdgeBreaker/CLERS face decode — every one of those
> was this project reverse-engineering the *compressor's output* as if it were
> the data model. The working parser is `js/vulcan00TParser.js`; it decodes all
> fixtures exactly (100% verts + faces vs DXF, including the 10 201-vertex grid).
> Everything below is **historical context only** — do not resume the grammar
> hunt.

## The answer (SOLVED 2026-07-13)

A `.00t` is a **`vulZ` FastLZ-compressed, paged container**. Inflate it, and the
geometry underneath is plain fixed-stride binary:

```
.00t file
├─ starts with vulZ magic (EA FB A7 8A "vulZ")  → compressed container
│     └─ walk the 8-byte pointer tree, FastLZ-inflate each page,
│        reassemble at page_number × page_size  →  "raw image":
│           120-byte header (LITTLE-endian)
│           vertex_count : BE u32 @ 0x48
│           face_count   : BE u32 @ 0x60
│           N × (3 × BE f64)                     absolute vertices
│           M × (3 × BE u32 + 12-byte payload)   1-based face indices
│           trailing ASCII attributes + optional PNG thumbnail
└─ else → already a flat raw image
```

**Endianness quirk:** the container header is little-endian; the geometry fields
inside the decompressed image are big-endian. `.dgd.isis` design DBs use the SAME
`vulZ` container; `.bmf`/`.bdf` block models use a separate uncompressed 0x808 page
container.

**Do not re-derive — use the shipped code:**
- Reference decoder (source of truth): `ROSETTA/tri00t.rs` (siblings: `bmf.rs`,
  `isis.rs`).
- Spec: `00T_FORMAT.md`.
- JS parser / writer: `js/vulcan00TParser.js`, `js/vulcan00TWriter.js`
  (+ `js/vulcanBmfParser.js`, `js/vulcanIsisParser.js`).
- Python parser: `python/vulcan00t_parser.py` (DXF export: `python/oot_to_dxf.py`).

Verified against every fixture in `exampleFiles/` — 100% of vertices and 100% of
face topology, including a 10,201-vertex / 20,000-face grid. **Authoritative
write-up: the `vulcan-00t-tri` GitHub wiki (`Home` + `Post-Mortem`).**

## EdgeBreaker doesn't apply to `.00t` — do not resume it here

EdgeBreaker/CLERS is a real, useful mesh-connectivity compression algorithm (see
the separate **`edgebreaker` skill** for the actual algorithm — Draco/glTF use it).
It is simply **NOT what `.00t` uses**: `.00t` stores explicit big-endian u32 index
triples, no connectivity codec at all.

For ~9 months this project reverse-engineered the **compressed** byte stream as if
it were the data model. FastLZ control bytes looked like "tag classes"
(`0x20/0x40/0x60`), literal runs looked like "FULL/DELTA coordinate values", and
match ops looked like "EdgeBreaker/CLERS" faces + "SEP" bytes. **There is NO
coordinate TAG/DELTA grammar, NO axis state machine, and NO EdgeBreaker/CLERS face
codec** — the whole apparatus (coord "WINS" W1–W15, the cube gate-shift sequence,
the S/side/strip/rail work, the Z-surface predictor, "Mystery A/E") was fitting
FastLZ noise with per-file special cases and never generalized.

The lesson (see `Post-Mortem` / `RETIRED.md`): when a binary format shows a **magic
string** and your decoded "grammar" needs **per-file exceptions** and **won't
generalize**, suspect a **compression/container layer before inventing a value
grammar**, and get real production data + ground truth early.

Kept for the record only (NOT instructions): `HistoryOfTests.md`, `WINS.md`,
`EDGEBREAKER_RESEARCH.md`, `CUBE_GRAMMAR_RESEARCH.md`, `SESSION_SUMMARY.md`,
`STRIP_SCHEDULE.md`, `Z_RECONSTRUCTION_HUNT.md`, the `python/side*/strip*/col*`
scripts, `reference/RESUME-2026-07-12.md`. `RETIRED.md` + `TRIAGE.md` explain what
was superseded. Historical memory (do not treat as live):
`[[project_edgebreaker_findings]]`, `[[project_coord_codec_cracked]]`,
`[[project_topology_refs_cracked]]`, `[[project_coord_order_breakthrough]]`.
