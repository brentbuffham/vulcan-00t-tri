# RETIRED — pre-2026-07-13 parser work

**Cutoff: all `.00t` parser work from before 2026-07-13 ~01:00 is RETIRED.**

The format is SOLVED (see [`00T_FORMAT.md`](00T_FORMAT.md)): a `.00t` file is a
`vulZ` **FastLZ-compressed, paged container**. Decompress it and the geometry is
plain fixed-stride binary — absolute big-endian `f64` vertices and big-endian
`u32` face-index triples. There is **no** delta/tag coordinate grammar and **no**
EdgeBreaker/CLERS face encoding. Every pre-cutoff "rule" was pattern-fitting the
**compressed** byte stream (FastLZ control bytes and back-references) as if it were
the data model. See [`TRIAGE.md`](TRIAGE.md) for the full post-mortem.

## Canonical parser (USE THESE)

| Role | File |
|---|---|
| Reference decoder (source of truth) | `ROSETTA/tri00t.rs` |
| Format spec | `00T_FORMAT.md` |
| JS runtime parser | `js/vulcan00TParser.js` |
| JS writer | `js/vulcan00TWriter.js` |
| Python runtime parser | `python/vulcan00t_parser.py` |

All five viewers (`js/oot-read.html`, `js/oot-compare.html`, `js/oot-viewer.html`,
`js/oot_to_dxf.html`, `js/intercepts_compare.html`) and the Python CLI
(`python/oot_to_dxf.py`) now use the canonical parser.

## Retired (DO NOT USE / DO NOT RESUME)

- **Old parser entry points** — moved to `RETIRED/`:
  - `RETIRED/oot_parser_v2.py` (toy-only Python parser; was 0 verts on production)
  - `RETIRED/oot-parser.js` (toy-only JS parser)
  - `RETIRED/spirale-reversi-sketch.js` (EdgeBreaker/CLERS stack sketch)
- **Python research corpus (~330 scripts in `python/`)** — the delta / axis /
  EdgeBreaker / splice / ref-index experiments (`decode_v*.py`, `axis_*.py`,
  `ma_*.py`, `refhunt*.py`, `zhunt*.py`, `deterministic_*.py`, `face_*.py`,
  `coord_*.py`, `topo_*.py`, and the rest) plus their `*.npy`/`*.pkl`/`*.csv`
  artifacts. Historical only. **8 of them import the moved `oot_parser_v2` and no
  longer run** — this is intended; they are not to be resurrected.
- **Root research docs** — historical only, superseded by `00T_FORMAT.md`:
  `DECODING.md`, `CUBE_GRAMMAR_RESEARCH.md`, `CUBE_LOOP_PLAN.md`,
  `DRIFT_BAND_FINDINGS.md`, `EDGEBREAKER_RESEARCH.md`, `FIRST500_FINDINGS.md`,
  `HistoryOfTests.md`, `K0_RULE_RESULTS.md`, `MISFRAME_CENSUS.md`,
  `MYSTERY_A_HUNT.md`, `PARALLELOGRAM_PROOF.md`, `REFERENCE_COLUMN_HUNT.md`,
  `REF_INDEX_DECODE.md`, `SELECTOR_HUNT.md`, `SESSION_SUMMARY.md`,
  `SLOT_ALIGNMENT.md`, `SPHERE_LOOP_PLAN.md`, `VALUE_SPLICE_HUNT.md`,
  `VULCAN-RESUME.md`, `WINS.md`, `Z_RECONSTRUCTION_HUNT.md`, `COLD_VALIDATION.md`,
  `TODO.md`.

The retired research is kept in git history for the record; it should not guide any
future work. If you are picking this up: read `00T_FORMAT.md`, then `TRIAGE.md`.
