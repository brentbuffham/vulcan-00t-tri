# ROSETTA — reference decoders for Vulcan file formats

The "Rosetta stone" reference decoders (Rust, from the Incline codebase) that
cracked several Maptek Vulcan binary formats after ~9 months of dead-end
reverse engineering. They are the **source of truth**; the runtime parsers in
this repo (`js/`, `python/`) are ports. When a port and a file here disagree,
**these files win** — reconcile the port to match.

These are dropped here as reference only — there is no `Cargo.toml`/crate wiring
in this repo. They compile as part of the Incline project (they use `glam`,
`memmap2`, `log`, `let`-chains, and reference sibling `crate::` modules).

## Files

| File | Vulcan format | What it decodes |
|---|---|---|
| `tri00t.rs` | `.00t` triangulation | vulZ/FastLZ container → BE f64 vertices + u32 face triples. See `../00T_FORMAT.md`. |
| `bmf.rs` | `.bmf` / `.bdf` block model (TBMS2.0) | 0x808-paged container, page-table tree, per-variable numeric/named columns, block bounds, orientation. |
| `isis.rs` | `.dgd.isis` / `.dgd.isix` design database | vulZ container → 117-byte SEGCRD records: polylines, text, layers, colour palette, index sidecar. |

## The shared key: `vulZ`

`tri00t.rs` and `isis.rs` are both **vulZ FastLZ-compressed** containers —
`isis.rs` imports `decode_vulz_archive`/`VULZ_MAGIC` straight from `tri00t.rs`.
That shared compression layer is exactly what the pre-2026-07-13 `.00t` work
missed: it read the *compressed* stream as the data model and invented a
delta/tag/EdgeBreaker grammar out of FastLZ opcodes (see `../TRIAGE.md` and the
wiki Post-Mortem). `bmf.rs` uses a different, uncompressed 0x808-page container.

## Scope these references cover that the ports may not yet

- Full multi-page pointer-tree walk (production-scale files), FastLZ level 2,
  auxiliary/PNG streams, and self-healing recovery paths (`tri00t.rs`).
- `.00t` **writing** (`tri00t.rs::write_00t_with_progress`).
- Block-model variable decoding, bounds, and bearing/dip/plunge orientation
  (`bmf.rs`); design polylines/text/layers/palette (`isis.rs`).
