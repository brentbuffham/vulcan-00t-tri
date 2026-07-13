# ROSETTA — the reference `.00t` decoder

`tri00t.rs` is the **authoritative** Rust reference decoder for the Maptek Vulcan
`.00t` triangulation format (from the Incline codebase). It is the "Rosetta stone"
that cracked the format after ~9 months of dead-end delta/EdgeBreaker reverse
engineering: a `.00t` is a **vulZ FastLZ-compressed, paged container**, and once
the pages are inflated and reassembled the geometry is plain fixed-stride binary
(120-byte header, BE `u32` counts at `0x48`/`0x60`, then absolute BE `f64`
vertices and BE `u32` face-index triples).

This file is kept here as the **source of truth**. The repo's runtime parser
`js/vulcan00TParser.js` is a JavaScript port of it; `00T_FORMAT.md` is the prose
spec. When the JS port and this file disagree, **this file wins** — reconcile the
JS to match.

Note it is dropped here as reference only — there is no `Cargo.toml`/crate wiring
in this repo. It compiles as part of the Incline project (it uses the `log` crate
and `let`-chains).

## Scope this reference covers that the JS port may not yet

- Full pointer-tree walk for multi-page containers (the 50 MB production files),
  not just single-page toy files.
- FastLZ **level 2** (extended match lengths + 16-bit far-distance escape), not
  only level 1.
- Auxiliary stream / PNG layer-preview gallery (`0x2c`/`0x34` header fields).
- Self-validating recovery for a wrong page-size field and for trailer words that
  are not logical page numbers.
- `.00t` **writing** (`write_00t_with_progress`) + build-from-vertices/faces.
