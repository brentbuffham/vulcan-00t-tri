# vulZ stale-page slot fix (`tri00t_v2.rs`)

**Status: fixed + verified.** `tri00t.rs` (v1) mis-decodes some re-saved Vulcan
`.00t` solids that Vulcan itself reads without complaint. `tri00t_v2.rs` fixes it
with a small, behaviour-preserving change to the vulZ page-tree walk.

## Symptom

`SOLID_MM_O31A_0504_8123.00t` — a re-saved solid, 741 vtx / 1475 faces per
Vulcan:

```
v1  SOLID: ERROR InvalidFaceIndices { min: 0, max: 4278190098, vertex_count: 741 }
v2  SOLID: OK verts=741 faces=1475 out_of_range_indices=0
    TARG:  OK verts=599 faces=1018 out_of_range_indices=0   (unchanged)
```

## Root cause

The container is `vulZ`: pages are compressed and reassembled at
`page_number * page_size`, addressed by a pointer tree. A page's trailer word can
be its logical number, but on these files every trailer word is `0`, so pages
place **sequentially in walk order**.

When a solid is edited and re-saved, an **old copy of a rewritten page can remain
physically in the file**, reachable inside an `advance` chain even though the
pointer tree names only the current copy. v1's `walk_page_run` numbered every
zero-numbered page from **one global `next_sequential` cursor**. A run that walked
from a tree-named page *into the stale orphan* let the orphan consume the next
sequential slot — the slot a **later** tree-named live page owned. That live page
then addressed a slot `>= total_pages`, was ignored, and its geometry was dropped.

Because the orphan still *fills* a slot, `missing_pages == 0` and neither of v1's
self-validating recoveries fires (the page-size retry needs
`missing_pages == total_pages`; the sequential retry needs
`decoded_pages == total_pages` and is deliberately gated away from stale-copy
files). The corruption is therefore **silent** — a decoded-but-wrong mesh.

SOLID concretely: pointer tree names pages `[18494, 8252, 36517]`. v1 walks
`18494`'s run into stale orphan `35198`, assigning `18494→0, 35198→1, 36517→2`;
the real page `8252` then lands in slot 3 (`> total 3`) and is dropped. Correct
order is `[18494, 8252, 36517]` (the tree-naming order).

## Fix

Anchor each run's slot counter to the **tree-naming index** of its start page —
the order pages are listed by the pointer tree's leaf blocks — instead of a single
global cursor:

- `push_pointer_block(&mut self, …, record_tree_index)` records, in walk order, the
  index of each page-header target (a record whose `second`/`advance` word is
  non-zero). `record_tree_index` is **true only for the data walk**; the aux
  stream (PNG gallery) is a separate page space and must not consume data slots.
- `walk_page_run` starts `run_slot` from `tree_index[start]` (falling back to the
  global `next_sequential` for flat/older files whose root points straight at a
  contiguous run, and for the `ignore_numbers` recovery). Tree-named pages then
  always land in their own slot; run-scanned continuations flow on from there, and
  a stale orphan can no longer displace a live page.

The change is inert for every non-stale file (tree-naming order already equals
sequential order there), so v1's fixtures and both real files above decode
identically or better.

## Verify

```
rustc --edition 2024 tri00t_v2.rs   # + a small main calling Triangulation::from_path
```

The JS port carries the identical fix (`kirra/src/fileIO/Maptek/vulcan00TParser.js`,
`VulzWalk.treeIndex`) with a regression test that builds a synthetic stale-orphan
container. See `00T_FORMAT.md` §2.4.
