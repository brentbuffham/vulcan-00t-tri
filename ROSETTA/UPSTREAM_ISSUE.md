# Upstream issue draft — `tri00t.rs` vulZ stale-page slot bug

Ready to paste into the Incline repo's issue tracker. The fixed decoder lives
next to this file as `tri00t_v2.rs`; the root-cause writeup is `STALE_PAGE_FIX.md`.

---

## `vulZ` page-tree walk drops a live page when a stale orphan page shares an `advance` chain — silent geometry corruption

### Summary

The vulZ page reassembly (`VulzWalk`) assigns zero-numbered pages from a **single
global `next_sequential` cursor** in walk order. When a `.00t` has been edited and
re-saved, an **old copy of a rewritten page can remain physically in the file**,
reachable inside an `advance` chain even though the pointer tree names only the
*current* copy. A run that walks from a tree-named page *into that stale orphan*
lets the orphan consume the next sequential slot — the slot a **later tree-named
live page** owns. The live page then addresses a slot `>= total_pages`, is
ignored, and its geometry is dropped.

Because the orphan still *fills* a slot, `missing_pages == 0`, so **neither
self-validating recovery fires** and the corruption is **silent** (a
decoded-but-wrong mesh, or an `InvalidFaceIndices` error downstream). Vulcan
itself reads these files fine.

### Reproduction

A re-saved solid (741 vtx / 1475 faces per Vulcan):

```
v1  ERROR InvalidFaceIndices { min: 0, max: 4278190098, vertex_count: 741 }
```

The pointer tree names pages `[18494, 8252, 36517]`, but page `18494`'s `advance`
chain runs `18494 → 35198 (stale orphan) → 36517`. The walk assigns
`18494→slot0, 35198→slot1, 36517→slot2`, so the real page `8252` gets `slot3`
(`> total 3`) and is discarded. Correct reassembly is the **tree-naming order**
`[18494, 8252, 36517]`.

> The triggering file is proprietary site data, but the shape is reproducible
> synthetically: build a 2-page vulZ container whose page-0 `advance` points at a
> full-size garbage page before the tree's second leaf entry.

### Why the existing recoveries miss it

- **Page-size retry** requires `missing_pages == total_pages` — but every slot is
  filled (one wrongly), so `missing_pages == 0`.
- **Sequential-in-walk-order retry** requires `decoded_pages == total_pages` and
  is *deliberately* gated away from stale-copy files (`decoded_pages` here is 4 vs
  `total 3`).

### Root cause (v1)

`walk_page_run` numbers pages from the shared cursor:

```rust
let slot = if self.ignore_numbers || page.number == 0 {
    self.next_sequential          // ← global, order-dependent
} else {
    page.number
};
if slot < self.total_pages {
    if from_tree || !self.tree_covered[slot] { /* place */ }
    self.next_sequential = slot.saturating_add(1);   // ← orphan advances it
}
```

The `from_tree || !tree_covered[slot]` guard prevents a stale page from
*overwriting* a claimed slot, but not from *stealing the slot number* a later
tree-named page needs.

### Fix

Anchor each run's slot counter to the **tree-naming index** of its start page
(the order pages are listed by the pointer tree's leaf blocks), instead of the
global cursor. Tree-named pages then always land in their own slot; run-scanned
continuations flow on from there. Flat/older files (start page not individually
tree-named) and the `ignore_numbers` recovery fall back to the global cursor — so
behaviour is unchanged for every non-stale file.

**1. Struct fields** (`VulzWalk`):

```rust
    placed_at: std::collections::HashMap<usize, usize>,
+   /// page-record offset -> its slot in tree-naming order (leaf-block order).
+   tree_index: std::collections::HashMap<usize, usize>,
+   tree_index_counter: usize,
    next_sequential: usize,
```

…and initialise `tree_index: HashMap::new(), tree_index_counter: 0` at
construction.

**2. `push_pointer_block`** — record page targets in tree order (data walk only;
the aux/PNG-gallery walk shares this method and must **not** consume data slots):

```rust
-   fn push_pointer_block(&self, offset: usize, stack: &mut Vec<usize>) {
+   fn push_pointer_block(&mut self, offset: usize, stack: &mut Vec<usize>, record_tree_index: bool) {
        // … existing target-collection loop unchanged …
+       if record_tree_index {
+           for &target in &targets {
+               // a page record's `second`/advance word is non-zero; a nested
+               // pointer block's is zero.
+               let is_page = target
+                   .checked_add(4)
+                   .and_then(|at| read_le_u32(self.bytes, at).ok())
+                   .is_some_and(|second| second != 0);
+               if is_page && !self.tree_index.contains_key(&target) {
+                   self.tree_index.insert(target, self.tree_index_counter);
+                   self.tree_index_counter += 1;
+               }
+           }
+       }
        stack.extend(targets.into_iter().rev());
    }
```

Call sites:

```rust
// in walk_data:
-   self.push_pointer_block(offset, &mut stack);
+   self.push_pointer_block(offset, &mut stack, true);   // data walk records tree index
// in walk_aux:
-   self.push_pointer_block(offset, &mut stack);
+   self.push_pointer_block(offset, &mut stack, false);  // aux is a separate page space
```

**3. `walk_page_run`** — start the run's slot from its tree index:

```rust
    fn walk_page_run(&mut self, mut offset: usize) {
        let mut from_tree = true;
+       let mut run_slot = if self.ignore_numbers {
+           self.next_sequential
+       } else {
+           self.tree_index.get(&offset).copied().unwrap_or(self.next_sequential)
+       };
        loop {
            // …
-           let slot = if self.ignore_numbers || page.number == 0 { self.next_sequential } else { page.number };
+           let slot = if self.ignore_numbers || page.number == 0 { run_slot } else { page.number };
            if slot < self.total_pages {
                if from_tree || !self.tree_covered[slot] { /* place */ }
-               self.next_sequential = slot.saturating_add(1);
+               run_slot = slot.saturating_add(1);
+               self.next_sequential = self.next_sequential.max(slot.saturating_add(1));
            }
            // …
        }
    }
```

> ⚠️ Gotcha: `walk_aux` also calls `push_pointer_block`, and it runs **before**
> `walk_data`. Without the `record_tree_index` flag, the aux (PNG gallery) pointer
> tree pollutes `tree_index` first and shifts every data page's index by one —
> regressing files that previously worked.

### Verification

```
v2  SOLID: OK verts=741 faces=1475 out_of_range_indices=0
v2  TARG:  OK verts=599 faces=1018 out_of_range_indices=0   (unchanged from v1)
```

- **SOLID** (stale-orphan file): v1 `InvalidFaceIndices` → v2 decodes fully,
  matching Vulcan's own 741/1475.
- **TARG** (clean file that already worked): identical under v1 and v2 — the change
  is inert when tree-naming order already equals sequential order (every non-stale
  file), for flat/older files, and for the `ignore_numbers` recovery.

### Scope / risk

- Touches only `VulzWalk` (struct + `push_pointer_block` + `walk_page_run`). No
  format, API, or public-behaviour change for correctly-decoding files.
- Adds one `HashMap<usize, usize>` + `usize` to the walk state; O(1) per page.
- The only behavioural change is *which slot a zero-numbered page is placed in when
  a run walks past the file's live page set* — previously order-of-traversal, now
  tree-naming order (authoritative per the format's own "the tree names the current
  copy" rule).

### Suggested labels

`bug`, `decoder`, `data-corruption`
