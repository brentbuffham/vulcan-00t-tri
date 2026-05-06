# EdgeBreaker Research — Cross-Reference Findings

## Sources

1. **Original EdgeBreaker** (Rossignac 1999) — PDF binary couldn't be parsed via WebFetch.
2. **CLERS bit table** (confirmed from secondary sources):
   - C = `0` (1 bit)
   - R = `110` (3 bits)
   - L = `101` (3 bits)
   - E = `100` (3 bits)
   - S = `111` (3 bits)
3. **Google Draco `mesh_edgebreaker_decoder_impl.cc`** — direct source code, fetched.

## Op semantics (from Draco, verbatim)

| Op | Boundary mutation | Stack op | Notes |
|---|---|---|---|
| **C** | `active_corner_stack.back() = corner` | none | Update top of active stack |
| **R / L** | `active_corner_stack.back() = corner; check_topology_split=true` | none | Same as C update; flag for split |
| **E** | `active_corner_stack.push_back(corner); check_topology_split=true` | **PUSH** | Branch START |
| **S** | `active_corner_stack.pop_back();` then maybe restore from `topology_split_active_corners`; then `active_corner_stack.back() = corner` | **POP + maybe push** | Branch END / merge |

**Critical insight:** EdgeBreaker is a stack-based recursive traversal. **E = branch start, S = branch end.** Our current `EdgeBreakerDecoder` has a `stack` field but never pushes/pops. We're treating it as a linear walk, which works for simple genus-0 closed shapes (cube) but breaks for anything with branching topology (sphere, hexhole hole, L-shape interior corner).

## Implications for OOT

1. **Sphere likely uses E and S ops.** A sphere with 96 faces and 50 verts has lots of branching potential. If we don't model S, the gate eventually walks into already-decoded territory and produces wrong faces. Currently SPHERE somehow gets 96 faces (count match) but vertex match is 2/50 — likely vertex POSITION is wrong due to axis assignment, not topology.

2. **Cube without S works because it's small and convex.** Our hardcoded `CUBE_SEQ` traverses cube's 12 faces in a linear spiral with no branching needed (single E at the end to close).

3. **The S op is what we don't model.** If 4-Prism, Hexhole, L-Shape produce wrong face counts/topology, S is a candidate culprit.

## Cube byte-pattern ↔ op-type partial mapping

From the cube's 11 face-generating ops (matched against our hardcoded `CUBE_SEQ`):

| pos | tag | lo_nib | c_remain | hardcoded type | hypothesis |
|----|-----|--------|----------|----------------|------------|
| 0 | 40:17 | 7 | 5 | C | lo=7 + c>0 → C |
| 1 | C0:5b | B | 4 | C | lo=B → C-eligible |
| 2 | 40:2b | B | 3 | C | |
| 3 | 40:43 | 3 | 2 | R | lo=3 → R-only |
| 4 | 40:5b | B | 2 | C | |
| 5 | E1:07 | 7 | 1 | C | lo=7 + c>0 → C |
| 6 | 40:17 | 7 | 0 | R | lo=7 + c=0 → R (degraded from C) |
| 7 | 40:33 | 3 | 0 | R | |
| 8 | C0:43 | 3 | 0 | R | |
| 9 | 40:3f | F | 0 | R | lo=F → R |
| 10 | 40:13 | 3 | 0 | E | lo=3 + last → E |

**Tentative rule (cube only):**
- `lo_nib ∈ {7, B}` AND `c_ops_remaining > 0` → **C**
- `lo_nib ∈ {7, B}` AND `c_ops_remaining = 0` → **R** (degraded)
- `lo_nib = 3` → **R** (or **E** if final op)
- `lo_nib = F` → **R**
- `lo_nib not in {3, 7, B, F}` → unknown (would need more data)

**Caveat:** This rule fits cube's 11 ops but **may not generalize**. Quick check against 4-Prism's face section ops (after misalignment fix): `40:ef`, `40:1b` (finalizer), `40:0f`, `40:13`, `40:0b`, `40:17`, `40:1f` — non-finalizer non-leading ops are `40:0f, 40:13, 40:0b, 40:17, 40:1f`. With cube rule:
- 0f → R
- 13 → R (lo=3)
- 0b → C-eligible
- 17 → C-eligible
- 1f → R (lo=F)

Only 2 C-eligible. But 4-prism needs 5 C ops (n_verts=8, init=3). **Cube rule doesn't fit 4-prism.**

So either:
- The rule needs more context (sep byte? hi_nib? prev-op state?)
- 4-prism uses S or L ops we're not modeling
- The op-type encoding differs by file

## Action items

1. **Implement S op handling** in `EdgeBreakerDecoder` — push/pop active corner stack. Validate against cube + 4-prism without breaking solved files.
2. **Cross-check cube rule against more files.** If lo_nib classification holds with refinements, it's a real rule.
3. **The gate-shift cube sequence (-1,-1,+1,0,0,-1,-2,-1,0,0,0) is still unmapped** — Draco's source uses corner-table indexing that doesn't directly translate to our gate-shift model. This needs more work, possibly a different decoder framing (corner table instead of bnd list).

## Useful sources

- Draco source: `github.com/google/draco/blob/main/src/draco/compression/mesh/mesh_edgebreaker_decoder_impl.cc`
- EdgeBreaker website: `faculty.cc.gatech.edu/~jarek/edgebreaker/`
- CLERS bit table confirmed from Wikipedia + secondary refs.
