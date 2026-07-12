# Maptek Vulcan `.00t` Triangulation Format — Specification

**Status: SOLVED.** The `.00t` file is a `vulZ` FastLZ-compressed, paged container.
Decompress it and the geometry underneath is a plain fixed-stride binary
structure — absolute IEEE-754 vertices and explicit integer face-index triples.
There is **no** delta/tag coordinate grammar and **no** EdgeBreaker/CLERS
connectivity encoding; those earlier hypotheses were the result of reading the
*compressed* byte stream as if it were the data model.

This spec is verified against every fixture in `exampleFiles/` (100% of
vertices and 100% of face topology reproduced vs the paired DXF), including a
10 201-vertex / 20 000-face 18-page grid. Reference implementations:
`js/vulcan00TParser.js` (production) and `python/` ports.

> **Endianness quirk (read this first).** The **container** header fields are
> **little-endian**. The **geometry** fields inside the decompressed image
> (counts, vertex doubles, face indices) are **big-endian**. Do not assume one
> endianness for the whole file.

---

## 1. Top-level structure

```
.00t file
├── if it starts with the vulZ magic  → compressed container (§2)
│      └── decode → "raw image" (§4)
└── else                              → already a flat "raw image" (§4)
```

A real Vulcan `.00t` is always the compressed form. The flat raw form is what
you get after decompression (and what a writer emits before compression).

---

## 2. `vulZ` container

### 2.1 Magic

```
offset 0x00 : EA FB A7 8A 76 75 6C 5A     "….vulZ"   (8 bytes)
```

### 2.2 Container header fields (little-endian)

| Offset | Size | Field | Meaning |
|-------:|-----:|-------|---------|
| `0x14` | u32 | `page_size` | logical page size in bytes (validated `1024 … 4 194 304`) |
| `0x20` | u64 | `total_expanded_len` | total logical image length (the reassembled raw bytes) |
| `0x2c` | u32 | `aux_offset` | file offset of the auxiliary stream's pointer tree (0 = none) |
| `0x34` | u32 | `aux_len` | expanded length of the auxiliary stream |
| `0x3c` | — | `walk_start` | offset where the **data** pointer-tree walk begins |

`total_pages = ceil(total_expanded_len / page_size)`. The reassembled image is
`total_expanded_len` bytes; page *n* occupies `[n·page_size, (n+1)·page_size)`.

### 2.3 Record model

The container body is a tree of **8-byte records** `(first, second)`, both
little-endian u32:

* **Pointer block** — `second == 0`. Up to `0x800 / 8 = 256` consecutive
  entries `(target, 0)`, each `target` pointing at another pointer block or at a
  page header. A `target` of 0, or an entry whose `second != 0`, terminates the
  block.
* **Page header** — `second != 0`, interpreted as `(stored_len, advance)`:
  * `stored_len` — bytes of the stored (compressed) FastLZ stream that follows.
  * `advance` — distance from the header to the next back-to-back page; spans
    the stored data **plus** a trailer. Constraints:
    `advance != 0`, `stored_len ≤ 4 MiB`, `advance ≥ stored_len`,
    `advance ≤ stored_len + 0x4000`, `header+8+stored_len ≤ file length`.

Immediately after the stored stream is a trailer. Its first word is the page's
**logical page number** (little-endian u32) — unless it is the end-of-page
marker `FA FB FC FD` (`0xFDFCFBFA` as an LE word) or absent, in which case the
number is treated as 0.

### 2.4 Walk algorithm

Authoritative source: the pointer tree. Walk it from `walk_start` (data) and
from `aux_offset` (auxiliary stream, walked first so gallery pages aren't
swallowed):

```
stack = [start]
while stack not empty:
    off = stack.pop()
    if already visited: (if it was run-scanned, mark its slot tree-authoritative); continue
    mark visited
    second = u32_le(off + 4)
    if second == 0:  push the block's targets (in block order)
    else:            walk_page_run(off)
```

`walk_page_run(off)`:

```
from_tree = true
loop:
    (stored_len, advance) = header(off)
    payload = fastlz_decompress(bytes[off+8 : off+8+stored_len])   // §3
    number  = trailer word at off+8+stored_len (0 if end-marker/absent)
    if payload.len == page_size:
        slot = (number == 0) ? next_sequential : number
        if slot < total_pages and (from_tree or slot not already tree-covered):
            copy payload into image at slot·page_size
        next_sequential = slot + 1
    off = off + 8 + advance
    if off is not another page header: break        // likely a table the tree also references
    from_tree = false                               // subsequent pages in the run are run-scanned
```

Notes:
* **Stale copies.** Rewritten pages can leave old versions in the file. The tree
  names the current copy; a run-scanned page never overwrites a tree-referenced
  slot.
* **Older/flat files** point the root straight at the first page of a contiguous
  run; run-scanning covers them.
* A decode is **complete** only if every one of `total_pages` slots was filled.
  A hole means corruption (triangulations are stored contiguously).

The reference decoder also has two self-validating recoveries (retry with the
observed page length if the header's `page_size` disagrees with the data; retry
placing pages sequentially if trailer words are not usable page numbers), each
accepted only if it then covers every page. These are robustness measures, not
part of the normal path.

### 2.5 Auxiliary stream

`aux_offset`/`aux_len` describe a second, smaller pointer tree outside the
page-numbered space. In design databases it holds the PNG layer-preview gallery
(and layer names). For plain triangulations it is typically empty and can be
ignored.

---

## 3. FastLZ codec (per page)

Each page's stored stream is one FastLZ block (LZ77 family). The compression
**level** is carried in the **top three bits of the first control byte**:
`0 → level 1`, `1 → level 2`. Level 2 adds an extended match-length loop and a
16-bit far-distance escape.

Decode loop (the first op's level bits are masked off; the first op is always a
literal run):

```
control = next byte
if control < 32:                       // LITERAL RUN
    len = control + 1
    copy len literal bytes to output
else:                                  // BACK REFERENCE
    len = control >> 5
    ref = (control & 0x1f) << 8
    if len == 7:                       // extended length
        loop: code = next byte; len += code
              break unless (level2 and code == 255)
    code = next byte
    ref += code
    if level2 and code == 255 and (control & 0x1f) == 0x1f:   // far match
        ref = (next_byte << 8) + next_byte + 8191
    len += 2
    src = output.len - ref - 1         // copy is overlap-safe (byte by byte)
    copy len bytes from output[src…] to output
```

Match copies must be performed **byte by byte** because source and destination
can overlap (the standard LZ run-length trick).

---

## 4. Raw image layout (after decompression)

All multi-byte geometry values are **big-endian**.

```
0x00              120-byte header
0x48   u32 (BE)   vertex_count
0x60   u32 (BE)   face_count
0x78              vertices[vertex_count]      each 24 bytes  (§4.1)
…                 faces[face_count]           each 24 bytes  (§4.2)
…                 trailing attributes                        (§4.3)
```

`face_section_start = 120 + vertex_count·24`
`trailer_start       = face_section_start + face_count·24`

### 4.1 Vertex record (24 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| `+0`  | f64 (BE) | X |
| `+8`  | f64 (BE) | Y |
| `+16` | f64 (BE) | Z |

Coordinates are **absolute** doubles (no delta, no truncation). Reject
non-finite values. Coordinates are model-space, often large real-world values
(e.g. easting ≈ 27 170, northing ≈ 157 410) — center on the bounding box for
rendering.

### 4.2 Face record (24 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| `+0`  | u32 (BE) | index A |
| `+4`  | u32 (BE) | index B |
| `+8`  | u32 (BE) | index C |
| `+12` | 12 bytes | opaque payload (attributes/color; preserved, not interpreted) |

### 4.3 Index base

Indices may be 0-based or 1-based. Vulcan writes **1-based** canonically; detect:

* `min == 0 && max <  vertex_count` → **0-based**
* `min >= 1 && max <= vertex_count` → **1-based**
* otherwise → invalid (indices out of range)

When the mesh references neither index 0 nor the last vertex, both
interpretations are in-range; prefer 1-based (the Vulcan convention).

### 4.4 Trailing attributes

After the face section: ASCII attribute tokens (`NAME`, `SHADED`, `WIREFRAME`,
`USE_ICOLOUR`, layer/path strings, `UserAttributes`, …) and, in some files, an
embedded PNG thumbnail (`89 50 4E 47 … IEND`). A full key/value parse is
optional for geometry consumers.

### 4.5 Closure-duplicate vertices

Some meshes store a trailing vertex equal to the first (a closure vertex), so
`vertex_count` can exceed the number of geometrically distinct points (e.g. the
toy triangle stores 4 vertices for 3 corners). This is genuine file content and
faces index into the **full** list — keep all vertices for correct indexing;
dedupe only for display if desired.

---

## 5. Writing (`.00t` output)

To emit a raw image: 120-byte header with `vertex_count`@`0x48` and
`face_count`@`0x60` (BE u32), then BE-f64 vertex triples, then face records.
Emit indices as **1-based** (canonical Vulcan form) so a 0-based mesh that
happens not to reference vertex 0 cannot be misdetected on reload. Preserve the
12-byte face payload and trailing attributes for round-trip. (Compressing back
into a `vulZ` container is a separate step and not required to interoperate with
consumers that read the raw form.)

Reference writer: `js/vulcan00TWriter.js` (`write00t({vertices, faces})` →
`ArrayBuffer`); its output round-trips through `parse00t()`.

---

## 6. Verification

Decoded with `js/vulcan00TParser.js`, scored against the paired DXF
(`3DFACE` entities). Vertices: 100% coverage. Faces (unordered coord-triple
match):

| Fixture | Verts | Faces | Face match vs DXF |
|---------|------:|------:|------------------:|
| triangle | 4 | 1 | 1/1 |
| prism | 5 | 2 | 2/2 |
| 4-sides prism | 8 | 6 | 6/6 |
| fan | 16 | 6 | 6/6 |
| hexhole | 12 | 12 | 12/12 |
| nonround | 16 | 14 | 14/14 |
| sphere | 50 | 96 | 96/96 |
| stepped pyramid | 20 | 18 | 18/18 |
| L-shape | 12 | 20 | 20/20 |
| solid cube | 8 | 12 | 12/12 |
| big grid | 10 201 | 20 000 | (18 pages, 0 missing) |

---

## 7. Provenance

The container + FastLZ decode model is ported from the Incline project's
`tri00t.rs` reference decoder. Earlier reverse-engineering in this repository
(the coordinate TAG/SEP/count/DELTA grammar and the EdgeBreaker/CLERS face
decoder, documented in `HistoryOfTests.md`, `DECODING.md`, `README.md`) was
operating on the compressed byte stream and is superseded by this spec.
