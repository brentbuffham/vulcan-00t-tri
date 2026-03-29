# Decoding Vulcan .00t Triangulation Files

**Step-by-step guide to the reverse-engineered binary format.**

This document describes how to read a Maptek Vulcan `.00t` triangulation file and extract vertices and faces without the Vulcan SDK or licence. The format was reverse-engineered through binary analysis of test files with known geometries.

---

## 1. File Header (offset 0x0000)

```
Offset  Size  Field
0x00    4B    Magic bytes: EA FB A7 8A
0x04    4B    Signature: ASCII "vulZ"
0x20    4B    Data size (LE uint32)
0x3C    4B    First page pointer (LE uint32)
```

Validate the magic bytes and signature before proceeding.

## 2. Find the Data Section

The file uses a page-chain structure (2048-byte linked pages). The actual data starts after the `"Created External\0"` and `"Variant\0"` strings, typically around offset `0x2040`.

**Search for** `Variant\0` (bytes `56 61 72 69 61 6E 74 00`). The data section begins immediately after this marker.

```
data_start = variant_index + 8
```

## 3. Pre-Coordinate Header (23 bytes at data_start)

```
Offset  Field
+12     Vertex/coord count (1 byte)
+19     Face/triangle count (1 byte)
+22     Constant 0x14
```

Note: the "vertex count" here counts unique coordinate values, not 3D vertices. The actual 3D vertex count may differ.

## 4. Find Section Boundaries

The data region contains three sections in order:

1. **Coordinate section** — compressed vertex coordinates
2. **Face section** — EdgeBreaker-encoded face connectivity
3. **Attribute section** — metadata (SHADED, WIREFRAME, etc.)

**Attribute section** starts at the byte sequence `00 05 40 04 00 0A 20 08 07` followed by the string `SHADED`.

**Face section** starts at the last occurrence of `20 00` before the attribute section.

```
coord_start = data_start + 23
coord_end   = face_section_start
face_start  = face_section_start
face_end    = attribute_section_start
```

## 5. Decode Coordinate Values

The coordinate section stores delta-compressed IEEE 754 big-endian doubles. Three element types share the byte stream:

### Element types

| First byte | Type | Action |
|-----------|------|--------|
| `0x00` (before first FULL value) | **Zero literal** | Value is 0.0, consume 0 data bytes |
| `0x00–0x06` | **Count byte** | Read `count + 1` data bytes → coordinate value |
| `b & 0x07 == 0x07` and `b >= 7` | **Separator** | Skip 1 byte |
| `0x60–0xFF` (except separators) | **Tag pair** | Read 2 bytes (this byte + next) |
| `0x08–0x5F` (non-count, non-sep) | **Skip byte** | Skip 1 byte (metadata) |

**Note:** `0x00` is only a zero literal before the first FULL coordinate value has been decoded. After the first FULL value, `0x00` is treated as a standard count byte (count=0, reads 1 data byte). Tag pairs in the coordinate section only have first bytes >= `0x60` (classes 60, 80, A0, C0, E0). Lower bytes that aren't count bytes or separators are single-byte metadata and should be skipped.

### Reconstructing a coordinate value

Given count byte `b` and the following `b + 1` stored bytes:

**FULL value** (first stored byte is `0x40`, `0x41`, `0xC0`, or `0xC1`):
```
result = stored_bytes + zero_padding   (pad to 8 bytes total)
value  = IEEE 754 big-endian double(result)
```

**DELTA value** (first stored byte is anything else):
```
result[0]              = previous_result[0]          (keep byte 0)
result[1..count+1]     = stored_bytes                (insert new bytes)
result[count+2..7]     = previous_result[count+2..7] (keep trailing bytes)
value                  = IEEE 754 big-endian double(result)
```

Update `previous_result = result` after each coordinate.

## 6. Assign Axes (X/Y/Z) to Coordinate Values

Each coordinate value represents one axis of one or more vertices. The axis is determined by a **state machine**:

### Initial rule
The first 3 coordinate values are always **X, Y, Z** (axes 0, 1, 2) of the first vertex (V0).

### State machine (after the first 3)

State: `current_axis` (0/1/2), `direction` (+1 or -1, starts at +1)

For each subsequent coordinate, examine the **first non-C0 tag** that follows it:

| Tag condition | Action |
|--------------|--------|
| Tag class = `E0` | **Stay** on same axis |
| `lo_nib = 0xF` AND `hi_nib = 0` | Set `direction = -1`, move: `axis = (axis - 1) mod 3` |
| `lo_nib = 0xF` AND `hi_nib > 0` | **Stay** on same axis |
| Everything else (including no tag) | **Move** in current direction: `axis = (axis + direction) mod 3` |

Where `lo_nib = byte2 & 0x0F` and `hi_nib = (byte2 >> 4) & 0x0F` of the tag's second byte.

## 7. Build the Vertex Table

### Running state model

Maintain a "running vertex" `[X, Y, Z]` that updates as coordinates are processed:

1. **V0**: Set from the first 3 coordinate values (X, Y, Z)
2. **Each subsequent coordinate**: Updates the running state's assigned axis, then creates a new vertex as a snapshot of the running state

### C0 tag vertex assignments

`C0` class tags in the coordinate section create **additional vertex slots** that share coordinate values:

```
C0 tag second byte:
  hi_nib = vertex slot index (which vertex gets this value)
  lo_nib = Z-axis variant selector:
           0x7 = use base Z (first Z value seen)
           0xF = use alternate Z (second Z value seen)
```

When a C0 tag appears after a coordinate value, it means: "also assign this coordinate's value (for this axis) to the vertex at slot `hi_nib`."

Vertex slots NOT explicitly assigned an axis value by C0 tags inherit the **base value** (first value seen) for that axis.

## 8. Decode Face Connectivity (EdgeBreaker)

The face section uses an **EdgeBreaker** traversal encoding. Faces are not stored as explicit `(v0, v1, v2)` triples. Instead, a sequence of topology operations rebuilds the mesh.

### Face section structure

```
20 00                    — section start marker
[40 XX]                  — initial face metadata tag (if present before vertex data)
[00 VV 20 03] × N        — initial triangle vertex list (1-based), ended by E0 03
                          (or implicit triangle (0,1,2) if topology tags come first)

For each group:
  00 40 / 00 C0          — group flag
  separator byte
  00 VV                  — explicit vertex index (1-based)
  20 10                  — group marker
  [E0/E1 XX] [sep]       — preamble
  40 XX                  — topology op (nib=7: C operation, uses explicit vertex)
  40 XX                  — topology op (C or R depending on context)
  40 1B                  — finalizer (gate advance -1, no face created)
  E0 03                  — group end
  E0 00                  — section end (last group only)
```

### EdgeBreaker operations

The decoder maintains a **boundary loop** (ordered list of vertex indices) and a **gate** (current edge position in the boundary):

| Operation | Action |
|-----------|--------|
| **C** (Create) | New vertex. Triangle = (gate_left, gate_right, new_vertex). Insert new vertex into boundary. |
| **R** (Right) | Connect to far-right vertex. Triangle = (left, right, far_right). Remove right from boundary. |
| **L** (Left) | Connect to far-left vertex. Triangle = (far_left, left, right). Remove left from boundary. |
| **E** (End) | Close triangle from remaining boundary vertices. |

### Group-based decoding (open meshes)

For strips, fans, and planes:

- **Group without back-reference**: Operations are **C, C, finalizer** (creates 2 faces per group)
- **Group with back-reference** (explicit vertex already on boundary): Operations are **C, R, finalizer**
- **Closing group** (E0:04 ending): Single **E** operation

The **finalizer** (`40:1B`) advances the gate backward by 1 position.

### Closed manifolds (cubes, solids)

Closed meshes use a continuous stream of C, R, L, E operations without the group/finalizer structure. Both `40` and `C0` class tags encode **C** operations. The `0x3` low-nibble typically encodes **R** or **L** operations.

## 9. Output

With the vertex table and face list, you can export to any format:

- **OBJ**: `v X Y Z` lines + `f v1 v2 v3` lines (1-based indices)
- **3DFACE DXF**: Standard DXF with 3DFACE entities
- **STL**: Binary or ASCII triangles with computed normals

---

## Known Limitations

1. **High-precision coordinates**: Values with 7-8 significant bytes in their IEEE 754 representation can collide with tag byte values, causing misdecoding. This affects coordinates like `32307.853395xxxx`.

2. **Face decoding for complex meshes**: The deterministic face operation selection works for strips, fans, and planes. For complex closed solids, the exact operation (C vs L vs R) is context-dependent and may require trying multiple interpretations.

3. **Coordinate section**: Values near zero can be misidentified as count bytes. Files where all axes share the same value (e.g., a flat grid at Z=0) may have axis tracking issues.

4. **Fan coordinates**: Files with non-round coordinates (many significant decimal places) produce unreliable coordinate values due to high-entropy byte collisions with tag detection.

---

## File Format Summary

```
┌─────────────────────────────────────────────┐
│ Header (60 bytes)                           │
│   Magic: EA FB A7 8A                        │
│   Signature: "vulZ"                         │
├─────────────────────────────────────────────┤
│ Page Chain (2048-byte linked pages)         │
├─────────────────────────────────────────────┤
│ "Created External\0" + "Variant\0"         │
├─────────────────────────────────────────────┤
│ Pre-coord header (23 bytes)                 │
│   +12: coord count, +19: face count         │
├─────────────────────────────────────────────┤
│ Coordinate Section                          │
│   Delta-compressed BE doubles               │
│   Axis state machine (X→Y→Z cycling)        │
│   C0 tags = vertex slot assignments         │
├─────────────────────────────────────────────┤
│ Face Section (starts at last "20 00")       │
│   EdgeBreaker topology operations           │
│   C/R/L/E encoded in 40/C0 class tag pairs  │
├─────────────────────────────────────────────┤
│ Attribute Section                           │
│   SHADED, WIREFRAME, IRGB, UserAttributes  │
├─────────────────────────────────────────────┤
│ Duplicate of entire data section            │
├─────────────────────────────────────────────┤
│ Trailing padding (E0 FF 00 pattern)         │
└─────────────────────────────────────────────┘
```

---

*Reverse-engineered by Brent Buffham and Claude through systematic binary analysis. No decompilation or disassembly of Maptek software was performed.*
