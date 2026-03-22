# vulcan-00t-tri
00t files are a Maptek Triangulation binary format there are no known parsers or decoders for this format.  This library is an attempt to decode and reverse engineer the format for wider use.

# Vulcan .00t Triangulation Parser

**Reverse-engineered parser for Maptek Vulcan `.00t` binary triangulation files.**

No Vulcan licence required. No SDK dependency. Pure standalone implementations in JavaScript, Python, and HTML.

Built by [Brent Buffham](https://blastingapps.com) as part of the [Kirra](https://kirra-design.com) blast design platform.

---

## The Problem

Maptek Vulcan is the dominant geological modelling software in mining. Its native triangulation format — `.00t` — is a proprietary binary format with no public documentation. Every mine site has thousands of these files representing pit surfaces, geological boundaries, blast designs, and terrain models.

If you want to work with this data outside of Vulcan, your options are:

1. Pay for a Vulcan licence (~$30k+/year)
2. Export to DXF/STL one file at a time through the Vulcan GUI
3. Use the Vulcan Python SDK (which still requires a licence)

None of these work for a web-based tool like Kirra that needs to ingest mining data directly in the browser.

So we cracked it open.

---

## The Journey

This parser was reverse-engineered across multiple sessions of binary analysis, starting from zero knowledge of the format. Here's how it unfolded.

### 1 — Establishing the skeleton

The first session identified the basic file structure by examining hex dumps of `.00t` files alongside their DXF exports:

- **Magic bytes**: `EA FB A7 8A` followed by ASCII `vulZ`
- **Page chain**: 2048-byte linked pages, mostly zero-padded, with data starting around page 4 (offset `0x2040`)
- **Data block**: begins with `"Created External\0"` + `"Variant\0"` strings, followed by the coordinate stream, then attribute metadata (`SHADED`, `USE_ICOLOUR`, `WIREFRAME`, file path, `UserAttributes`)
- **Duplicate data**: the entire data section appears to be stored twice

This gave us the roadmap but not the encoding.

### 2 — Cracking the coordinate encoding

Using a simple test file — a cube with 8 vertices at known coordinates (X=100/300, Y=500/600, Z=900/950) — we reverse-engineered the coordinate compression:

**Discovery 1: Truncated big-endian doubles.** Coordinates are stored as truncated IEEE 754 big-endian doubles. A count byte (0–6) tells how many of the 8 double bytes are stored. The rest are reconstructed.

**Discovery 2: FULL vs DELTA values.** If the first stored byte is `0x40` or `0x41` (the exponent byte for positive doubles in the coordinate range), it's a FULL value — the stored bytes are the MSB portion, zero-padded to 8 bytes. Otherwise, it's a DELTA — byte 0 is kept from the previous value, the stored bytes replace the middle, and trailing bytes are preserved from the previous value.

```
Example: X=100.0
  Count=1, data=[40 59]
  → 40 59 00 00 00 00 00 00
  → IEEE 754 BE double = 100.0 ✓

Example: Z=950.0 (delta from Z=900.0 = 40 8C 20 ...)
  Count=1, data=[8D B0]
  → keep byte[0]=40, insert [8D B0], keep trailing zeros
  → 40 8D B0 00 00 00 00 00 = 950.0 ✓
```

**Discovery 3: The trailing byte fix.** The initial delta rule zero-padded the trailing bytes. This caused X=300 (stored as delta from Y=600) to decode as 288.0 instead of 300.0. The fix: delta values preserve trailing bytes from the previous value, not zeros.

```
Y=600 = 40 82 C0 00 00 00 00 00
X=300 delta: count=0, data=[72]
  → 40 [72] C0 00 00 00 00 00 = 300.0 ✓
  (not 40 72 00 00 00 00 00 00 = 288.0 ✗)
```

### 3 — The separator breakthrough

A linear strip test file (8 vertices on a grid of 1000/1100/1200/1300) exposed a critical flaw: the byte `0x07` was being treated as a count byte (meaning "read 8 data bytes") when it was actually a **separator**.

The real rule: **any byte where the low 3 bits are all set (`byte & 0x07 === 0x07`) and the value is ≥ 7 is a separator/topology marker, not a count byte.** Count bytes are 0x00–0x06 only.

```
Separators: 0x07, 0x0F, 0x17, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x47, ...
Count bytes: 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
Tag pairs: everything else ≥ 0x08 (consumes 2 bytes)
```

This single fix made the linear strip decode perfectly (1000 ✓, 1100 ✓, 1200 ✓, 1300 ✓) and explained why earlier attempts on real mining files with larger coordinates had failed.

### 4 — Face connectivity and EdgeBreaker

With coordinates cracked, we turned to the face/triangle encoding. Using test files of increasing complexity — single triangle, plane (2 faces), cube (12 faces), fan (6 faces), linear strip (5 faces) — we established:

- The **face section** starts after a `20 00` tag pair and ends at `E0 00`
- **Vertex indices** appear as single-byte data values in `00 VV 20 XX` patterns (1-based)
- The first face is implicitly formed from the first 3 vertices in the coordinate stream
- Most face connectivity is encoded in **tag pairs** (`40 XX`, `C0 XX`, `E0 XX`) that describe mesh topology

The face encoding appears to be an **EdgeBreaker-like compressed mesh topology** format (Rossignac, 1999). Rather than storing explicit `(v0, v1, v2)` triples, it encodes the traversal of the mesh as a sequence of topology operations — similar to the CLERS op-codes in EdgeBreaker (C=new vertex, L=left visited, E=end, R=right visited, S=split).

Evidence:
- The cube (12 faces, 8 vertices) stores only 7 explicit vertex indices in the face section — one per new vertex beyond the initial triangle
- The tag pairs between vertex indices encode the remaining faces through adjacency relationships
- The separator values (`0x17`, `0x2F`, `0x47`, `0x5F`) appear both in the coordinate section and the face section, suggesting a unified topology stream

**The face encoding is not yet fully decoded.** The exact mapping from tag byte values to EdgeBreaker operations remains an open problem.

---

## File Structure

```
Offset    Content
───────────────────────────────────────────────
0x0000    Header (60 bytes)
            Magic:     EA FB A7 8A
            Signature: 'vulZ' (ASCII)
            Data size: LE uint32 at offset 0x20
            Page ptr:  LE uint32 at offset 0x3C

0x003C    Page chain (linked list of 2048-byte pages)
          Mostly zero-padded. Data typically starts at page 4.

0x2040    Data block header
            "Created External\0"
            "Variant\0"

0x2061    Pre-coordinate header (23 bytes)
            Position +12: vertex/point count
            Position +19: face/triangle count
            Position +22: 0x14 (constant)

0x2078    Coordinate stream
          (varies)  Tag pairs, separators, delta-compressed doubles

          Face section marker: tag pair 20 00
          Face vertex indices + topology tags
          Face section end: tag pair E0 00

          Attribute block: SHADED, USE_ICOLOUR, WIREFRAME,
                          file path, IRGB, UserAttributes

          DUPLICATE of entire data section

          Trailing padding (E0 FF 00 pattern)
```

## Coordinate Encoding

```
Stream element types:
  Count byte (0x00–0x06):  read count+1 data bytes → coordinate value
  Separator  (b & 7 == 7): skip 1 byte (topology marker)
  Tag pair   (all else):   skip 2 bytes (metadata/face connectivity)

Coordinate reconstruction:
  FULL:  first data byte is 0x40/0x41/0xC0/0xC1
         → stored bytes + zero padding = 8-byte BE double

  DELTA: first data byte is anything else
         → byte[0] from previous value
         → stored bytes at positions [1..count+1]
         → trailing bytes from previous value
         → reconstructed 8-byte BE double
```

## Current Limitations

**Coordinate decoding** works perfectly for values with ≤6 significant bytes in their IEEE 754 representation. This covers most mining coordinates with moderate precision. For coordinates with 7–8 significant bytes (e.g. 32307.853395xxxx), the high-entropy data bytes can collide with tag byte values, causing misdecoding. A robust solution would require understanding how the encoder signals the boundary between coordinate data and tag bytes in these cases.

**Face connectivity** is partially decoded. The first face and explicit vertex indices are extracted, but full triangle reconstruction requires decoding the EdgeBreaker-like topology operations encoded in the tag pairs. The current workaround is to use a DXF sidecar file for face connectivity.

**Multi-page files** with non-standard page chain layouts may fail to find the Variant marker. The parser includes fallback scanning for `Created External` and the pre-coordinate header pattern.

---

## Tools Included

### `oot_to_dxf.html`
Single-file browser app. Drag & drop `.00t` files, batch convert to 3DFACE DXF, point cloud DXF, OBJ, or CSV. Supports sidecar `.dxf` files for face connectivity. Zero dependencies — just open in a browser.

### `oot_to_dxf.py`
PyQt6 desktop app with the same batch conversion features. Requires `PyQt6` and `ezdxf`.

```bash
pip install PyQt6 ezdxf
python oot_to_dxf.py
```

### `oot-parser.js`
Standalone ES module for integration into web applications (e.g. Kirra). Zero dependencies.

```javascript
import { parseOOT, toOBJ, toCSV } from './oot-parser.js';

const buffer = await file.arrayBuffer();
const result = parseOOT(buffer);

result.vertices       // [[x, y, z], ...]
result.faces          // [[v0, v1, v2], ...] (first face + sidecar)
result.coordValues    // all decoded coordinate values
result.header         // { vertexCount, faceCount, ... }
result.warnings       // any parse issues
```

### `oot_dxf_viewer.py`
PyQt6 hex viewer and decoder for reverse-engineering. Shows the raw byte stream colour-coded by element type (FULL/DELTA/tag/separator), with coordinate values decoded in real time. Useful for continuing the reverse-engineering effort.

---

## Test Files

The `test-files/` directory contains purpose-built `.00t` and matching `.dxf` files used during reverse-engineering:

| File | Vertices | Faces | Purpose |
|------|----------|-------|---------|
| `tri-crack-triangle` | 3 | 1 | Simplest possible — single triangle |
| `tri-crack` | 4 | 2 | Flat plane — two triangles sharing an edge |
| `tri-crack-solid` | 8 | 12 | Cube — all coordinate combinations |
| `tri-crack-fan` | 6 | 6 | Fan topology — shared central vertex |
| `tri-crack-linear` | 8 | 6 | Linear strip — grid of triangles |

These were created in Vulcan with round coordinate values (100, 300, 500, 600, 900, 950, 1000–1300) to make the binary encoding easier to spot.

---

## Contributing

The biggest open problem is **fully decoding the face connectivity**. If you have access to Vulcan and can generate test files with known topologies, that's the most valuable contribution. Specifically useful would be:

- A triangle strip with 10+ triangles in a known zigzag pattern
- A mesh with a hole (boundary edges)
- A closed solid with >20 faces
- Files exported from different Vulcan versions

If you're familiar with EdgeBreaker, Touma-Gotsman, or similar mesh compression algorithms, the tag byte patterns in the face section are waiting to be mapped to CLERS operations.

---

## Acknowledgements

The reverse-engineering was conducted through systematic binary analysis, progressively more complex test files, and comparison with DXF exports. No decompilation or disassembly of Maptek software was performed. The format was decoded purely from examining the binary output of legitimate Vulcan exports.

This work is in the spirit of interoperability — enabling mining professionals to work with their own data in the tools of their choice.

---

## Licence

This parser code is released under the MIT licence. The `.00t` file format is proprietary to Maptek. This project is not affiliated with or endorsed by Maptek.