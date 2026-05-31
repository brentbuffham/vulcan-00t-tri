#!/usr/bin/env python3
"""Test the FIXED-WIDTH RECORD hypothesis for .00t vertices/faces.

Strategy: get ground-truth vertices from the DXF twin, then search the raw
.00t bytes for those exact IEEE-754 double patterns (BE and LE). If vertices
are stored as fixed-width records, the hits will appear at a regular stride.
"""
import struct, re, sys

stem = sys.argv[1] if len(sys.argv) > 1 else 'tri-crack-solid'
dxf = f'exampleFiles/{stem}.dxf'
oot = f'exampleFiles/{stem}.00t'

# ── extract 3DFACE corner vertices from DXF ──
lines = [l.strip() for l in open(dxf).read().split('\n')]
pairs = list(zip(lines[0::2], lines[1::2]))

verts = []          # ordered, with duplicates (face corners)
uverts = set()
faces = 0
j = 0
while j < len(pairs):
    c, v = pairs[j]
    if v == '3DFACE':
        faces += 1
    if c in ('10', '11', '12', '13'):
        try:
            x = float(v); y = float(pairs[j+1][1]); z = float(pairs[j+2][1])
        except (ValueError, IndexError):
            j += 1; continue
        verts.append((x, y, z))
        uverts.add((round(x, 4), round(y, 4), round(z, 4)))
        j += 3; continue
    j += 1

print(f'== {stem} ==')
print(f'3DFACE entities: {faces}')
print(f'unique vertices: {len(uverts)}')
for v in sorted(uverts):
    print('   ', v)

data = open(oot, 'rb').read()
print(f'.00t size: {len(data)} bytes\n')

# ── search for each distinct coordinate value (skip 0.0 and sentinels) ──
coordvals = sorted({round(c, 4) for v in uverts for c in v
                    if c != 0.0 and abs(c) < 1e19})
print('distinct coord values & their byte offsets in .00t:')
all_be_offsets = {}
for cv in coordvals:
    be = struct.pack('>d', cv); le = struct.pack('<d', cv)
    obe = [m.start() for m in re.finditer(re.escape(be), data)]
    ole = [m.start() for m in re.finditer(re.escape(le), data)]
    all_be_offsets[cv] = obe
    print(f'  {cv:>10}  BE@{obe}   LE@{ole}')

# ── look for a fixed-stride vertex block (BE doubles) ──
print('\nall BE-double hits sorted by offset:')
flat = sorted((off, cv) for cv, offs in all_be_offsets.items() for off in offs)
for off, cv in flat:
    print(f'   off {off:5d} (0x{off:04x}): {cv}')

if len(flat) >= 2:
    print('\ngaps between consecutive BE hits:')
    for k in range(1, len(flat)):
        print(f'   {flat[k][0]-flat[k-1][0]:4d} bytes  ({flat[k-1][1]} -> {flat[k][1]})')
