#!/usr/bin/env python3
"""Locate the real vertex/triangle counts and base coordinate in a .00t,
using ground-truth values from the CSV."""
import sys, struct

path = sys.argv[1]
d = open(path, 'rb').read()
n = len(d)

VERTS = 1_212_592
TRIS  = 3_232_403
ROWS  = 9_697_208
# coordinate extremes from the CSV
XMIN, XMAX = 60347.797, 60819.844
YMIN, YMAX = 213957.500, 214684.750
ZMIN, ZMAX = 512.701, 541.988

def find_i32(val, label):
    pat = struct.pack('<i', val)
    hits = []
    start = 0
    while True:
        i = d.find(pat, start)
        if i < 0: break
        hits.append(i)
        start = i + 1
    print(f'  int32 {label}={val} (0x{val & 0xffffffff:08x}): {len(hits)} hits' +
          ('' if not hits else '  at ' + ', '.join(str(h) for h in hits[:12])))
    return hits

print('=== exact-count int32 search ===')
for v, lab in [(VERTS, 'VERTS'), (TRIS, 'TRIS'), (ROWS, 'ROWS'),
               (VERTS-1, 'VERTS-1'), (TRIS-1, 'TRIS-1'),
               (VERTS+1, 'VERTS+1'), (TRIS+1, 'TRIS+1')]:
    find_i32(v, lab)

print('\n=== near-count int32 in the geometry header (offsets 8252..9000) ===')
for off in range(8252, 9000, 4):
    v = struct.unpack('<i', d[off:off+4])[0]
    if 1_000_000 < v < 20_000_000:
        print(f'  @{off}: {v:,}')

print('\n=== base-coordinate double search (first vertex ~ XMIN/YMIN) ===')
# Search the geometry start region for IEEE-754 doubles within the X/Y range.
for off in range(8252, 9200):
    try:
        x = struct.unpack('<d', d[off:off+8])[0]
    except struct.error:
        continue
    if XMIN - 1 <= x <= XMAX + 1:
        # check if a plausible Y follows within 8 or 16 bytes
        for delta in (8, 16, 24):
            try:
                y = struct.unpack('<d', d[off+delta:off+delta+8])[0]
            except struct.error:
                continue
            if YMIN - 1 <= y <= YMAX + 1:
                print(f'  @{off}: X={x:.3f}  (+{delta}) Y={y:.3f}')
                break

print('\n=== big-endian double variant (parser uses read_be_double) ===')
for off in range(8252, 9200):
    try:
        x = struct.unpack('>d', d[off:off+8])[0]
    except struct.error:
        continue
    if XMIN - 1 <= x <= XMAX + 1:
        print(f'  BE @{off}: X={x:.3f}')
