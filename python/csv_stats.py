#!/usr/bin/env python3
"""Stream a huge XYZ CSV (\\r or \\n delimited): row count, coord ranges,
unique-vertex count. Establishes decode targets from ground truth."""
import sys

path = sys.argv[1]
rows = 0
uniq = set()
xmin = ymin = zmin = float('inf')
xmax = ymax = zmax = float('-inf')

with open(path, 'rb') as f:
    buf = b''
    while True:
        chunk = f.read(1 << 20)
        if not chunk:
            break
        buf += chunk
        # split on either \r or \n
        buf = buf.replace(b'\r', b'\n')
        parts = buf.split(b'\n')
        buf = parts.pop()  # keep trailing partial line
        for line in parts:
            if not line:
                continue
            try:
                xs, ys, zs = line.split(b',')
                x = float(xs); y = float(ys); z = float(zs)
            except Exception:
                continue
            rows += 1
            uniq.add((x, y, z))
            if x < xmin: xmin = x
            if x > xmax: xmax = x
            if y < ymin: ymin = y
            if y > ymax: ymax = y
            if z < zmin: zmin = z
            if z > zmax: zmax = z

print(f'rows           : {rows:,}')
print(f'unique verts   : {len(uniq):,}')
print(f'implied tris   : {rows/3:,.0f}  (rows/3)')
print(f'X range        : {xmin:.3f} .. {xmax:.3f}  (span {xmax-xmin:.3f})')
print(f'Y range        : {ymin:.3f} .. {ymax:.3f}  (span {ymax-ymin:.3f})')
print(f'Z range        : {zmin:.3f} .. {zmax:.3f}  (span {zmax-zmin:.3f})')
