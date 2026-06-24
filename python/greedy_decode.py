#!/usr/bin/env python3
"""Per-axis running-prev decoder.
Model: each count-record updates ONE axis. New value = (high 8-nb bytes from
that axis's previous double) ++ (payload as the low nb bytes). Axis is assigned
by which candidate lands on its ground-truth grid (X,Y sparse → decisive;
Z dense → fallback when neither X nor Y matches)."""
import sys, struct
import numpy as np

oot = sys.argv[1]
cachedir = sys.argv[2]
gt = {ax: np.load(f'{cachedir}/gt_{ax}.npy') for ax in 'xyz'}

def on_grid(v, ax, tol):
    a = gt[ax]
    i = np.searchsorted(a, v)
    if i <= 0: return abs(a[0] - v) < tol
    if i >= len(a): return abs(a[-1] - v) < tol
    return min(abs(a[i] - v), abs(a[i-1] - v)) < tol

def be(raw):
    raw = (raw + b'\x00' * 8)[:8]
    return struct.unpack('>d', raw)[0]

d = open(oot, 'rb').read()
hdr = struct.unpack('<15i', d[0:60])
geo_end = hdr[11]
TAG_CLASSES = (0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0)
FULL_IND = (0x40, 0x41, 0xC0, 0xC1)
def is_sep(b): return (b & 0x07) == 0x07 and b >= 0x07

# seed per-axis prev from vertex 0
prev = {'x': bytes(d[8328:8336]), 'y': bytes(d[8336:8344]), 'z': bytes(d[8344:8352])}
print('seed:', {k: be(v) for k, v in prev.items()})

TOL_XY = 0.006
ZLO, ZHI = 511.0, 543.0
cnt = {'x': 0, 'y': 0, 'z': 0, 'none': 0}
verts = []
cur = {'x': None, 'y': None, 'z': None}
pos = 8328 + 24

while pos < geo_end:
    b = d[pos]
    if b <= 0x06:
        nb = b + 1
        payload = bytes(d[pos + 1:pos + 1 + nb])
        pos += 1 + nb
        if len(payload) != nb or (payload and payload[0] in FULL_IND):
            continue
        cx = be(prev['x'][:8-nb] + payload)
        cy = be(prev['y'][:8-nb] + payload)
        cz = be(prev['z'][:8-nb] + payload)
        if on_grid(cx, 'x', TOL_XY):
            ax, val = 'x', cx
        elif on_grid(cy, 'y', TOL_XY):
            ax, val = 'y', cy
        elif ZLO <= cz <= ZHI:
            ax, val = 'z', cz
        else:
            cnt['none'] += 1
            continue
        cnt[ax] += 1
        prev[ax] = (prev[ax][:8-nb] + payload + b'\x00'*8)[:8]
        cur[ax] = val
        if ax == 'z' and cur['x'] is not None and cur['y'] is not None:
            verts.append((cur['x'], cur['y'], cur['z']))
    elif is_sep(b):
        pos += 1
    elif (b & 0xE0) in TAG_CLASSES:
        pos += 1
    else:
        pos += 1

tot = sum(cnt.values())
print(f'\nassigned: X={cnt["x"]:,}  Y={cnt["y"]:,}  Z={cnt["z"]:,}  none={cnt["none"]:,}  (total {tot:,})')
print(f'clean-assign rate: {(tot-cnt["none"])/tot*100:.1f}%')
print(f'vertices assembled (on Z-complete): {len(verts):,}   GT verts = 1,212,592')
if verts:
    print('first 5 verts:', [tuple(round(c,3) for c in v) for v in verts[:5]])
