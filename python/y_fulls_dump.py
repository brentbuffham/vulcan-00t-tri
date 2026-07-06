#!/usr/bin/env python3
"""Dump all framed FULLs per axis with positions; test the 'shorth' robust
range (shortest interval containing half the points) as a GT-free band."""
import struct
import numpy as np

d = open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t', 'rb').read(); n = len(d)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90:
        face_start = occ[k]; break
def be(b): return struct.unpack('>d', bytes(b))[0]
RATIO = 1.15
SEED = [abs(be(d[8326:8334])), abs(be(d[8334:8342])), abs(be(d[8342:8350]))]
bk = {0: [], 1: [], 2: []}
pos = 8350
while pos + 8 <= face_start:
    if d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = abs(be(d[pos:pos + 8]))
        if np.isfinite(v) and v > 0:
            r = [max(v, s) / min(v, s) for s in SEED]
            a = int(np.argmin(r))
            if r[a] < RATIO: bk[a].append(v)
    pos += 1
(XL, XH), (YL, YH), (ZL, ZH) = [(np.array(bk[a]).min(), np.array(bk[a]).max()) for a in range(3)]
def band(v):
    x = abs(v)
    if ZL <= x <= ZH: return 2
    if XL <= x <= XH: return 0
    if YL <= x <= YH: return 1
    return -1
def full_at(p):
    if p + 8 <= face_start and d[p] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[p:p + 8])
        if band(v) >= 0: return v
    return None
framed = {0: [], 1: [], 2: []}
pos = 8350
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    v = full_at(pos)
    if v is not None:
        framed[band(v)].append((pos, v)); pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        v = full_at(pos + 1); framed[band(v)].append((pos + 1, v)); pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start: pos += 3; continue
    if pos + 2 <= face_start: pos += 2; continue
    pos += 1

print('ALL framed Y FULLs (pos, value, lead byte context):')
for p, v in framed[1]:
    print(f'  pos={p:8d}  {v:12.3f}   bytes={d[p:p+8].hex()}  pre={d[p-4:p].hex()}')

def shorth(vals, frac=0.5):
    s = np.sort(np.asarray(vals)); m = len(s)
    k = max(2, int(np.ceil(m * frac)))
    best = None
    for i in range(m - k + 1):
        w = s[i + k - 1] - s[i]
        if best is None or w < best[0]: best = (w, s[i], s[i + k - 1])
    return best

print('\nshorth(50%) per axis, and expanded band = shorth +/- 5*width (min width guard 1.0):')
for a in range(3):
    vals = [abs(v) for _, v in framed[a]]
    w, lo, hi = shorth(vals)
    width = max(hi - lo, 1.0)
    print(f'  axis{a}: shorth=[{lo:.3f}..{hi:.3f}] w={w:.3f}  '
          f'band5=[{lo - 5 * width:.3f}..{hi + 5 * width:.3f}]  n={len(vals)}')
