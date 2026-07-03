#!/usr/bin/env python3
"""Face-record index extraction + GT alignment (intercepts).
Hypothesis: face records embed explicit vertex indices as COUNT-prefixed values
(00=1 byte, 01=2 bytes BE). Extract them in stream order and compare against the
DXF triangle stream (vertex ids by first appearance in DXF face order)."""
import sys, struct
import numpy as np

oot = sys.argv[1] if len(sys.argv) > 1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
dxf = sys.argv[2] if len(sys.argv) > 2 else r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'

# ---------- GT: triangles in DXF order, vertices by first appearance ----------
lines = open(dxf, 'r', errors='ignore').read().split('\n')
i = 0; n = len(lines); tris_xyz = []; cur = {}; in3d = False
def fnum(s):
    try: return float(s)
    except: return None
while i < n - 1:
    code = lines[i].strip(); val = lines[i+1].strip() if i+1 < n else ''
    if code == '0':
        if in3d and len(cur) >= 9:
            tris_xyz.append(cur.copy())
        in3d = (val.upper() == '3DFACE'); cur = {}
    elif in3d:
        c = fnum(code); f = fnum(val)
        if c is not None and f is not None and abs(f) < 1e8:
            ci = int(c)
            for k in range(4):
                if ci == 10+k: cur[(k,0)] = f
                elif ci == 20+k: cur[(k,1)] = f
                elif ci == 30+k: cur[(k,2)] = f
    i += 2
vid = {}; verts = []; gt_tris = []
for t in tris_xyz:
    tri = []
    for k in range(3):
        p = (round(t[(k,0)],3), round(t[(k,1)],3), round(t[(k,2)],3))
        if p not in vid:
            vid[p] = len(verts); verts.append(p)
        tri.append(vid[p])
    gt_tris.append(tuple(tri))
NV = len(verts); NT = len(gt_tris)
print(f'GT: {NV} verts, {NT} tris (first-appearance ids in DXF order)')
print('first 12 GT tris:', gt_tris[:12])

# ---------- face records ----------
d = open(oot, 'rb').read()
occ = [i for i in range(8326, len(d)-2) if d[i] == 0xE0 and d[i+1] == 0x03]
# skip the first (coord-marker) record; face block = dense run
recs = []
for k in range(1, len(occ)):
    end = occ[k+1] if k+1 < len(occ) else len(occ) and None
    recs.append(d[occ[k]:occ[k+1]] if k+1 < len(occ) else d[occ[k]:occ[k]+64])
print(f'face records: {len(recs)}')

# ---------- extract COUNT-prefixed values ----------
# scan each record payload: byte 0x00 -> next 1 byte = value; 0x01 -> next 2 bytes BE
vals = []   # (rec_idx, offset_in_rec, nbytes, value)
for ri, r in enumerate(recs):
    pl = r[2:]
    j = 0
    while j < len(pl):
        b = pl[j]
        if b == 0x00 and j+1 < len(pl):
            vals.append((ri, j, 1, pl[j+1])); j += 2
        elif b == 0x01 and j+2 < len(pl):
            vals.append((ri, j, 2, (pl[j+1] << 8) | pl[j+2])); j += 3
        else:
            j += 1
print(f'extracted values: {len(vals)}')
seq = [v[3] for v in vals]
print('first 60 values:', seq[:60])
inrange = sum(1 for v in seq if v < NV)
print(f'values < NV({NV}): {inrange}/{len(seq)} ({inrange/len(seq)*100:.0f}%)')
inrange_t = sum(1 for v in seq if v < NT)
print(f'values < NT({NT}): {inrange_t}/{len(seq)} ({inrange_t/len(seq)*100:.0f}%)')
hist_hi = sorted(set(v for v in seq if v >= NV))[:20]
print('out-of-range values (first 20):', hist_hi)

# ---------- GT vertex first-appearance sequence ----------
# In EdgeBreaker the C-op count == NV - (initial tri verts). Explicit indices usually
# appear at S/split ops. Sanity: does the value sequence hit GT triangle vertices in order?
flat = [v for t in gt_tris for v in t]
print('\nGT flat stream first 60:', flat[:60])
