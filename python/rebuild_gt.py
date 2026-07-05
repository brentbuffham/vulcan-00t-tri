#!/usr/bin/env python3
"""REBUILD GT from the intercepts DXF (the scratchpad intercepts_gt.csv +
faces_gt.npy died with an old session). Produces, in python/ cwd:
  - intercepts_gt.csv : unique 3DFACE corner vertices (first-seen order)
  - faces_gt.npy      : triangle triples as indices into that vertex list
Positional matching downstream (KDTree) makes the exact index order irrelevant
as long as csv and npy are mutually consistent -- which they are by construction.
"""
import re, numpy as np

dxf = r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'
txt = open(dxf, errors='ignore').read()

faces = []
for m in re.finditer(r'\n\s*0\r?\n3DFACE\r?\n(.*?)(?=\n\s*0\r?\n)', txt, re.S):
    body = m.group(1)
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    codes = {}
    for i in range(0, len(lines) - 1):
        if lines[i] in ('10','11','12','13','20','21','22','23','30','31','32','33'):
            try: codes.setdefault(lines[i], float(lines[i + 1]))
            except ValueError: pass
    quad = []
    for k in range(4):
        try: quad.append((codes[f'1{k}'], codes[f'2{k}'], codes[f'3{k}']))
        except KeyError: break
    faces.append(quad)
print('3DFACE entities:', len(faces))

# triangle = first 3 corners (corner3==corner2 => degenerate quad = triangle)
tri = [f[:3] if (len(f) < 4 or f[3] == f[2]) else f for f in faces]
nquad = sum(1 for f in tri if len(f) == 4)
print('true quads (kept as 4-corner):', nquad)

# unique vertex list, first-seen order, 3dp key
key = {}; verts = []
def vid(p):
    k = (round(p[0], 3), round(p[1], 3), round(p[2], 3))
    if k not in key:
        key[k] = len(verts); verts.append([p[0], p[1], p[2]])
    return key[k]

fidx = []
for f in tri:
    ids = [vid(c) for c in f[:3]]
    fidx.append(ids)
V = np.array(verts)
F = np.array(fidx)
print('unique verts:', V.shape, '  triangles:', F.shape)
print('verts referenced by faces:', len(np.unique(F)))

np.savetxt('intercepts_gt.csv', V, delimiter=',', fmt='%.6f')
np.save('faces_gt.npy', F)
print('saved intercepts_gt.csv + faces_gt.npy')
print('XZ bbox: X', V[:,0].min(), V[:,0].max(), ' Z', V[:,2].min(), V[:,2].max())
