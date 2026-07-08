#!/usr/bin/env python3
"""score25 -- score a P npy vs a case DXF at 0.25m/1m (SCORING ONLY). Caches GT."""
import sys, os
import numpy as np
from scipy.spatial import cKDTree
CASES = {
    'intercepts': r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf',
    'SYLVANIA':   r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topoDXF.dxf',
    'OB34':       r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_TopoDXF.dxf',
}
case, npy = sys.argv[1], sys.argv[2]
def dxf_verts(path):
    seen = set(); in3d = False; cur = {}
    with open(path, 'r', errors='ignore') as f:
        prev = None
        for line in f:
            s = line.strip()
            if prev is None: prev = s; continue
            code, val = prev, s; prev = None
            if code == '0':
                if in3d:
                    for kk in range(4):
                        if (kk, 0) in cur and (kk, 1) in cur and (kk, 2) in cur:
                            seen.add((cur[(kk, 0)], cur[(kk, 1)], cur[(kk, 2)]))
                in3d = (val.upper() == '3DFACE'); cur = {}
            elif in3d:
                try: ci = int(code); fv = float(val)
                except Exception: continue
                if abs(fv) < 1e8:
                    for base, ax in ((10, 0), (20, 1), (30, 2)):
                        if base <= ci <= base + 3: cur[(ci - base, ax)] = fv
    return np.array(list(seen))
gc = f'GT_{case}.npy'
if os.path.exists(gc):
    G = np.load(gc)
else:
    G = dxf_verts(CASES[case]); np.save(gc, G)
P = np.load(npy)
dist, _ = cKDTree(G).query(P)
dxy, _ = cKDTree(G[:, :2]).query(P[:, :2])
m25 = dist < 0.25
yel = (~m25) & (dxy < 0.25)
N = min(500, len(P))
print(f'{case} {npy}: <0.25m {int(m25.sum())}/{len(P)} ({100*m25.mean():.2f}%)  <1m {int((dist<1).sum())}/{len(P)} ({100*(dist<1).mean():.2f}%)  yellow {int(yel.sum())}  first{N}<0.25 {int((dist[:N]<0.25).sum())}')
