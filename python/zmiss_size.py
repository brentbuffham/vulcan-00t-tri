import numpy as np
from scipy.spatial import cKDTree
P = np.loadtxt('P_v10_intercepts.csv', delimiter=',')
Gu = np.unique(np.loadtxt('intercepts_gt.csv', delimiter=','), axis=0)
d3, _ = cKDTree(Gu).query(P)
dxy, _ = cKDTree(Gu[:, :2]).query(P[:, :2])
m = d3 < 0.25
z = (~m) & (dxy < 0.25)
r = ~m & ~z
print(f'total {len(P)}  green(3D<250mm) {m.sum()}  yellow(XYok,Zoff) {z.sum()}  red {r.sum()}')
print(f'current 3D match: {100*m.mean():.1f}%')
print(f'if the Z-only class were fixed: {m.sum()+z.sum()}/{len(P)} = {100*(m.sum()+z.sum())/len(P):.1f}%  (+{z.sum()} verts, +{100*z.mean():.1f} pts)')
# how far off is Z on the yellow class?
_, idx = cKDTree(Gu[:, :2]).query(P[:, :2])
zerr = np.abs(P[z, 2] - Gu[idx[z], 2])
print(f'Z error on yellow class: median {np.median(zerr):.3f}m  p90 {np.percentile(zerr,90):.3f}m  max {zerr.max():.3f}m')
print(f'  quantized? Z errors as multiples of 0.125m: {np.round(np.sort(zerr)[:20]/0.125,2)}')
