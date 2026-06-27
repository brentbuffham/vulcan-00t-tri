#!/usr/bin/env python3
"""Average spacing from footprint area / count (tests scale & extent, independent of
delta clustering): for a regular pattern, spacing ~= sqrt(area / n_points). Compare to
the expected drill pattern (4.5x5.2 -> ~5; 8x7.5 -> ~8). Also report fulls-only NN."""
import sys, struct
import numpy as np
from scipy.spatial import cKDTree, ConvexHull
xyz=sys.argv[1]
P=np.loadtxt(xyz,delimiter=',')
med=np.median(P,axis=0)
keep=(np.abs(P[:,0]-med[0])<2000)&(np.abs(P[:,1]-med[1])<2000)&(np.abs(P[:,2]-med[2])<200)
P=P[keep]
xy=P[:,:2]
# dedup distinct plan locations >=0.5m
t=cKDTree(xy); seen=np.zeros(len(xy),bool); idx=[]
for i in range(len(xy)):
    if seen[i]: continue
    idx.append(i)
    for j in t.query_ball_point(xy[i],0.5): seen[j]=True
D=xy[idx]
hull=ConvexHull(D); area=hull.volume  # 2D hull 'volume' = area
print(f'distinct plan points={len(D):,}  footprint area={area:,.0f} m^2  (bbox {np.ptp(D[:,0]):.0f} x {np.ptp(D[:,1]):.0f} m)')
print(f'==> average spacing sqrt(area/n) = {np.sqrt(area/len(D)):.2f} m   (expected ~5 or ~8.5)')
# also: if it were the full raw count
print(f'    (raw n={len(xy):,} -> sqrt(area/n)= {np.sqrt(area/len(xy)):.2f} m)')
