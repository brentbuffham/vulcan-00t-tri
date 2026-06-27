#!/usr/bin/env python3
"""Independent geometry check: nearest-neighbour spacing of decoded intercepts vs the
expected drill/blast pattern (~4.5x5.2 -> NN ~5m, or ~8x7.5 -> NN ~8.5m). Report NN
distribution in plan (X-Y) and 3D, on raw points and on de-duplicated distinct
locations (collapsing <0.5m near-duplicates from un-calibrated short deltas)."""
import sys
import numpy as np
from scipy.spatial import cKDTree
xyz=sys.argv[1]
P=np.loadtxt(xyz,delimiter=',')
# main cluster filter (drop the few far outliers so they don't skew)
med=np.median(P,axis=0)
keep=(np.abs(P[:,0]-med[0])<2000)&(np.abs(P[:,1]-med[1])<2000)&(np.abs(P[:,2]-med[2])<200)
P=P[keep]
print(f'points (main cluster) = {len(P):,}')
def nn(pts,label):
    if len(pts)<3: print(f'  {label}: too few'); return
    t=cKDTree(pts); dd,_=t.query(pts,k=2); nnd=dd[:,1]
    nnd=nnd[np.isfinite(nnd)]
    print(f'  {label}: n={len(pts):,} NN median={np.median(nnd):.2f} mode~{np.round(np.median(nnd[(nnd>0.5)]),1) if (nnd>0.5).any() else 0}'
          f'  | %in[4,6]={np.mean((nnd>=4)&(nnd<=6))*100:.0f}  %in[7,9]={np.mean((nnd>=7)&(nnd<=9))*100:.0f}')
    h,edges=np.histogram(nnd[nnd<15],bins=np.arange(0,15,0.5))
    top=np.argsort(h)[-5:][::-1]
    print('     top NN bins (m):', ', '.join(f'{edges[i]:.1f}-{edges[i]+0.5:.1f}:{h[i]}' for i in top))
print('PLAN (X-Y):'); nn(P[:,:2],'raw  ')
# dedup distinct locations in plan
t=cKDTree(P[:,:2]); seen=np.zeros(len(P),bool); keepidx=[]
for i in range(len(P)):
    if seen[i]: continue
    keepidx.append(i)
    for j in t.query_ball_point(P[i,:2],0.5): seen[j]=True
D=P[keepidx]
print(f'distinct plan locations (>=0.5m apart) = {len(D):,}')
nn(D[:,:2],'dedup')
print('3D:'); nn(P[:,:3],'raw3d'); nn(D[:,:3],'ddp3d')
