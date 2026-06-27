#!/usr/bin/env python3
"""Robust FULL extraction via CONSECUTIVE-RUN detection. Real coord doubles sit
back-to-back (stride 8); a false 0x40-hit won't have another in-band double exactly
8 bytes away. Find maximal runs of consecutive in-band BE doubles, band-classify,
group by 3 -> vertices. Write XYZ + bbox. NO GT (bbox/shape = verification)."""
import sys, struct
import numpy as np
oot=sys.argv[1]; outxyz=sys.argv[2] if len(sys.argv)>2 else None
d=open(oot,'rb').read()
h=struct.unpack('<15i',d[0:60]); geo_end=h[11] if 8352<h[11]<=len(d) else len(d)
def be(o):
    try:
        v=struct.unpack('>d',d[o:o+8])[0]; return v
    except: return float('nan')
def inband(v): return v==v and 1.0<abs(v)<1e7
# find runs: positions where be(o) and be(o+8) both inband, stride 8
runs=[]; o=8300
while o<geo_end-16:
    if d[o] in (0x40,0x41,0xc0,0xc1) and inband(be(o)) and inband(be(o+8)):
        run=[]; p=o
        while p<geo_end-8 and inband(be(p)):
            run.append(be(p)); p+=8
        if len(run)>=3: runs.append((o,run))
        o=p
    else: o+=1
allv=[v for _,r in runs for v in r]
print(f'{oot}\n runs={len(runs)} total doubles in runs={len(allv):,}')
if len(allv)<6: print(' too few'); sys.exit()
av=np.abs(np.array(allv))
# 3 bands by log-gap split
s=np.sort(av); g=np.diff(np.log10(s+1)); cut=sorted(np.argsort(g)[-2:]); edges=[ (s[c]+s[c+1])/2 for c in cut]
def band(v):
    a=abs(v); return 0 if a<edges[0] else (1 if a<edges[1] else 2)
for b in range(3):
    arr=np.array([v for v in allv if band(v)==b])
    if len(arr): print(f' band{b}: n={len(arr):,} range[{arr.min():.2f},{arr.max():.2f}]')
# group each run into vertices by 3 (consistent axis order within a run)
verts=[]
for _,r in runs:
    for i in range(0,len(r)-2,3):
        tri=r[i:i+3]; bb=[band(x) for x in tri]
        if sorted(bb)==[0,1,2]:
            v=[None,None,None]
            for x in tri: v[band(x)]=x
            verts.append(v)
P=np.array(verts)
print(f' vertices={len(P):,}')
if len(P):
    print(f' bbox band0[{P[:,0].min():.2f},{P[:,0].max():.2f}] band1[{P[:,1].min():.2f},{P[:,1].max():.2f}] band2[{P[:,2].min():.2f},{P[:,2].max():.2f}]')
    if outxyz: np.savetxt(outxyz,P,fmt='%.4f',delimiter=','); print(' wrote',outxyz)
