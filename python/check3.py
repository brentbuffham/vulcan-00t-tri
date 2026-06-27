#!/usr/bin/env python3
"""Sanity: are the KNOWN decoded FULL vertices actually in the intercepts GT?
Check seed + V1 + V2 (decoded earlier as fulls) and ALL all-full vertices vs GT."""
import sys, struct
import numpy as np
from scipy.spatial import cKDTree
gt=np.loadtxt(sys.argv[2],delimiter=','); tree=cKDTree(gt)
d=open(sys.argv[1],'rb').read()
def be(o): return struct.unpack('>d',d[o:o+8])[0]
face_start=next((i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03), len(d))
for name,p in [('seed',8326)]:
    v=(be(p),be(p+8),be(p+16)); dd,_=tree.query(np.array(v)); print(f'{name} {tuple(round(x,3) for x in v)} -> nearestGT dist={dd:.3f}')
# decoded V1/V2 (fulls @8366..) as (X,Y,Z) by band
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def full(o):
    v=be(o);
    return v if (d[o] in (0x40,0x41) and ((400<abs(v)<900) or (54000<abs(v)<58000) or (158000<abs(v)<166000))) else None
verts=[]; o=8326; cur={}
while o<face_start-8:
    v=full(o)
    if v is not None:
        b=band(v)
        if b in cur: cur={}
        cur[b]=v; o+=8
        if len(cur)==3: verts.append((cur[0],cur[1],cur[2])); cur={}
    else: cur={}; o+=1
P=np.array(verts)
print(f'\nall-FULL vertices={len(P)}')
if len(P):
    dd,_=tree.query(P);
    print(f' nearest-GT dist: min={dd.min():.3f} median={np.median(dd):.3f} max={dd.max():.3f}  within1m={np.mean(dd<1)*100:.0f}%')
    for v,e in list(zip(P,dd))[:8]: print(f'   {v[0]:.3f} {v[1]:.3f} {v[2]:.3f}  dGT={e:.3f}')
