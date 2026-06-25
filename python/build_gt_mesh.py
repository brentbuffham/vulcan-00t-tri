#!/usr/bin/env python3
"""Build the GT mesh topology from the face-ordered CSV (3 rows = 1 triangle).
Compute V, F, unique edges E, boundary edges, Euler characteristic, and infer
boundary loops / holes. This dictates the EdgeBreaker opcode counts to expect."""
import sys
from collections import defaultdict
csv=sys.argv[1]; out=sys.argv[2]
vid={}; faces=0
edge_count=defaultdict(int)
def key(a,b,c): return (round(float(a)*100),round(float(b)*100),round(float(c)*100))
buf=b''; tri=[]
nrows=0
with open(csv,'rb') as f:
    while True:
        ch=f.read(1<<22)
        if not ch: break
        buf=(buf+ch).replace(b'\r',b'\n'); parts=buf.split(b'\n'); buf=parts.pop()
        for line in parts:
            if not line: continue
            try:
                a,b,c=line.split(b','); k=key(a,b,c)
            except Exception: continue
            nrows+=1
            i=vid.get(k)
            if i is None: i=len(vid); vid[k]=i
            tri.append(i)
            if len(tri)==3:
                faces+=1
                for (u,v) in ((tri[0],tri[1]),(tri[1],tri[2]),(tri[2],tri[0])):
                    e=(u,v) if u<v else (v,u)
                    edge_count[e]+=1
                tri=[]
V=len(vid); F=faces; E=len(edge_count)
boundary=sum(1 for c in edge_count.values() if c==1)
nonmanifold=sum(1 for c in edge_count.values() if c>2)
chi=V-E+F
print(f'rows={nrows:,}  V={V:,}  F={F:,}  E={E:,}')
print(f'boundary edges (in 1 tri): {boundary:,}')
print(f'non-manifold edges (in >2 tri): {nonmanifold:,}')
print(f'Euler chi = V-E+F = {chi:,}')
print(f'For orientable surface: chi = 2 - 2g - b  (b=boundary loops, g=genus)')
print(f'2E vs 3F: 2E={2*E:,} 3F={3*F:,}  (interior edges={ (3*F-boundary)//2:,})')
# EdgeBreaker expectation: #C = number of vertices introduced by C ops.
# Standard EB on a mesh with boundary handled by a dummy vertex: #C ~ V - boundary_verts.
import pickle
with open(out,'wb') as fo: pickle.dump({'V':V,'F':F,'E':E,'boundary':boundary,'chi':chi}, fo)
print('saved',out)
