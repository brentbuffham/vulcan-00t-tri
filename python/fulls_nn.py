#!/usr/bin/env python3
"""Spacing of FULLS-ONLY vertices (exact, no delta guesswork). Scan the coord section
for runs of 3 consecutive band-distinct FULL doubles = a fully-exact vertex; compute
plan NN spacing. These positions are trustworthy (V1/V2 verified), so their spacing is
the honest test of the drill pattern (~5 or ~8.5 m)."""
import sys, struct
import numpy as np
from scipy.spatial import cKDTree
f=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(f,'rb').read()
hdr=struct.unpack('<15i',d[0:60])
face_start=next((i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03), len(d))
def be(o): return struct.unpack('>d',d[o:o+8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def full(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return None
    v=be(o)
    if (400<abs(v)<900) or (54000<abs(v)<58000) or (158000<abs(v)<166000): return v
    return None
verts=[]; o=8326; cur={}
while o<face_start-8:
    v=full(o)
    if v is not None:
        b=band(v)
        if b in cur: cur={}
        cur[b]=v; o+=8
        if len(cur)==3: verts.append((cur[0],cur[1],cur[2])); cur={}
    else:
        cur={}; o+=1   # break run on any non-full
P=np.array(verts)
print(f'all-FULL vertices = {len(P):,}')
if len(P)>3:
    print(f' bbox X[{P[:,0].min():.1f},{P[:,0].max():.1f}] Y[{P[:,1].min():.1f},{P[:,1].max():.1f}] Z[{P[:,2].min():.2f},{P[:,2].max():.2f}]')
    t=cKDTree(P[:,:2]); dd,_=t.query(P[:,:2],k=2); nn=dd[:,1]; nn=nn[np.isfinite(nn)]
    print(f' plan NN: median={np.median(nn):.2f}m mean={nn.mean():.2f}m  %in[4,6]={np.mean((nn>=4)&(nn<=6))*100:.0f} %in[7,9]={np.mean((nn>=7)&(nn<=9))*100:.0f}')
    h,e=np.histogram(nn[nn<15],bins=np.arange(0,15,0.5)); top=np.argsort(h)[-6:][::-1]
    print('  top NN bins:', ', '.join(f'{e[i]:.1f}:{h[i]}' for i in top))
