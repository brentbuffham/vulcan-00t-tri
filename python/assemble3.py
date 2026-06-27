#!/usr/bin/env python3
"""Assembly v3: Z-terminated vertices with Y-dedup. Observed order: Z always FULL and
present (height, terminates a vertex); X delta-or-full; Y FULL only when it changes
(carried otherwise). Rule: FULL band-Z -> set Z, EMIT (curX,curY,curZ); FULL band-X ->
curX; FULL band-Y -> curY; DELTA -> X (splice k=count+1 onto X prev). Score 3D vs GT."""
import sys, struct
import numpy as np
from scipy.spatial import cKDTree
oot=sys.argv[1]; gtcsv=sys.argv[2]; KRULE=sys.argv[3] if len(sys.argv)>3 else 'cnt'
G=np.loadtxt(gtcsv,delimiter=','); tree=cKDTree(G)
d=open(oot,'rb').read()
face_start=next((i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03), len(d))
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
curX=curY=curZ=None; prevXb=None; pos=8326; verts=[]; ndelta=nesc=0
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); b=band(v)
        if b==2:
            curZ=v
            if None not in (curX,curY,curZ): verts.append((curX,curY,curZ))
        elif b==0: curX=v; prevXb=d[pos:pos+8]
        else: curY=v
        pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start and prevXb is not None:
            k=min((count+1) if KRULE=='cnt' else int(KRULE),7)
            val=be(bytes(prevXb[:8-k])+d[rec_end-k:rec_end])
            curX=val; prevXb=struct.pack('>d',val); ndelta+=1
            pos=rec_end; continue
    nesc+=1; pos+=1
P=np.array(verts)
print(f'rule k={KRULE}: deltas={ndelta} esc={nesc} verts={len(P):,}  GT={len(G):,}')
for tol in (0.1,0.5,1.0,2.0):
    dd,idx=tree.query(P,distance_upper_bound=tol); hit=np.isfinite(dd)
    uniq=len(np.unique(idx[hit])) if hit.any() else 0
    print(f'  tol={tol}m vert-hits={hit.sum():,} uniqueGT={uniq:,} recall={uniq/len(G)*100:.1f}%')
