#!/usr/bin/env python3
"""NON-CIRCULAR calibration: decode purely from bytes (prev only ever holds DECODED
values, never GT), then score whole VERTICES (3D) against GT vertices. Try splice
length rule via argv: 'cnt' = k=count+1, or a fixed int. FULL axis=band, DELTA fills
missing slot in X,Y,Z order. Reports 3D vertex recall at several tolerances."""
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
prevb=[None,None,None]; pos=8326; filled={}; verts=[]; nfull=ndelta=nesc=0
def flush():
    global filled
    if len(filled)==3: verts.append((filled[0],filled[1],filled[2]))
    filled={}
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); ax=band(v)
        if ax in filled: flush()
        prevb[ax]=d[pos:pos+8]; filled[ax]=v; nfull+=1; pos+=8
        if len(filled)==3: flush()
        continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            k = (count+1) if KRULE=='cnt' else int(KRULE)
            k=min(k,7)
            miss=[a for a in range(3) if a not in filled and prevb[a] is not None]
            ax=miss[0] if miss else None
            if ax is not None:
                val=be(bytes(prevb[ax][:8-k])+d[rec_end-k:rec_end])
                prevb[ax]=struct.pack('>d',val); filled[ax]=val; ndelta+=1
                pos=rec_end
                if len(filled)==3: flush()
                continue
    nesc+=1; pos+=1
P=np.array(verts)
print(f'rule k={KRULE}: fulls={nfull} deltas={ndelta} esc={nesc} verts={len(P):,}')
for tol in (0.1,0.5,1.0,2.0):
    dd,_=tree.query(P,distance_upper_bound=tol); hit=np.isfinite(dd)
    dd2,idx=tree.query(P[hit]) if hit.any() else (None,np.array([],int))
    uniq=len(np.unique(idx)) if hit.any() else 0
    print(f'  tol={tol}m: vert-hits={hit.sum():,} uniqueGT={uniq:,} recall={uniq/len(G)*100:.1f}%')
