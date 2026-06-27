#!/usr/bin/env python3
"""Assembly via BAND-RESYNC cycle. Values decode right (seed exact); problem is
grouping coords into XYZ triples. Walk coords; maintain X->Y->Z cycle; a FULL's band
tells its true axis -> if band != cycle pos, a coord was missed: RESYNC cycle to band.
DELTA follows the cycle. Emit a vertex when the cycle wraps. Score 3D vs GT (no GT in
decode). Also dump first coords' (band,kind) to see the true order."""
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
prevb=[None,None,None]; cur=[None,None,None]; pos=8326; cyc=0; verts=[]; dump=[]
def emit():
    if None not in cur: verts.append(tuple(cur))
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); ax=band(v)
        if len(dump)<30: dump.append(f'{"XYZ"[ax]}F')
        prevb[ax]=d[pos:pos+8]; cur[ax]=v; cyc=(ax+1)%3
        if ax==2: emit()
        pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            k=min((count+1) if KRULE=='cnt' else int(KRULE),7)
            ax=cyc
            if prevb[ax] is not None:
                val=be(bytes(prevb[ax][:8-k])+d[rec_end-k:rec_end])
                if len(dump)<30: dump.append(f'{"XYZ"[ax]}d')
                prevb[ax]=struct.pack('>d',val); cur[ax]=val; cyc=(cyc+1)%3
                if ax==2: emit()
            pos=rec_end; continue
    pos+=1
P=np.array(verts)
print('first coords order:', ' '.join(dump))
print(f'verts={len(P):,}')
for tol in (0.1,0.5,1.0):
    dd,idx=tree.query(P,distance_upper_bound=tol); hit=np.isfinite(dd)
    uniq=len(np.unique(idx[hit])) if hit.any() else 0
    print(f'  tol={tol}m uniqueGT={uniq:,} recall={uniq/len(G)*100:.1f}%')
