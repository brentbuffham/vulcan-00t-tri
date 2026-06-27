#!/usr/bin/env python3
"""DIAGNOSTIC decode: prove the misalignment is AXIS, not scale. Splice k=5 (the
calibrated rule); resolve each delta's axis by which axis's splice lands on a TRUE GT
coordinate (GT used ONLY to pick the axis slot, to isolate the open axis-rule).
Assemble vertices (new vertex when an axis repeats; carry unfilled). Output cloud +
recall. If this aligns ~72%, the values are right and only the axis rule is missing."""
import sys, struct
import numpy as np
from scipy.spatial import cKDTree
oot=sys.argv[1]; gtcsv=sys.argv[2]; out=sys.argv[3]
G=np.loadtxt(gtcsv,delimiter=','); tree=cKDTree(G)
gax=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gmatch(v,a,tol=0.01):
    arr=gax[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return arr[j]
    return None
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
prevb=[None,None,None]; prevv=[None,None,None]; cur=[None,None,None]; seen=set(); verts=[]; pos=8326
def assign(a,val):
    global seen,cur
    if a in seen:
        if None not in cur: verts.append(tuple(cur))
        seen={a}
    else: seen.add(a)
    cur[a]=val; prevb[a]=struct.pack('>d',val); prevv[a]=val
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); a=band(v); m=gmatch(v,a); assign(a, m if m is not None else v); pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            picked=None
            for a in range(3):
                if prevb[a] is None: continue
                val=be(bytes(prevb[a][:3])+d[rec_end-5:rec_end])
                m=gmatch(val,a)
                if m is not None and abs(m-prevv[a])>0.05: picked=(a,m); break
            if picked: assign(*picked)
            pos=rec_end; continue
    pos+=1
if None not in cur: verts.append(tuple(cur))
P=np.array(verts); np.savetxt(out,P,fmt='%.4f',delimiter=',')
dd,idx=tree.query(P,distance_upper_bound=1.0); hit=np.isfinite(dd)
print(f'verts={len(P):,} matched<1m={hit.sum():,} uniqueGT={len(np.unique(idx[hit])):,}/{len(G):,} recall={len(np.unique(idx[hit]))/len(G)*100:.1f}%')
