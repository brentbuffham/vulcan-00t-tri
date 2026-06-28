#!/usr/bin/env python3
"""Structure LABELING (discovery): snap each coord to its exact GT value so the running
point can't drift, so the GT-vertex boundary detector fires cleanly and reconstructs the
true vertex sequence + order/dedup pattern. GT used to LABEL structure only. Output: how
many vertices reconstruct, and the per-record (axis, full/delta) trace with boundaries,
so we can read the GT-free boundary/axis rule off the bytes."""
import sys, struct
import numpy as np
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gset=set(zip(np.round(G[:,0]*100).astype(int),np.round(G[:,1]*100).astype(int),np.round(G[:,2]*100).astype(int)))
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def snap(v,a,tol):
    arr=gA[a]; i=np.searchsorted(arr,v); c=[arr[j] for j in (i-1,i) if 0<=j<len(arr)]
    if not c: return None
    b=min(c,key=lambda x:abs(x-v)); return b if abs(b-v)<=tol else None
def in_gt(x,y,z): return (round(x*100),round(y*100),round(z*100)) in gset
d=open(oot,'rb').read()
# face block = the DENSE run of short e0 03 records (not the lone coord-section marker).
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k] < 90:  # 3 e0 03 within 90 bytes = dense face run
        face_start=occ[k]; break
print(f'[coord section 8326..{face_start}]')
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
cur=[snap(be(d[8326:8334]),0,1),snap(be(d[8334:8342]),1,1),snap(be(d[8342:8350]),2,1)]
prevb=[d[8326:8334],d[8334:8342],d[8342:8350]]
got=set(); trace=[]; recs=[]; pos=8350; nres=0
if in_gt(*cur): got.add((round(cur[0]*100),round(cur[1]*100),round(cur[2]*100)))
def step(a,kind,recbytes):
    boundary=in_gt(*cur)
    if boundary: got.add((round(cur[0]*100),round(cur[1]*100),round(cur[2]*100)))
    if len(trace)<80: trace.append('XYZ'[a]+kind+('|' if boundary else ''))
    recs.append((a,kind,boundary,recbytes))
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); a=band(v); s=snap(v,a,1)
        if s is not None: cur[a]=s; prevb[a]=struct.pack('>d',s); step(a,'F',d[pos:pos+8].hex())
        pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            # choose axis: prefer one that, snapped, completes a GT vertex; else nearest moved
            comp=None; mid=None
            for a in range(3):
                cand=be(bytes(prevb[a][:3])+d[rec_end-5:rec_end])
                s=snap(cand,a,3)
                if s is None or abs(s-cur[a])<0.03: continue
                save=cur[a]; cur[a]=s; ok=in_gt(*cur); cur[a]=save
                if ok and comp is None: comp=(a,s)
                if mid is None: mid=(a,s)
            pick=comp or mid
            if pick: a,s=pick; cur[a]=s; prevb[a]=struct.pack('>d',s); step(a,'d',d[pos:rec_end].hex())
            else: nres+=1
            pos=rec_end; continue
    nres+=1; pos+=1
print(f'reconstructed GT vertices = {len(got):,} / {len(gset):,} = {len(got)/len(gset)*100:.1f}%   unresolved-records={nres:,}')
print('order trace (| = a real vertex completed):')
print(' '+' '.join(trace))
# boundary rule hint: what kind/axis precedes each boundary
bx=[(recs[i][0],recs[i][1]) for i in range(len(recs)) if recs[i][2]]
from collections import Counter
print('axis+kind that COMPLETES a vertex:', Counter(f'{"XYZ"[a]}{k}' for a,k in bx).most_common())
