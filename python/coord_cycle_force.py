#!/usr/bin/env python3
"""Force strict X->Y->Z cycle over scalars (complete framing): scalar k gets axis
k%3 (seeds = X,Y,Z at k=0,1,2). FULLs occupy their band's slot: if full band !=
expected axis, report (cycle break). Depth per token = oracle over 0..3 on the
FORCED axis only. Score hits."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
    if not np.isfinite(v): return False
    arr=gA[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return True
    return False
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8])); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb],b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    pos+=1
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
k=3  # scalars 0,1,2 = seeds
hits=Counter(); tot=Counter(); breaks=0; agree=0; nf=0
for t in toks:
    exp=k%3
    if t[0]=='F':
        v=be(t[1]); a=band(v); nf+=1
        if a==exp: agree+=1
        else: breaks+=1
        regs[a][:]=t[1]
        k+=1  # full occupies one cycle slot
        continue
    payload=t[1]; nb=len(payload)
    a=exp
    bestvb=None
    for dep in range(0,4):
        if nb+dep>8: continue
        vb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
        if gt_hit(be(vb),a): bestvb=vb; break
    tot[a]+=1
    if bestvb is not None:
        regs[a][:]=bestvb; hits[a]+=1
    else:
        # keep register unchanged (avoid corruption) but count miss
        pass
    k+=1
print(f'fulls: {nf}  full-band==cycle-slot: {agree}  breaks: {breaks}')
allh=sum(hits.values()); alln=sum(tot.values())
for a,nm in ((0,'X'),(1,'Y'),(2,'Z')):
    print(f'{nm}: {hits[a]}/{tot[a]} = {hits[a]/max(tot[a],1)*100:.1f}%')
print(f'TOTAL: {allh}/{alln} = {allh/alln*100:.1f}%')
