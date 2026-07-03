#!/usr/bin/env python3
"""Diagnose beam-path misses: cluster locations, and for each missed V-token test
alternatives: other-axis splice, inner-offset splice (payload at byte offsets 1..4
from the end), signed-add delta. Report which alternative rescues most misses."""
import sys, struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
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
        toks.append(('F',d[pos:pos+8],pos)); pos+=8; continue
    if b<=0x06 and pos+1+b+1<=face_start:
        toks.append(('V',d[pos+1:pos+1+b+1],pos)); pos+=1+b+1; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3],pos)); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2],pos)); pos+=2; continue
    toks.append(('S',bytes([b]),pos)); pos+=1
# greedy replay using ORACLE: pick any axis+mode that hits GT; track what rescues
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
modes=Counter(); misspos=[]
nlab=0; nmiss=0
seq=[]
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]; seq.append((a,v,'F')); continue
    if t[0]!='V': continue
    payload=t[1]; nb=len(payload)
    found=None
    for a in range(3):
        vb=bytes(regs[a][:8-nb])+payload
        if band(be(vb))==a and gt_hit(be(vb),a): found=(a,vb,'tail'); break
    if not found:
        # inner splice: payload ends at byte 8-off (off=1..3 from end)
        for off in (1,2,3):
            for a in range(3):
                if nb+off<=8:
                    vb=bytes(regs[a][:8-nb-off])+payload+bytes(regs[a][8-off:])
                    if band(be(vb))==a and gt_hit(be(vb),a): found=(a,vb,f'inner{off}'); break
            if found: break
    if not found:
        # signed add on int64
        for a in range(3):
            delta=int.from_bytes(payload,'big',signed=True)
            u=struct.unpack('>Q',bytes(regs[a]))[0]
            vb=struct.pack('>Q',(u+delta)&0xFFFFFFFFFFFFFFFF)
            if band(be(vb))==a and gt_hit(be(vb),a): found=(a,vb,'add'); break
    if found:
        a,vb,mode=found; regs[a][:]=vb; modes[mode]+=1; nlab+=1; seq.append((a,be(vb),mode))
    else:
        nmiss+=1; misspos.append(t[2]); seq.append((-1,None,'miss'))
print(f'oracle-labeled: {nlab}  miss: {nmiss}  modes: {modes.most_common()}')
# miss clustering
mp=np.array(misspos)
if len(mp):
    hist,edges=np.histogram(mp,bins=20,range=(8350,face_start))
    print('miss density over file (20 bins):',hist.tolist())
# axis counts
axc=Counter(s[0] for s in seq if s[0] is not None and s[0]>=0)
print('axis counts (oracle): X=%d Y=%d Z=%d  (target 2975 each)'%(axc[0],axc[1],axc[2]))
# hex dump around first 3 misses
for p in misspos[:3]:
    print(f'\n@{p}: '+' '.join(f'{b:02x}' for b in d[p-16:p+16]))
