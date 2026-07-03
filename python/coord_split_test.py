#!/usr/bin/env python3
"""Split-payload hypothesis (W11-13 'inner-Y'): a V-token payload may hold TWO
axis updates: head bytes -> axis A splice, tail bytes -> axis B splice.
Sequential oracle: single-axis (any depth) first; else try all splits/axis pairs.
No register update on total miss. Report rescue rates + split patterns."""
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
        toks.append(('F',d[pos:pos+8],pos)); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb],pos,b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    pos+=1
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
single=0; split=0; miss=0; total=0
split_pat=Counter(); single_ax=Counter()
for t in toks:
    if t[0]=='F':
        v=be(t[1]); regs[band(v)][:]=t[1]; continue
    payload=t[1]; nb=len(payload); total+=1
    done=False
    for a in range(3):
        for dep in range(0,4):
            if nb+dep>8: continue
            vb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
            if gt_hit(be(vb),a):
                regs[a][:]=vb; single+=1; single_ax[a]+=1; done=True; break
        if done: break
    if done: continue
    found=None
    for k2 in range(1,nb):
        h,tl=payload[:k2],payload[k2:]
        for a in range(3):
            va=bytes(regs[a][:8-k2])+h
            if not gt_hit(be(va),a): continue
            for b2 in range(3):
                if b2==a: continue
                nb2=nb-k2
                vb2=bytes(regs[b2][:8-nb2])+tl
                if gt_hit(be(vb2),b2):
                    found=(a,va,b2,vb2,k2); break
            if found: break
        if found: break
    if found:
        a,va,b2,vb2,k2=found
        regs[a][:]=va; regs[b2][:]=vb2; split+=1
        split_pat[('XYZ'[a],'XYZ'[b2],k2,nb)]+=1
    else: miss+=1
print(f'total V: {total}  single-hit: {single} ({single/total*100:.1f}%)  split-hit: {split} ({split/total*100:.1f}%)  miss: {miss} ({miss/total*100:.1f}%)')
print('single axis:',dict(single_ax))
print('split patterns (A,B,splitAt,nb):',split_pat.most_common(15))
