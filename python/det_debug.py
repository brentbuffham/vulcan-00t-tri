#!/usr/bin/env python3
"""Deterministic-rule debugger: run the strict-cycle + prefix-depth decoder;
at each V-token, when the deterministic value misses the GT grid, ask the oracle
(all axis/depth/splits) what works, ADOPT it (to continue), and log the diff:
(prefix, T-bytes, phase, det-choice vs oracle-choice). Print first 40 diffs +
summary stats of diff kinds."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
gA=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
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
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
slot=3
pos=8350
lastT=None
diffs=[]; nv=0; agree=0
kinds=Counter()
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        v=be(d[pos:pos+8]); fb=band(v)
        regs[fb][:]=d[pos:pos+8]
        exp=slot%3
        if fb!=exp: kinds[f'full_resync_{exp}->{fb}']+=1
        slot=slot-(slot%3)+fb+1
        pos+=8; lastT=None; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1; dep=b>>3
        payload=d[pos+1:pos+1+nb]
        a=slot%3; nv+=1
        detv=None
        if nb+dep<=8:
            detb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
            detv=be(detb)
        if detv is not None and gt_hit(detv,a):
            regs[a][:]=detb; slot+=1; agree+=1
        else:
            # oracle: single any axis/depth, then split
            found=None
            for a2 in range(3):
                for dep2 in range(0,4):
                    if nb+dep2>8: continue
                    vb=bytes(regs[a2][:8-nb-dep2])+payload+(bytes(regs[a2][8-dep2:]) if dep2 else b'')
                    if gt_hit(be(vb),a2): found=('single',a2,dep2,vb); break
                if found: break
            if not found:
                for k2 in range(1,nb):
                    h,tl=payload[:k2],payload[k2:]; f2=None
                    for a2 in range(3):
                        va=bytes(regs[a2][:8-k2])+h
                        if not gt_hit(be(va),a2): continue
                        for b2 in range(3):
                            if b2==a2: continue
                            vb2=bytes(regs[b2][:8-(nb-k2)])+tl
                            if gt_hit(be(vb2),b2): f2=('split',a2,b2,va,vb2,k2); break
                        if f2: break
                    if f2: found=f2; break
            if found:
                if found[0]=='single':
                    _,a2,dep2,vb=found
                    kinds[f'ax{a}->ax{a2} dep{dep}->dep{dep2}']+=1
                    if len(diffs)<40:
                        diffs.append(f'@{pos} p=0x{b:02x} T={lastT.hex() if lastT else "--"} phase={a} det=(a{a},d{dep}) oracle=(a{a2},d{dep2})')
                    regs[a2][:]=vb
                    # slot advance: if oracle axis == expected, normal; else resync
                    if a2==a: slot+=1
                    else: slot=slot-(slot%3)+a2+1
                else:
                    _,a2,b2,va,vb2,k2=found
                    kinds[f'split {("XYZ")[a2]}+{("XYZ")[b2]}@{k2}']+=1
                    if len(diffs)<40:
                        diffs.append(f'@{pos} p=0x{b:02x} T={lastT.hex() if lastT else "--"} phase={a} det=(a{a},d{dep}) oracle=SPLIT({("XYZ")[a2]},{("XYZ")[b2]},{k2})')
                    regs[a2][:]=va; regs[b2][:]=vb2
                    slot=slot-(slot%3)+b2+1
            else:
                kinds['unrescuable']+=1
                slot+=1
        pos+=1+nb; lastT=None; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        lastT=d[pos:pos+2]; pos+=2; continue
    pos+=1
print(f'V-tokens: {nv}  det-rule agreed: {agree} ({agree/nv*100:.1f}%)')
print('\ndiff kinds:',kinds.most_common(20))
print('\nfirst diffs:')
for s in diffs[:30]: print(' ',s)
