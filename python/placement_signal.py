#!/usr/bin/env python3
"""Does the preceding T-token signal payload placement (end at byte 7 vs 8)?
Tabulate (p, T1, T2) -> placement k purity on oracle-verified tokens.
Also test axis signal: (T1,T2) -> axis."""
import struct
import numpy as np
from collections import Counter, defaultdict
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
tabEnd=defaultdict(Counter)   # (p, T2 hi5) -> end position (k+nb)
tabAx=defaultdict(Counter)    # (T1, T2 low3?) -> axis
tabAx2=defaultdict(Counter)   # T1 full -> axis
pos=8350; lastT=None
prevax=2
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        v=be(d[pos:pos+8]); regs[band(v)][:]=d[pos:pos+8]; prevax=band(v); pos+=8; lastT=None; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        payload=d[pos+1:pos+1+nb]
        found=None
        for a in range(3):
            r=regs[a]
            for k2 in range(0,9-nb):
                vb=bytes(r[:k2])+payload+bytes(r[k2+nb:])
                if gt_hit(be(vb),a): found=(a,k2,vb); break
            if found: break
        if found:
            a,k2,vb=found
            regs[a][:]=vb
            if lastT is not None:
                t1,t2=lastT
                tabEnd[(b,t2)][k2+nb]+=1
                tabAx[(t1,(a-prevax)%3)]['x']+=0  # placeholder
                tabAx2[(t1,t2)][(a-prevax)%3]+=1
            prevax=a
        pos+=1+nb; lastT=None; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; lastT=None; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
def purity(tab):
    tot=pure=0
    for k,c in tab.items():
        n=sum(c.values()); tot+=n; pure+=c.most_common(1)[0][1]
    return pure,tot
p1,t1_=purity(tabEnd)
print(f'(p,T2) -> payload END purity: {p1}/{t1_} = {p1/max(t1_,1)*100:.1f}%')
rows=sorted(tabEnd.items(),key=lambda kv:-sum(kv[1].values()))[:20]
for key,c in rows:
    n=sum(c.values())
    print(f'  p=0x{key[0]:02x} T2=0x{key[1]:02x}: n={n:4d} ends {dict(sorted(c.items()))}')
p2,t2_=purity(tabAx2)
print(f'\n(T1,T2) -> axis-transition purity: {p2}/{t2_} = {p2/max(t2_,1)*100:.1f}%')
rows=sorted(tabAx2.items(),key=lambda kv:-sum(kv[1].values()))[:20]
for key,c in rows:
    n=sum(c.values())
    print(f'  T1=0x{key[0]:02x} T2=0x{key[1]:02x}: n={n:4d} trans {dict(sorted(c.items()))}')
