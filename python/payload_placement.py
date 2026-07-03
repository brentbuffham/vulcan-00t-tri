#!/usr/bin/env python3
"""Empirical payload-placement study. Use oracle decode to get verified
(register-before, value-after, token) triples. For each hit, find ALL positions k
where payload == double_after[k:k+nb]; also check double_before and double_after
share bytes outside [k,k+nb). Histogram k by prefix p (and by axis, nb)."""
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
place=defaultdict(Counter)   # p -> placement k (with axis)
placeax=defaultdict(Counter)
pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        v=be(d[pos:pos+8]); regs[band(v)][:]=d[pos:pos+8]; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        payload=d[pos+1:pos+1+nb]
        # oracle: any axis, any placement k (0..8-nb)
        found=None
        for a in range(3):
            r=regs[a]
            for k2 in range(0,9-nb):
                vb=bytes(r[:k2])+payload+bytes(r[k2+nb:])
                if gt_hit(be(vb),a):
                    found=(a,k2,vb); break
            if found: break
        if found:
            a,k2,vb=found
            regs[a][:]=vb
            place[b][k2]+=1
            placeax[(b,'XYZ'[a])][k2]+=1
        pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    pos+=1
print('prefix -> placement-start histogram (start byte k of payload in the double):')
for p in sorted(place):
    c=place[p]; n=sum(c.values())
    print(f'  p=0x{p:02x} (nb={(p&7)+1}, hi={p>>3}): n={n:5d}  {dict(sorted(c.items()))}')
print('\nby (prefix,axis) for the big ones:')
for key in sorted(placeax,key=lambda k:-sum(placeax[k].values()))[:16]:
    c=placeax[key]; n=sum(c.values())
    print(f'  p=0x{key[0]:02x},{key[1]}: n={n:5d}  {dict(sorted(c.items()))}')
