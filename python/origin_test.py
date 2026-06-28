#!/usr/bin/env python3
"""Test Brent's hypothesis: are deltas relative to the ORIGIN (seed) or the PREVIOUS
point? For each delta, splice the low bytes onto (a) the running prev of each axis and
(b) the SEED bytes of each axis; count how many land on an EXACT GT coordinate. Whichever
base yields more exact hits is the real reference. Also reports per-axis where it hits."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gA=[set(np.round(G[:,a],3).tolist()) for a in range(3)]
def hit(v,a): return round(v,3) in gA[a]
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
seed=[d[8326:8334],d[8334:8342],d[8342:8350]]
prevb=[d[8326:8334],d[8334:8342],d[8342:8350]]
pos=8350; prevhit=Counter(); orighit=Counter(); nd=0
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); prevb[band(v)]=d[pos:pos+8]; pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            nd+=1; low=d[rec_end-5:rec_end]
            ph=oh=None
            for a in range(3):
                if hit(be(bytes(prevb[a][:3])+low),a): ph=a
                if hit(be(bytes(seed[a][:3])+low),a): oh=a
            if ph is not None: prevhit[ph]+=1; prevb[ph]=bytes(prevb[ph][:3])+low+bytes(5)  # rough update
            if oh is not None: orighit[oh]+=1
            pos=rec_end; continue
    pos+=1
print(f'deltas={nd:,}')
print(f'PREV-relative exact GT hits:   {sum(prevhit.values()):,} ({sum(prevhit.values())/nd*100:.0f}%)  by axis {dict(prevhit)}')
print(f'ORIGIN-relative exact GT hits: {sum(orighit.values()):,} ({sum(orighit.values())/nd*100:.0f}%)  by axis {dict(orighit)}')
