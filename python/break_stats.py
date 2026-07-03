#!/usr/bin/env python3
"""Histogram token contexts at chain-break points: for each undecoded run start
(from closing_order coverage), record the first tokens' prefixes/T-bytes."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
order=np.load(sp+r'\closing_order.npy',allow_pickle=True)
covered=np.zeros(N,bool)
for vi,ti in order: covered[ti:ti+3]=True
# break starts
pc=Counter(); tc=Counter(); nb_c=Counter()
nb_all=Counter(); pall=Counter()
for t in toks:
    if t[0]=='V': pall[t[3]]+=1
starts=[]
i=0
while i<N:
    if not covered[i] and (i==0 or covered[i-1]):
        starts.append(i)
        for j in range(i,min(i+2,N)):
            t=toks[j]
            if t[0]=='V':
                pc[t[3]]+=1
                T=t[2]; tc[(T[0]>>4 if T else -1)]+=1
    i+=1
print(f'break starts: {len(starts)}')
print('prefix at break (first 2 toks):',pc.most_common(12))
print('  vs overall prefix distribution:',pall.most_common(8))
print('T1 hi-nibble at break:',tc.most_common(8))
