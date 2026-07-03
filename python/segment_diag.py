#!/usr/bin/env python3
"""Diagnose segment decode: scalar hit rate by axis, by segment length, and
failure clustering. Reuses segment_decode machinery via exec."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
vals=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
    if not np.isfinite(v): return False
    arr=vals[a]; i=np.searchsorted(arr,v)
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
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
labels=np.load(sp+r'\fp2_labels.npy',allow_pickle=True)
anch=[(i,l[1],l[2]) for i,l in enumerate(labels) if l[0]=='U']
for i,t in enumerate(toks):
    if t[0]=='F':
        v=be(t[1]); anch.append((i,band(v),round(v,3)))
anch=sorted(set(anch))
seen=set(); anch=[a for a in anch if not (a[0] in seen or seen.add(a[0]))]
gaps=[a2[0]-a1[0] for a1,a2 in zip(anch,anch[1:])]
print('anchor gap: median',int(np.median(gaps)),'p90',int(np.percentile(gaps,90)),'max',max(gaps))
# how much of the file is within gap<=3 of an anchor?
big=sum(g-1 for g in gaps if g>6)
print(f'tokens in gaps>6: {big} ({big/len(toks)*100:.0f}%)')
# consistency including 2-event possibility:
ok1=ok0=bad=0
for (i1,a1,_),(i2,a2,_) in zip(anch,anch[1:]):
    if (i2-i1)%3==(a2-a1)%3: ok0+=1
    else: bad+=1
print(f'consistent {ok0} vs inconsistent {bad}')
# axis composition of anchors
print('anchor axes:',Counter(a for _,a,_ in anch))
