#!/usr/bin/env python3
"""Fingerprint v2 (value-space): for each V-token, splice its payload at each
placement k into ALL GT doubles per axis (vectorized uint64); keep results that
land within 0.6mm of a GT value on that axis. Unique landing VALUE across
(axis,k,source) => certain label. Report: certainty coverage, axis sequence,
transition stats, (p,T1,T2)->k purity on certain labels."""
import struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
vals=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
u64=[vals[a].view(np.uint64) if vals[a].dtype==np.float64 else None for a in range(3)]
u64=[vals[a].copy().view(np.uint64) for a in range(3)]
def near_idx(v,a,tol=0.0006):
    arr=vals[a]; i=np.searchsorted(arr,v)
    out=[]
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: out.append(j)
    return out
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
NV=[len(v) for v in vals]
labels=[]
nu=nm=nz=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v)
        labels.append(('F',a,None,None)); continue
    payload=t[1]; nb=len(payload); pI=int.from_bytes(payload,'big')
    hits=set(); ksfound=defaultdict(set)
    for a in range(3):
        base=u64[a]
        for k in range(max(0,8-nb-3),8-nb+1):
            sh=8*(8-k-nb)
            mask=((1<<(8*nb))-1)<<sh
            cand=(base & ~np.uint64(mask)) | np.uint64(pI<<sh)
            vv=cand.view(np.float64)
            # proximity to own-axis grid
            arr=vals[a]
            idx=np.searchsorted(arr,vv)
            for jj in (idx-1,idx):
                jj2=np.clip(jj,0,len(arr)-1)
                ok=np.abs(arr[jj2]-vv)<=0.0006
                for tgt in np.unique(jj2[ok]):
                    hits.add((a,round(arr[tgt],3)))
                    ksfound[(a,round(arr[tgt],3))].add(k)
    if len(hits)==1:
        (a,w)=next(iter(hits))
        labels.append(('U',a,w,tuple(sorted(ksfound[(a,w)])))); nu+=1
    elif len(hits)==0:
        labels.append(('0',None,None,None)); nz+=1
    else:
        labels.append(('M',None,None,None)); nm+=1
print(f'unique={nu} multi={nm} zero={nz} fulls={sum(1 for t in toks if t[0]=="F")}')
seq=[(i,l[1]) for i,l in enumerate(labels) if l[0] in ('U','F')]
trans=Counter()
for (i1,a1),(i2,a2) in zip(seq,seq[1:]):
    if i2==i1+1: trans[(a2-a1)%3]+=1
print('adjacent-certain transitions:',dict(trans))
print('certain axis counts:',Counter(a for _,a in seq))
axstr=''.join('XYZ'[a] for _,a in seq[:120])
print('certain axis string:',axstr)
# placement purity on certain single-k labels
tab=defaultdict(Counter)
for t,l in zip(toks,labels):
    if t[0]=='V' and l[0]=='U' and len(l[3])==1:
        p=t[3]; T=t[2]
        tab[(p,T[0] if T else -1,T[1] if T else -1)][l[3][0]+ (p&7)+1]+=1
tot=pure=0
for k,c in tab.items():
    n=sum(c.values()); tot+=n; pure+=c.most_common(1)[0][1]
print(f'(p,T1,T2)->end purity on CERTAIN: {pure}/{tot} = {pure/max(tot,1)*100:.1f}% ({len(tab)} ctx)')
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\fp2_labels.npy',np.array(labels,dtype=object),allow_pickle=True)
