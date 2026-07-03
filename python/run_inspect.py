#!/usr/bin/env python3
"""Inspect an undecoded run: dump tokens with prefix/T-context, fingerprint
candidate summaries (axis histogram), and the committed vertices flanking it."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
import sys
LO=int(sys.argv[1]) if len(sys.argv)>1 else 3080
HI=int(sys.argv[2]) if len(sys.argv)>2 else 3130
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
vals=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
u64=[vals[a].copy().view(np.uint64) for a in range(3)]
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
        toks.append(('F',d[pos:pos+8],lastT,None,pos)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b,pos)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3],None,None,pos)); lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
# NOTE: E tokens included as pseudo-tokens here for display
order=np.load(sp+r'\closing_order.npy',allow_pickle=True)
tokmap={}
for vi,ti in order:
    for a in range(3): tokmap[ti+a]=(vi,a)
n=0
for i,t in enumerate(toks):
    if not (LO<=n<=HI and t[0] in ('V','F','E')):
        if t[0] in ('V','F'): n+=1
        continue
    T=t[2]
    ts=f'{T[0]:02x}{T[1]:02x}' if T else '----'
    mark=''
    if n in tokmap: mark=f' <== v{tokmap[n][0]} {"XYZ"[tokmap[n][1]]}'
    if t[0]=='F':
        print(f'{n:5d} @{t[4]} FULL {be(t[1]):14.3f} T={ts}{mark}')
    elif t[0]=='E':
        print(f'      @{t[4]} EEE {t[1].hex()}')
        continue
    else:
        p=t[3]
        # fingerprint axis histogram
        pI=int.from_bytes(t[1],'big'); nb=len(t[1])
        axh=Counter()
        for a in range(3):
            base=u64[a]
            for k in range(max(0,8-nb-3),8-nb+1):
                sh=8*(8-k-nb)
                mask=((1<<(8*nb))-1)<<sh
                cand=(base & ~np.uint64(mask)) | np.uint64(pI<<sh)
                vv=cand.view(np.float64)
                arr=vals[a]
                idx=np.searchsorted(arr,vv)
                for jj in (idx-1,idx):
                    jj2=np.clip(jj,0,len(arr)-1)
                    ok=np.abs(arr[jj2]-vv)<=0.0006
                    axh[a]+=len(np.unique(jj2[ok]))
        print(f'{n:5d} @{t[4]} p=0x{p:02x} nb={len(t[1])} T={ts} pl={t[1].hex():16s} fpAxes={dict(axh)}{mark}')
    n+=1
