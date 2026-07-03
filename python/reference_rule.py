#!/usr/bin/env python3
"""Reference-rule extraction from the 98.3% answer key.
For each labeled token (axis a, value w): find which earlier same-axis value u
works as splice reference: pack(u) and pack(w) agree outside the payload window
(compare stable bytes 0..6 only), and pack(w)'s window bytes == payload tail.
Reference candidates: dist-1 (previous value), dist 2..6, last FULL value on a,
first value of current 'run'. Histogram which reference class wins, split by
context (p, T1, whether prev step was a big jump)."""
import struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
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
tokval={}
for vi,ti in order:
    for a in range(3):
        if 0<=ti+a<N: tokval[ti+a]=(a,Gu[vi][a])
# history per axis in token order
hist=[[] for _ in range(3)]   # values in stream order per axis
lastfull=[None,None,None]
refstat=Counter()
ctxstat=defaultdict(Counter)
unexplained=0; total=0
seq=sorted(tokval)
for i in seq:
    t=toks[i]
    a,w=tokval[i]
    if t[0]=='F':
        lastfull[a]=w; hist[a].append(w); continue
    payload=t[1]; nb=len(payload)
    # candidate refs; VALUE-space check: splice(u, payload@[r,end]) ~= w
    found=None
    cands=[]
    hh=hist[a]
    for dist in range(1,7):
        if len(hh)>=dist: cands.append((f'prev{dist}',hh[-dist]))
    if lastfull[a] is not None: cands.append(('lastfull',lastfull[a]))
    for name,u in cands:
        ub=struct.pack('>d',u)
        for r in (0,1,2):
            if nb-r<1: break
            pl=payload[r:]
            for end in (8,7,6):
                k0=end-(nb-r)
                if k0<0: continue
                v=be(bytes(ub[:k0])+pl+bytes(ub[end:]))
                if np.isfinite(v) and abs(v-w)<=0.0006:
                    found=(name,r,end); break
            if found: break
        if found: break
    total+=1
    if found:
        name,r,end=found
        refstat[name]+=1
        p=t[3]; T=t[2]
        ctxstat[(name)][(p,T[0] if T else -1)]+=0  # placeholder
    else:
        unexplained+=1
    hist[a].append(w)
print(f'labeled tokens: {total}  unexplained: {unexplained} ({unexplained/max(total,1)*100:.1f}%)')
print('reference class histogram:',refstat.most_common())
