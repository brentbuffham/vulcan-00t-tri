#!/usr/bin/env python3
"""Extract decoder rule tables from the 74.7% solved stream (closing_order.npy).
Replay committed vertices in token order, maintain registers, and for each
committed token determine which placement (end 8/7/6) reproduced the known value.
Tables: (p,T1,T2)->end ; window-kind signatures. Save JSON."""
import struct, json
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
TOL=0.0006
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
# token -> (axis, value) from committed vertices
tokval={}
for vi,ti in order:
    vx,vy,vz=Gu[vi]
    for a,tv in ((0,vx),(1,vy),(2,vz)):
        if 0<=ti+a<N: tokval[ti+a]=(a,tv)
# replay: registers from best-effort; extract end per committed V-token
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
tabEnd=defaultdict(Counter)
nlab=0
for i,t in enumerate(toks):
    if t[0]=='F':
        v=be(t[1]); regs[band(v)][:]=t[1]; continue
    if i not in tokval: continue
    a,tv=tokval[i]
    payload=t[1]; nb=len(payload)
    endc=None; vbc=None
    for end in (8,7,6):
        k0=end-nb
        if k0<0: continue
        vb=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
        if abs(be(vb)-tv)<=TOL: endc=end; vbc=vb; break
    if endc is None:
        # self-fit fallback (register was stale) — mark but use target bytes
        tb=struct.pack('>d',tv)
        for end in (8,7,6):
            k0=end-nb
            if k0<0: continue
            vb=bytes(tb[:k0])+payload+bytes(tb[end:])
            if abs(be(vb)-tv)<=TOL: endc=end; vbc=vb; break
    if endc is None:
        regs[a][:]=struct.pack('>d',tv); continue
    regs[a][:]=vbc
    T=t[2]; p=t[3]
    tabEnd[(p,T[0] if T else -1,T[1] if T else -1)][endc]+=1
    nlab+=1
tot=pure=0
for k,c in tabEnd.items():
    n=sum(c.values()); tot+=n; pure+=c.most_common(1)[0][1]
print(f'labels {nlab}; (p,T1,T2)->end purity {pure}/{tot} = {pure/max(tot,1)*100:.1f}% over {len(tabEnd)} contexts')
# fallback purities
for name,proj in (('(p,T2)',lambda k:(k[0],k[2])),('(p,T1)',lambda k:(k[0],k[1])),('(p,)',lambda k:(k[0],)),
                  ('(p,T2hi5)',lambda k:(k[0],k[2]>>3 if k[2]>=0 else -1)),
                  ('(p,T1lo5,T2hi5)',lambda k:(k[0],k[1]&0x1f if k[1]>=0 else -1,k[2]>>3 if k[2]>=0 else -1))):
    t2=defaultdict(Counter)
    for k,c in tabEnd.items():
        for e,n in c.items(): t2[proj(k)][e]+=n
    tt=pp=0
    for k,c in t2.items():
        n=sum(c.values()); tt+=n; pp+=c.most_common(1)[0][1]
    print(f'  fallback {name}: {pp/max(tt,1)*100:.1f}% over {len(t2)} ctx')
out={f'{k[0]},{k[1]},{k[2]}':dict(c) for k,c in tabEnd.items()}
json.dump(out,open(sp+r'\end_table.json','w'))
print('saved end_table.json')
