#!/usr/bin/env python3
"""Beam v4: complete framing, FREE branching over axis x depth(0..3).
Afterwards: correlate winning (axis,depth) with prefix byte to learn true semantics."""
import sys, struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
BEAM=int(sys.argv[1]) if len(sys.argv)>1 else 250
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
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
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],pos)); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb],pos,b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3],pos)); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2],pos)); pos+=2; continue
    pos+=1
nv=sum(1 for t in toks if t[0]=='V')
HIT=[3.9,3.5,1.0]; MISS=-3.5
beam=[(0.0, d[8326:8334], d[8334:8342], d[8342:8350], ())]
vi=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v)
        beam=[(sc,)+tuple(bytes(t[1]) if i==a else r for i,r in enumerate((rx,ry,rz)))+(ph,) for sc,rx,ry,rz,ph in beam]
        continue
    if t[0]!='V': continue
    payload=t[1]; nb=len(payload)
    cand={}
    for sc,rx,ry,rz,ph in beam:
        regs=(rx,ry,rz)
        for a in range(3):
            r=regs[a]
            for dep in range(0,4):
                if nb+dep>8: continue
                vb=r[:8-nb-dep]+payload+(r[8-dep:] if dep else b'')
                v=be(vb)
                ok=gt_hit(v,a)
                s2=sc+(HIT[a] if ok else MISS)
                rr=[rx,ry,rz]; rr[a]=vb
                key=(rr[0],rr[1],rr[2])
                if key not in cand or cand[key][0]<s2:
                    cand[key]=(s2,rr[0],rr[1],rr[2],ph+((a,dep,ok),))
    beam=sorted(cand.values(),key=lambda x:-x[0])[:BEAM]
    vi+=1
    if vi%2000==0: print(f'  V {vi}/{nv} best={beam[0][0]:.0f}')
best=beam[0]
path=best[4]
hits=Counter(); tot=Counter()
for a,dep,ok in path: tot[a]+=1; hits[a]+=ok
allh=sum(hits.values())
print(f'final score {best[0]:.0f}')
for a,nm in ((0,'X'),(1,'Y'),(2,'Z')):
    print(f'{nm}: {hits[a]}/{tot[a]} = {hits[a]/max(tot[a],1)*100:.1f}%')
print(f'TOTAL: {allh}/{nv} = {allh/nv*100:.1f}%  (beam2 83.9%, beam3 53.2%)')
# prefix vs winning (axis,depth) for HIT tokens
vt=[t for t in toks if t[0]=='V']
tab=defaultdict(Counter)
for t,(a,dep,ok) in zip(vt,path):
    if ok: tab[t[3]][(a,dep)]+=1
print('\nprefix byte -> winning (axis,depth) [hits only]:')
for p in sorted(tab):
    c=tab[p]; n=sum(c.values())
    top=', '.join(f'{"XYZ"[a]}d{dep}:{cnt}' for (a,dep),cnt in c.most_common(4))
    print(f'  p=0x{p:02x} (nb={(p&7)+1}, hi={p>>3}): n={n:5d}  {top}')
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\beam4_path.npy',
        np.array(path,dtype=object),allow_pickle=True)
