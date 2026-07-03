#!/usr/bin/env python3
"""Deterministic decoder v2: consumes action_table.json learned by
triple_lock_beam.py. Per V-token context (p,T1,T2) choose action by table with
fallback hierarchy: (p,T1,T2) -> (p,T2) -> (p,T1) -> (p,) -> global.
Actions: ('S',end) single at current phase; ('R',end) refine prev phase;
('P',k2) split. Cycle always advances; FULLs literal + resync.
GT ONLY for final scoring. This is the shape of the production parser."""
import sys, struct, json
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
raw=json.load(open(sp+r'\action_table.json'))
# build fallback tables
t3=defaultdict(Counter); t2a=defaultdict(Counter); t2b=defaultdict(Counter); t1=defaultdict(Counter); t0=Counter()
for k,acts in raw.items():
    p,T1,T2=(int(x) for x in k.split(','))
    for ak,n in acts.items():
        kind,val=ak.split(','); val=int(val); a=(kind,val)
        t3[(p,T1,T2)][a]+=n; t2a[(p,T2)][a]+=n; t2b[(p,T1)][a]+=n; t1[(p,)][a]+=n; t0[a]+=n
def lookup(p,T1,T2):
    for tab,key in ((t3,(p,T1,T2)),(t2a,(p,T2)),(t2b,(p,T1)),(t1,(p,))):
        if key in tab and sum(tab[key].values())>=2:
            return tab[key].most_common(1)[0][0]
    return t0.most_common(1)[0][0]
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
ph=0
pts=[]
pos=8350; lastT=None
kinds=Counter()
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        v=be(d[pos:pos+8]); a=band(v)
        regs[a][:]=d[pos:pos+8]
        ph=(a+1)%3
        if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        pos+=8; lastT=None; kinds['F']+=1; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        payload=d[pos+1:pos+1+nb]
        T1=lastT[0] if lastT else -1; T2=lastT[1] if lastT else -1
        kind,val=lookup(b,T1,T2)
        if kind=='S':
            end=val; k0=end-nb
            if 0<=k0 and end<=8:
                regs[ph][:]=bytes(regs[ph][:k0])+payload+bytes(regs[ph][end:])
            if ph==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
            ph=(ph+1)%3
        elif kind=='R':
            a=(ph-1)%3; end=val; k0=end-nb
            if 0<=k0 and end<=8:
                regs[a][:]=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
        else:  # split
            k2=max(1,min(val,nb-1))
            h,tl=payload[:k2],payload[k2:]
            a=ph; b2=(ph+1)%3
            regs[a][:]=bytes(regs[a][:8-k2])+h
            regs[b2][:]=bytes(regs[b2][:8-(nb-k2)])+tl
            if 2 in (a,b2): pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
            ph=(b2+1)%3
        kinds[kind]+=1
        pos+=1+nb; lastT=None; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; lastT=None; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
P=np.array(pts)
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print('kinds:',dict(kinds))
print(f'decoded vertices: {len(P)} (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(sp+r'\det_v2.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote det_v2.xyz')
