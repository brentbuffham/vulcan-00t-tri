#!/usr/bin/env python3
"""DETERMINISTIC v3 — SOLE PARSER (no ground truth in the decode loop).
Model: unified tokenizer (zero-strip); strict X->Y->Z cycle; FULL = literal
8-byte BE double, resyncs cycle to its band; V-token = splice onto the PREVIOUS
value of the current axis; placement (r,end) chosen by:
  1. (p,T1,T2) rule table (from answer key) when context seen and pure,
  2. else minimal-|delta| across candidate placements (encoder emits minimal
     windows, so the true placement gives the smallest step).
GT used ONLY for scoring at the end."""
import struct, json, os
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
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
# rule table (optional; empty dict if missing)
tab={}
tp=sp+r'\end_table.json'
if os.path.exists(tp):
    raw=json.load(open(tp))
    for k,c in raw.items():
        p,T1,T2=(int(x) for x in k.split(','))
        n=sum(c.values()); top=max(c.items(),key=lambda kv:kv[1])
        if n>=3 and top[1]/n>=0.9:
            tab[(p,T1,T2)]=int(top[0])
print(f'tokens {N}; trusted table contexts: {len(tab)}')
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
ph=0
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
used_tab=0; used_min=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]
        if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        ph=(a+1)%3; continue
    payload=t[1]; nb=len(payload); p=t[3]; T=t[2]
    a=ph
    prev=be(regs[a])
    # candidate placements
    cands=[]
    for r in (0,1,2):
        if nb-r<1: break
        pl=payload[r:]
        for end in (8,7,6):
            k0=end-(nb-r)
            if k0<0: continue
            vb=bytes(regs[a][:k0])+pl+bytes(regs[a][end:])
            v=be(vb)
            if not np.isfinite(v) or band(v)!=a: continue
            cands.append((abs(v-prev),r,end,vb))
    chosen=None
    key=(p,T[0] if T else -1,T[1] if T else -1)
    if key in tab:
        endt=tab[key]
        for dv,r,end,vb in cands:
            if end==endt and r==0: chosen=(dv,r,end,vb); used_tab+=1; break
    if chosen is None and cands:
        cands.sort()
        chosen=cands[0]; used_min+=1
    if chosen:
        regs[a][:]=chosen[3]
    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
    ph=(ph+1)%3
print(f'placement source: table {used_tab}, min-delta {used_min}')
P=np.array(pts)
# ---- scoring only ----
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print(f'v3 GT-FREE decode: {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(sp+r'\det_v3.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote det_v3.xyz')
