#!/usr/bin/env python3
"""DETERMINISTIC v4 — SOLE PARSER (no ground truth in the decode loop).
THE ANNOUNCEMENT MODEL (from hand-trace + p_hi census, 97.8%):
  - V-prefix p = [hi bits: number of FULL doubles that follow this token]
                 [lo3: payload length-1]
  - stream = slot sequence, X->Y->Z cycle, one slot per V-token or ANNOUNCED
    FULL; both advance phase +1. Z-slot write emits the vertex.
  - a FULL that was NOT announced = out-of-cycle re-anchor (no advance).
  - escape bytes (>=0x20 immediately before a sane FULL) are consumed.
  - V value = splice onto current same-axis register at k0 from the T1 rule;
    among {rule-k0, alt-k0, carry+-1} pick the band-sane candidate with the
    smallest |delta| (local choice only).
GT used ONLY for scoring at the end."""
import struct
import numpy as np
from math import log
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
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        lastT=None; pos+=1; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b)); lastT=None; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
print(f'tokens {N}')
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
SCALE=(8.0,8.0,0.5)
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
ph=0
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
expect=0   # announced FULLs outstanding
stats={'v':0,'f_slot':0,'f_re':0,'oob':0}
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v)
        regs[a][:]=t[1]
        if expect>0:
            expect-=1; stats['f_slot']+=1
            if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
            ph=(a+1)%3      # announced slot; band defines the slot
        else:
            stats['f_re']+=1  # re-anchor: no advance, no emit
        continue
    payload=t[1]; nb=len(payload); p=t[3]
    expect=p>>3
    if nb==0: continue
    a=ph
    prev=be(regs[a])
    k0r=k0_rule(t[2],nb)
    best=None
    for k0,kcost in ((k0r,0.0),(5-k0r,1.5)):
        e=k0+nb
        if e>8 or k0<0: continue
        vb=bytes(regs[a][:k0])+bytes(payload)+bytes(regs[a][e:])
        v=be(vb)
        if np.isfinite(v) and band(v)==a:
            c=kcost+log(1+abs(v-prev)/SCALE[a])
            if best is None or c<best[0]: best=(c,vb)
        if k0>=1:
            for cc in (1,-1):
                b2=regs[a][k0-1]+cc
                if 0<=b2<=255:
                    vb2=bytes(regs[a][:k0-1])+bytes([b2])+bytes(payload)+bytes(regs[a][e:])
                    v2=be(vb2)
                    if np.isfinite(v2) and band(v2)==a:
                        c=kcost+1.0+log(1+abs(v2-prev)/SCALE[a])
                        if best is None or c<best[0]: best=(c,vb2)
    if best is not None:
        regs[a][:]=best[1]
    else:
        stats['oob']+=1
    stats['v']+=1
    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
    ph=(ph+1)%3
print('stats',stats)
P=np.array(pts)
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
dist,_=cKDTree(Gu).query(P)
print(f'v4 GT-FREE decode: {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(sp+r'\det_v4.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote det_v4.xyz')
