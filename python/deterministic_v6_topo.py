#!/usr/bin/env python3
"""DETERMINISTIC v6 — GT-free vertex decoder with TOPOLOGY-ADJACENCY guidance.

v5-P2 core (R2 value rule + setband phase) PLUS:
  1. Per-axis register HISTORY (the emission table built so far).
  2. GT-free neighbor map extracted from the topology section's reference
     stream (refs = absolute/spliced emission indices, RESUME-2026-07-07).
  3. At each value token: default = R2 splice on prev same-axis register.
     If decoded mesh neighbors exist for the current slot and the default
     lands far from them while a splice onto some OLDER same-axis register
     (the 171/180 event mechanism) lands near, take the override.

GT is used ONLY for scoring at the end.  Tokenizer kept in sync with
deterministic_v5.py (Fe = 10 bytes).
"""
import struct
import numpy as np
from collections import defaultdict

oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
d=open(oot,'rb').read()
geo_end=struct.unpack('<15i',d[0:60])[11]
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    x=abs(v)
    if 500<x<1000: return 2
    if 50000<x<60000: return 0
    if 160000<x<166000: return 1
    return -1
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None

# ---------------- coord tokenizer (== deterministic_v5.py) ----------------
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if full_at(pos) is not None:
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        toks.append(('Fe',d[pos+1:pos+9],lastT,None)); lastT=None; pos+=10; continue
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
print(f'tokens {len(toks)}')

# ---------------- topology reference stream -> neighbor map ----------------
TAGS=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
tpos=face_start; refs=[]; gi=-1; prev_ref=0
while tpos<geo_end:
    b=d[tpos]
    if b in (0xE0,0xE1): gi+=1; tpos+=2; continue
    if b==0x00:
        nxt=d[tpos+1] if tpos+1<geo_end else 0
        if 0x20<=nxt<0x80: tpos+=1; continue
        r=(prev_ref&~0xFF)|nxt
        if r<=2974: refs.append((gi,r)); prev_ref=r
        tpos+=2; continue
    if 0x01<=b<=0x06:
        nb=b+1; v=int.from_bytes(d[tpos+1:tpos+1+nb],'big')
        if nb==2 and v<=2974: refs.append((gi,v)); prev_ref=v
        elif nb==2: pass
        tpos+=1+nb; continue
    if 0x08<=b<0x20: tpos+=1; continue
    tpos+=2
print(f'topology refs: {len(refs)} over {gi+1} groups')
nbr=defaultdict(set)
for k in range(len(refs)):
    g1,r1=refs[k]
    for j in range(k+1,len(refs)):
        g2,r2=refs[j]
        if g2-g1>2: break
        if r1!=r2:
            nbr[r1].add(r2); nbr[r2].add(r1)
print(f'slots with neighbors: {len(nbr)}  mean degree {np.mean([len(v) for v in nbr.values()]):.1f}')

# ---------------- R2 value rule (== v5) ----------------
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
def spl(R,payload,k0,c=0):
    nb=len(payload); end=k0+nb
    if k0<0 or end>8: return None
    bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
    if c!=0:
        kk=k0-1
        if kk<0: return None
        nv=bb[kk]+c
        if not(0<=nv<=255): return None
        bb[kk]=nv
    return bytes(bb)
def r2_value(R,payload,T,a):
    nb=len(payload)
    if nb==0 or nb>8: return None
    k0r=k0_rule(T,nb)
    if k0r+nb>8: k0r=8-nb
    vb=spl(R,payload,k0r)
    if vb is not None and band(be(vb))==a: return vb
    for c in (-1,1,-2,2,-3,3,-4,4):
        vb=spl(R,payload,k0r,c)
        if vb is not None and band(be(vb))==a: return vb
    pv=be(R); best=None
    for k0 in range(0,8-nb+1):
        vb=spl(R,payload,k0)
        if vb is not None and band(be(vb))==a:
            dv=abs(be(vb)-pv)
            if best is None or dv<best[0]: best=(dv,vb)
    return best[1] if best else None

# ---------------- decode with topology guidance ----------------
TOL={0:4.0,1:16.0,2:0.0625}       # half slab spacing per axis
HIST=64                            # same-axis registers searched back
def neighbor_median(axisvals,a,slot,win=2):
    cand=set()
    for s in range(slot-win,slot+win+1): cand|=nbr.get(s,set())
    vals=[axisvals[a][n] for n in cand if n in axisvals[a]]
    if not vals: return None
    return float(np.median(vals))
def run_v6(guide=True):
    regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
    hist=[[bytes(regs[a])] for a in range(3)]
    axisvals=[{ } for _ in range(3)]
    for a in range(3): axisvals[a][0]=be(regs[a])
    ph=0
    pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
    miss=0; overrides=0; checked=0
    for t in toks:
        slot=len(pts)                       # slot being assembled
        if t[0] in ('F','Fe'):
            v=be(t[1]); a=band(v)
            if a<0: continue
            regs[a][:]=t[1]; hist[a].append(bytes(t[1]))
            if a==2 and ph==2:
                for ax in range(3): axisvals[ax][slot]=be(regs[ax])
                pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
            ph=(a+1)%3
            continue
        payload=t[1]
        if len(payload)==0: continue
        a=ph
        vb=r2_value(bytes(regs[a]),payload,t[2],a)
        if guide:
            med=neighbor_median(axisvals,a,slot)
            if med is not None:
                checked+=1
                dv=abs(be(vb)-med) if vb is not None else 1e18
                if dv>TOL[a]:
                    # try splices onto older same-axis registers
                    best=None
                    k0s={k0_rule(t[2],len(payload))} | set(range(0,8-len(payload)+1))
                    for R in hist[a][-HIST:]:
                        for k0 in k0s:
                            cb=spl(R,payload,k0)
                            if cb is None or band(be(cb))!=a: continue
                            dd=abs(be(cb)-med)
                            if best is None or dd<best[0]: best=(dd,cb)
                    if best is not None and best[0]<dv and best[0]<=TOL[a]:
                        vb=best[1]; overrides+=1
        if vb is not None:
            regs[a][:]=vb; hist[a].append(bytes(vb))
        else: miss+=1
        if a==2:
            for ax in range(3): axisvals[ax][slot]=be(regs[ax])
            pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        ph=(ph+1)%3
    print(f'  guide={guide}: miss {miss}, neighbor-checked {checked}, overrides {overrides}')
    return np.array(pts)

from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
kd=cKDTree(Gu)
for guide in (False,True):
    P=run_v6(guide)
    dist,_=kd.query(P)
    d2,_=cKDTree(P).query(Gu)
    tag='v6-topo' if guide else 'v6-base(P2)'
    print(f'{tag}: {len(P)} pts')
    for tol in (0.002,0.1,1.0):
        print(f'  precision <{tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)   GT recall <{tol}m: {(d2<tol).sum()} ({(d2<tol).mean()*100:.1f}%)')
