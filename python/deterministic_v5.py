#!/usr/bin/env python3
"""DETERMINISTIC v5 — GT-FREE vertex decoder (no ground truth in the decode loop).

Value rule R2 (bake-off winner, 98.55% teacher-forced per-token, value-tol 1mm):
  k0 from T1:  0x21-0x3F -> 2;  0x40-0x5F -> 3;  0x20 -> (3 if T2<0x60 else 2);
               no T -> {nb4:3, nb5:3, nb6:2}
  splice payload at [k0,k0+nb) onto prev SAME-AXIS register; if the result is
  out of band: try prefix-carry c=+-1..+-4 at byte k0-1, then placement scan
  k0=0..8-nb (band-sane), nearest to prev as last resort.
  (Nearest-prev-only = 52%, minimality-override = 80% -> both rejected.)

Phase variants raced end-to-end:
  P1 announce : v4 model (p>>3 = #FULLs that fill slots; unannounced = re-anchor)
  P2 setband  : every FULL snaps phase to band+1 (self-syncing)
  P3 bandmatch: FULL fills slot iff band==phase else re-anchor
All FULLs always update their band register.
GT used ONLY for scoring at the end."""
import struct
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
d=open(oot,'rb').read()
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
# tokenizer: FULL precedence, escape consumption, V payload truncation at inner FULL
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if full_at(pos) is not None:
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:   # escape-prefixed FULL
        # W13-production: [esc][FULL 8B][1 trailing byte] = 10 bytes total
        # (trailing byte confirmed at break sites 29105/29262/66845 2026-07-04)
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
print(f'tokens {len(toks)}  (V {sum(1 for t in toks if t[0]=="V")}, F {sum(1 for t in toks if t[0]=="F")}, Fe {sum(1 for t in toks if t[0]=="Fe")})')
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
def r2_value(R,payload,T,a):
    """R2 rule: returns new 8-byte register value bytes (or None)."""
    nb=len(payload)
    if nb==0 or nb>8: return None
    def spl(k0,c=0):
        end=k0+nb
        if k0<0 or end>8: return None
        bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
        if c!=0:
            kk=k0-1
            if kk<0: return None
            nv=bb[kk]+c
            if not(0<=nv<=255): return None
            bb[kk]=nv
        return bytes(bb)
    k0r=k0_rule(T,nb)
    if k0r+nb>8: k0r=8-nb
    vb=spl(k0r)
    if vb is not None and band(be(vb))==a: return vb
    for c in (-1,1,-2,2,-3,3,-4,4):
        vb=spl(k0r,c)
        if vb is not None and band(be(vb))==a: return vb
    pv=be(R); best=None
    for k0 in range(0,8-nb+1):
        vb=spl(k0)
        if vb is not None and band(be(vb))==a:
            dv=abs(be(vb)-pv)
            if best is None or dv<best[0]: best=(dv,vb)
    return best[1] if best else None
def run(variant):
    regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
    ph=0; expect=0
    pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
    miss=0
    for t in toks:
        if t[0] in ('F','Fe'):
            v=be(t[1]); a=band(v)
            if a<0: continue
            regs[a][:]=t[1]
            if variant=='P1':
                if t[0]=='F' and expect>0:
                    expect-=1
                    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
                    ph=(a+1)%3
            elif variant=='P2':
                if a==2 and ph==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
                ph=(a+1)%3
            elif variant=='P3':
                if a==ph:
                    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
                    ph=(a+1)%3
            continue
        payload=t[1]; p=t[3]
        expect=p>>3
        if len(payload)==0: continue
        a=ph
        vb=r2_value(bytes(regs[a]),payload,t[2],a)
        if vb is not None: regs[a][:]=vb
        else: miss+=1
        if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        ph=(ph+1)%3
    return np.array(pts),miss
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
kd=cKDTree(Gu)
for variant in ('P1','P2','P3'):
    P,miss=run(variant)
    dist,_=kd.query(P)
    d2,_=cKDTree(P).query(Gu)
    print(f'\n{variant}: {len(P)} pts (GT {len(Gu)}), value-miss {miss}')
    for tol in (0.002,0.1,1.0):
        print(f'  precision <{tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)   GT recall <{tol}m: {(d2<tol).sum()} ({(d2<tol).mean()*100:.1f}%)')
