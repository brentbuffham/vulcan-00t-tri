#!/usr/bin/env python3
"""SEGMENT-EXACT GT-FREE DECODER (sole parser).
Split the stream at plain FULLs. Within a segment the cycle advances +1 per
V-token; the NEXT plain FULL's band is a checksum: it must land on the
expected slot. If it doesn't, the (mod 3) mismatch tells us the net number of
skipped slots; search skip positions exhaustively (segments are ~19 tokens),
scoring by delta plausibility. Mechanisms per token: splice@k0rule, alt-k0,
carry+-1, ref2 — greedy min-plausibility within each phase hypothesis.
GT used ONLY for scoring at the end."""
import struct
import numpy as np
from math import log
from collections import Counter
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
toks=[];pos=8350;lastT=None;esc=False
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],lastT,esc)); lastT=None; esc=False; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        esc=True; lastT=None; pos+=1; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b)); lastT=None; esc=False; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
SCALE=(8.0,8.0,0.5)
def dpen(a,dv): return log(1.0+abs(dv)/SCALE[a])
def decode_tok(t,a,regs,hist):
    """best (cost, vb) for token t on axis a."""
    payload=bytes(t[1]); nb=len(payload)
    if nb==0: return None
    k0r=k0_rule(t[2],nb)
    prev=be(regs[a])
    best=None
    refs=[(regs[a],0.0)]
    if len(hist[a])>=2: refs.append((hist[a][-2],2.5))
    for ref,rcost in refs:
        for k0,kcost in ((k0r,0.0),(5-k0r,1.5)):
            e=k0+nb
            if e>8 or k0<0: continue
            vb=ref[:k0]+payload+ref[e:]
            v=be(vb)
            if np.isfinite(v) and band(v)==a:
                c=rcost+kcost+dpen(a,v-prev)
                if best is None or c<best[0]: best=(c,vb)
            if k0>=1:
                for cc in (1,-1):
                    b2=ref[k0-1]+cc
                    if 0<=b2<=255:
                        vb2=ref[:k0-1]+bytes([b2])+payload+ref[e:]
                        v2=be(vb2)
                        if np.isfinite(v2) and band(v2)==a:
                            c=rcost+kcost+1.0+dpen(a,v2-prev)
                            if best is None or c<best[0]: best=(c,vb2)
    return best
def run_segment(seg,ph0,regs0,hist0,shift):
    """decode V-tokens seg with skip pattern totaling `shift` extra advances.
    Returns (cost, regs, hist, pts, ph_end). Try all single/double skip
    placements; skips inserted BEFORE token j mean phase jumps +1 there."""
    nV=len(seg)
    if shift==0: patterns=[()]
    elif shift==1: patterns=[(j,) for j in range(nV+1)]
    else: patterns=[(j,k) for j in range(nV+1) for k in range(j,nV+1)]
    best=None
    for pat in patterns:
        regs=list(regs0); hist={k:list(v) for k,v in hist0.items()}
        ph=ph0; cost=0.0; pts=[]
        pi=0; ok=True
        for j,t in enumerate(seg):
            while pi<len(pat) and pat[pi]==j: ph=(ph+1)%3; pi+=1
            r=decode_tok(t,ph,regs,hist)
            if r is None: ok=False; break
            c,vb=r
            cost+=c
            regs[ph]=vb; hist[ph]=(hist[ph]+[vb])[-3:]
            if ph==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
            ph=(ph+1)%3
            if best and cost>=best[0]: ok=False; break
        while pi<len(pat) and pat[pi]==nV: ph=(ph+1)%3; pi+=1
        if not ok: continue
        if best is None or cost<best[0]:
            best=(cost,regs,hist,pts,ph)
    return best
# split into segments at plain FULLs
regs=[bytes(d[8326:8334]),bytes(d[8334:8342]),bytes(d[8342:8350])]
hist={0:[regs[0]],1:[regs[1]],2:[regs[2]]}
ph=0
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
i=0
shift_census=Counter()
while i<N:
    # collect V-run until next plain FULL (escaped fulls applied inline)
    seg=[]
    while i<N and not (toks[i][0]=='F' and not toks[i][3]):
        t=toks[i]
        if t[0]=='F':  # escaped: re-anchor inline (breaks segment refs cleanly)
            # decode pending seg first with shift 0 (no checksum available)
            if seg:
                r=run_segment(seg,ph,regs,hist,0)
                if r:
                    c,regs_,hist_,pts_,ph_=r
                    regs=list(regs_);hist=hist_;pts+=pts_;ph=ph_
                seg=[]
            fb=bytes(t[1]); a=band(be(fb))
            regs[a]=fb; hist[a]=(hist[a]+[fb])[-3:]
        else:
            seg.append(t)
        i+=1
    if i>=N:
        if seg:
            r=run_segment(seg,ph,regs,hist,0)
            if r: c,regs_,hist_,pts_,ph_=r; pts+=pts_
        break
    fb=bytes(toks[i][1]); a=band(be(fb))
    # checksum: after decoding seg, phase should equal a
    base_end=(ph+len(seg))%3
    shift=(a-base_end)%3
    shift_census[shift]+=1
    r=run_segment(seg,ph,regs,hist,shift)
    if r is None:
        r=run_segment(seg,ph,regs,hist,0)
    if r:
        c,regs_,hist_,pts_,ph_=r
        regs=list(regs_);hist=hist_;pts+=pts_;ph=ph_
    # apply the FULL (slot-occupying)
    regs[a]=fb; hist[a]=(hist[a]+[fb])[-3:]
    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
    ph=(a+1)%3
    i+=1
print('segment shift census:',dict(shift_census))
P=np.array(pts)
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
dist,_=cKDTree(Gu).query(P)
print(f'SEGMENT-EXACT GT-FREE decode: {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(sp+r'\segment_exact.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote segment_exact.xyz')
