#!/usr/bin/env python3
"""GT-FREE BEAM DECODER (sole parser — no ground truth in the decode loop).
Feed-forward fails because ~5-10%% per-token ambiguity cascades. Instead run a
beam over per-token mechanism choices, scored ONLY by internal redundancy:
  - band sanity (hard)
  - delta plausibility (log-magnitude penalty per axis)
  - mechanism priors (splice@k0rule cheap; alt-k0/carry/deep-ref cost more)
  - FULL checksum: a plain FULL's band should equal the expected cycle slot
    (mismatch = phase penalty), and its value should be plausibly near the
    previous value of its band.
GT used ONLY for scoring the final output."""
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
print(f'tokens {N}')
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
SCALE=(8.0,8.0,0.5)   # typical |delta| per axis (X,Y,Z) in meters
def dpen(a,dv):
    return log(1.0+abs(dv)/SCALE[a])
# beam state: (score, regs0,regs1,regs2 (bytes), phase, pts tuple-list id)
# store pts per branch as python list; copy-on-write via tuples of chunks
class Br:
    __slots__=('score','regs','ph','pts','hist')
    def __init__(s,score,regs,ph,pts,hist):
        s.score=score; s.regs=regs; s.ph=ph; s.pts=pts; s.hist=hist
init_regs=(bytes(d[8326:8334]),bytes(d[8334:8342]),bytes(d[8342:8350]))
init_hist=({0:[init_regs[0]],1:[init_regs[1]],2:[init_regs[2]]})
beam=[Br(0.0,init_regs,0,[(be(init_regs[0]),be(init_regs[1]),be(init_regs[2]))],
         {0:[init_regs[0]],1:[init_regs[1]],2:[init_regs[2]]})]
W=48
for ti,t in enumerate(toks):
    newb=[]
    if t[0]=='F':
        fb=bytes(t[1]); v=be(fb); a=band(v)
        for br in beam:
            if t[3]:
                # escaped: re-anchor, no slot, small cost 0
                regs=list(br.regs); regs[a]=fb
                h={k:(list(vv) if k==a else vv) for k,vv in br.hist.items()}
                h[a]=(h[a]+[fb])[-3:]
                newb.append(Br(br.score,tuple(regs),br.ph,br.pts,h))
            else:
                pen=0.0 if a==br.ph else 3.0   # phase checksum
                regs=list(br.regs); regs[a]=fb
                pts=br.pts
                if a==2: pts=pts+[(be(regs[0]),be(regs[1]),be(regs[2]))]
                h={k:(list(vv) if k==a else vv) for k,vv in br.hist.items()}
                h[a]=(h[a]+[fb])[-3:]
                newb.append(Br(br.score+pen,tuple(regs),(a+1)%3,pts,h))
    else:
        payload=bytes(t[1]); nb=len(payload)
        if nb==0:
            newb=beam
            beam=newb
            continue
        k0r=k0_rule(t[2],nb)
        for br in beam:
            a=br.ph
            prev=be(br.regs[a])
            cands=[]
            refs=[('r1',br.regs[a],0.0)]
            if len(br.hist[a])>=2: refs.append(('r2',br.hist[a][-2],2.5))
            for rn,ref,rcost in refs:
                for k0,kcost in ((k0r,0.0),(5-k0r,1.5)):
                    e=k0+nb
                    if e>8 or k0<0: continue
                    vb=ref[:k0]+payload+ref[e:]
                    v=be(vb)
                    if np.isfinite(v) and band(v)==a:
                        cands.append((rcost+kcost+dpen(a,v-prev),vb))
                    # carry variants at k0-1
                    if k0>=1:
                        for c,ccost in ((1,1.0),(-1,1.0)):
                            b2=ref[k0-1]+c
                            if 0<=b2<=255:
                                vb2=ref[:k0-1]+bytes([b2])+payload+ref[e:]
                                v2=be(vb2)
                                if np.isfinite(v2) and band(v2)==a:
                                    cands.append((rcost+kcost+ccost+dpen(a,v2-prev),vb2))
            if not cands:
                # dead token: skip with penalty
                newb.append(Br(br.score+4.0,br.regs,(br.ph+1)%3,br.pts,br.hist))
                continue
            cands.sort(key=lambda x:x[0])
            for cost,vb in cands[:3]:
                regs=list(br.regs); regs[a]=vb
                pts=br.pts
                if a==2: pts=pts+[(be(regs[0]),be(regs[1]),be(vb))]
                h={k:(list(vv) if k==a else vv) for k,vv in br.hist.items()}
                h[a]=(h[a]+[vb])[-3:]
                newb.append(Br(br.score+cost,tuple(regs),(a+1)%3,pts,h))
    newb.sort(key=lambda b:b.score)
    beam=newb[:W]
    if ti%2000==0: print(f'  tok {ti}/{N} beam best {beam[0].score:.1f}')
best=beam[0]
print(f'done. best score {best.score:.1f}, pts {len(best.pts)}')
P=np.array(best.pts)
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
dist,_=cKDTree(Gu).query(P)
print(f'BEAM GT-FREE decode: {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(sp+r'\beam_gtfree.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote beam_gtfree.xyz')
