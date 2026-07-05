#!/usr/bin/env python3
"""TOPOLOGY STRIP DECODER (opus session, 2026-07-07).

Implements the strip/rail op-machine investigation for the intercepts topology
section, per RESUME-2026-07-07 "THE WORKING MODEL TO IMPLEMENT NEXT".

What this script does, GT-free unless noted:
  1. Tokenize the topology section (v2 grammar) and extract the vertex-reference
     stream (2-byte = absolute emission slot 0..2974; 1-byte = low-byte splice).
  2. Cluster refs into RAILS (strip columns) by slot-proximity + retirement.
  3. Emit a machine EDGE SET: rail-consecutive edges (validated as real mesh
     edges) + same-group edges.
  4. VALIDATION LADDER (GT used for SCORING ONLY):
       - rail-consecutive anchor-edge lengths vs random.
       - strip-table bookkeeping violation rate.
  5. Feed the rail edge set as the Y-slab neighbor guide into the v5-P2 coord
     decoder (== deterministic_v6_topo.py machinery) and GT-score vs the 23.6%
     baseline.

Run: python python/topo_strip_decoder.py
"""
import struct
import numpy as np
from collections import defaultdict, Counter
from scipy.spatial import cKDTree

OOT=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
GTCSV=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
PBASE=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\50aab51b-ee8a-4ea7-9ddd-f45e87eb7314\scratchpad\P_base.npy'

d=open(OOT,'rb').read()
geo_end=struct.unpack('<15i',d[0:60])[11]
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break

# ---------------- topology tokenizer -> per-group refs ----------------
def tokenize_topo():
    pos=face_start; groups=[]; cur=None; prev_ref=0
    def ng(delim,pos): return {'delim':delim,'pos':pos,'ops':[],'refs':[]}
    while pos<geo_end:
        b=d[pos]
        if b in (0xE0,0xE1):
            if cur: groups.append(cur)
            cur=ng(d[pos:pos+2].hex(),pos); pos+=2; continue
        if cur is None: cur=ng('HEAD',pos)
        if b==0x00:
            nxt=d[pos+1] if pos+1<geo_end else 0
            if 0x20<=nxt<0x80: pos+=1; continue
            r=(prev_ref&~0xFF)|nxt
            if r<=2974: cur['refs'].append(r); prev_ref=r
            pos+=2; continue
        if 0x01<=b<=0x06:
            nb=b+1; v=int.from_bytes(d[pos+1:pos+1+nb],'big')
            if nb==2 and v<=2974: cur['refs'].append(v); prev_ref=v
            pos+=1+nb; continue
        if 0x08<=b<0x20: pos+=1; continue
        cur['ops'].append((b,d[pos+1] if pos+1<geo_end else 0)); pos+=2
    if cur: groups.append(cur)
    return groups
groups=tokenize_topo()
print(f'topology groups: {len(groups)}')

# ---------------- rail clustering (GT-free) ----------------
JUMP=6; RETIRE=80
def cluster_rails(groups):
    rails=[]; active={}; ref_events=[]
    for gi,g in enumerate(groups):
        for r in g['refs']:
            if r==0: continue
            best=None
            for rid,last in active.items():
                dd=abs(r-last)
                if dd<=JUMP and (best is None or dd<best[0]): best=(dd,rid)
            if best is None:
                rid=len(rails); rails.append({'id':rid,'vals':[]})
            else: rid=best[1]
            rails[rid]['vals'].append((gi,r)); active[rid]=r
            ref_events.append((gi,r,rid))
            for k in [k for k,v in list(active.items()) if rails[k]['vals'][-1][0]<gi-RETIRE]:
                del active[k]
    return rails,ref_events
rails,ref_events=cluster_rails(groups)
big=[r for r in rails if len(r['vals'])>=5]
print(f'rails: {len(rails)}  long-lived(>=5): {len(big)}  (>=20): {sum(1 for r in rails if len(r["vals"])>=20)}')

# ---------------- machine edge set ----------------
rail_edges=set()
for r in rails:
    vs=[v for gi,v in r['vals']]
    for a,b in zip(vs,vs[1:]):
        if a!=b: rail_edges.add((min(a,b),max(a,b)))
group_edges=set()
for g in groups:
    rs=[x for x in g['refs'] if x]
    for i in range(len(rs)):
        for j in range(i+1,len(rs)):
            if rs[i]!=rs[j]: group_edges.add((min(rs[i],rs[j]),max(rs[i],rs[j])))
edges=rail_edges|group_edges
print(f'machine edges: rail={len(rail_edges)} group={len(group_edges)} total={len(edges)}')

# ---------------- STEP: bookkeeping violation rate ----------------
def bookkeeping(TOL=3,RET=250):
    ev=[(gi,r) for gi,r,rid in ref_events if 97<=gi<=2400]
    active={}; nid=0; matched=0; newr=0; total=0
    for gi,r in ev:
        total+=1
        for k in [k for k,(p,lg) in active.items() if lg<gi-RET]: del active[k]
        best=None
        for k,(p,lg) in active.items():
            dd=abs(r-p)
            if dd<=TOL and (best is None or dd<best[0]): best=(dd,k)
        if best is None: active[nid]=(r,gi); nid+=1; newr+=1
        else: matched+=1; active[best[1]]=(r,gi)
    print(f'bookkeeping (regular 97-2400, TOL={TOL} RET={RET}): {total} refs, '
          f'matched {matched} ({matched/total*100:.1f}%), violations(new-rail) {newr} ({newr/total*100:.1f}%)')
bookkeeping()

# ---------------- STEP: anchor-edge validation (GT scoring only) ----------------
def anchor_validate():
    P=np.load(PBASE)
    gt=np.loadtxt(GTCSV,delimiter=','); Gu=np.unique(gt,axis=0); kd=cKDTree(Gu)
    dist,_=kd.query(P); anchor=dist<0.002
    def elen(pairs):
        L=[]
        for a,b in pairs:
            if a<len(P) and b<len(P) and anchor[a] and anchor[b]:
                L.append(np.linalg.norm(P[a]-P[b]))
        return np.array(L)
    L=elen(rail_edges)
    rng=np.random.default_rng(0); aidx=np.where(anchor)[0]
    Lr=elen([(rng.choice(aidx),rng.choice(aidx)) for _ in range(4000)])
    print(f'anchor-edge: {anchor.sum()} anchor slots')
    print(f'  rail edges: {len(L)} anchor-pairs, median {np.median(L):.2f}m, frac 2-9m {((L>=2)&(L<=9)).mean()*100:.1f}%')
    print(f'  random:     median {np.median(Lr):.2f}m, frac 2-9m {((Lr>=2)&(Lr<=9)).mean()*100:.1f}%')
    return P,Gu
Pb,Gu=anchor_validate()

# ================= STEP 4: rail-edge Y-slab guide into v5-P2 coord decode =========
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
        nb=(b&7)+1; end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b)); lastT=None; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1

# neighbor map from MACHINE rail edges
nbr=defaultdict(set)
for a,b in edges:
    nbr[a].add(b); nbr[b].add(a)
print(f'\nrail-edge neighbor map: {len(nbr)} slots, mean deg {np.mean([len(v) for v in nbr.values()]):.1f}')

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

TOL_AX={0:4.0,1:16.0,2:0.0625}; HIST=64
def neighbor_median(axisvals,a,slot,win=1):
    cand=set()
    for s in range(slot-win,slot+win+1): cand|=nbr.get(s,set())
    vals=[axisvals[a][n] for n in cand if n in axisvals[a]]
    if not vals: return None
    return float(np.median(vals))
def run(guide=True,yonly=True):
    regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
    hist=[[bytes(regs[a])] for a in range(3)]
    axisvals=[{} for _ in range(3)]
    for a in range(3): axisvals[a][0]=be(regs[a])
    ph=0; pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
    miss=0; overrides=0; checked=0
    for t in toks:
        slot=len(pts)
        if t[0] in ('F','Fe'):
            v=be(t[1]); a=band(v)
            if a<0: continue
            regs[a][:]=t[1]; hist[a].append(bytes(t[1]))
            if a==2 and ph==2:
                for ax in range(3): axisvals[ax][slot]=be(regs[ax])
                pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
            ph=(a+1)%3; continue
        payload=t[1]
        if len(payload)==0: continue
        a=ph
        vb=r2_value(bytes(regs[a]),payload,t[2],a)
        if guide and (not yonly or a==1):
            med=neighbor_median(axisvals,a,slot)
            if med is not None:
                checked+=1
                dv=abs(be(vb)-med) if vb is not None else 1e18
                if dv>TOL_AX[a]:
                    best=None
                    k0s={k0_rule(t[2],len(payload))}|set(range(0,8-len(payload)+1))
                    for R in hist[a][-HIST:]:
                        for k0 in k0s:
                            cb=spl(R,payload,k0)
                            if cb is None or band(be(cb))!=a: continue
                            dd=abs(be(cb)-med)
                            if best is None or dd<best[0]: best=(dd,cb)
                    if best is not None and best[0]<dv and best[0]<=TOL_AX[a]:
                        vb=best[1]; overrides+=1
        if vb is not None:
            regs[a][:]=vb; hist[a].append(bytes(vb))
        else: miss+=1
        if a==2:
            for ax in range(3): axisvals[ax][slot]=be(regs[ax])
            pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        ph=(ph+1)%3
    return np.array(pts),overrides,checked
gt=np.loadtxt(GTCSV,delimiter=','); Gu2=np.unique(gt,axis=0); kd=cKDTree(Gu2)
print('\n--- coord decode score (GT scoring only) ---')
for guide,yonly,tag in [(False,True,'baseline (v5-P2, guide off)'),
                        (True,True,'rail-guide Y-only'),
                        (True,False,'rail-guide all-axis')]:
    P,ov,ch=run(guide,yonly)
    dist,_=kd.query(P)
    ex=(dist<0.002).mean()*100
    print(f'{tag}: {len(P)} pts, overrides {ov}/{ch}, exact<2mm {(dist<0.002).sum()} ({ex:.1f}%)')
