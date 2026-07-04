"""v5b: segment-wise phase selection by band-sanity, strict R2 core.
Between FULLs, try phase offsets {0,1,2}; strict decode (k0r + carry only,
must land in current-axis band). Offset with fewest violations wins.
GT only for final scoring."""
import struct
import numpy as np
from scipy.spatial import cKDTree
src=open(r'C:\Users\brent\desktop\git\vulcan-00t-tri\python\deterministic_v5.py').read()
src=src.split("def run(")[0]
exec(src)   # gives toks, k0_rule, band, be, gtcsv, d
def strict_val(R,payload,T,a):
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
    return None
# split token stream into segments at FULL boundaries
segs=[]; cur=[]
for t in toks:
    if t[0] in ('F','Fe'):
        if cur: segs.append(('V',cur)); cur=[]
        segs.append(('F',[t]))
    else: cur.append(t)
if cur: segs.append(('V',cur))
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
ph=0
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
stats={'seg':0,'ph_kept':0,'ph_switched':0,'viol':0}
for kind,ts in segs:
    if kind=='F':
        t=ts[0]; v=be(t[1]); a=band(v)
        if a>=0:
            regs[a][:]=t[1]
            ph=(a+1)%3          # setband after re-anchor
        continue
    stats['seg']+=1
    # try 3 offsets on COPIES; count violations
    best=None
    for off in range(3):
        rr=[bytearray(r) for r in regs]
        p2=[]; viol=0
        phx=(ph+off)%3
        for t in ts:
            payload=t[1]
            if len(payload)==0: continue
            a=phx
            vb=strict_val(bytes(rr[a]),payload,t[2],a)
            if vb is not None: rr[a][:]=vb
            else: viol+=1
            if a==2: p2.append((be(rr[0]),be(rr[1]),be(rr[2])))
            phx=(phx+1)%3
        key=(viol,off!=0)   # prefer fewer violations, then keep phase
        if best is None or key<best[0]: best=(key,off,rr,p2,phx,viol)
    _,off,rr,p2,phx,viol=best
    if off==0: stats['ph_kept']+=1
    else: stats['ph_switched']+=1
    stats['viol']+=viol
    for a in range(3): regs[a][:]=rr[a]
    pts.extend(p2); ph=phx
P=np.array(pts)
print('segments:',stats)
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
dist,_=cKDTree(Gu).query(P)
d2,_=cKDTree(P).query(Gu)
print(f'v5b: {len(P)} pts (GT {len(Gu)})')
for tol in (0.002,0.1,1.0):
    print(f'  precision <{tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)   recall: {(d2<tol).sum()} ({(d2<tol).mean()*100:.1f}%)')
