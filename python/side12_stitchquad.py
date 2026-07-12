"""Per-quad emit (geometric diagonal, like side4) but carrying `prev` ACROSS
stitched rail seams within a chain. Does stitching add seam faces on top of
side4's 525 distinct? GT (map11) scoring only.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

P = np.load('P_v11_intercepts.npy'); N = len(P)
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
ext = pickle.load(open('side_rule_ext.pkl', 'rb'))
Sof = {rid: v[1] for rid, v in ext.items()}
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rails = rv['rails']
map11, _ = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
faceset = {tuple(sorted(f)): i for i, f in enumerate(F)}
NF = len(F)
g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)
turns = []
cur = None
for gi, g in enumerate(groups):
    if g['is01']: continue
    if g['refs']:
        cur = len(turns) if gi in g2 else None
        if gi in g2: turns.append([g2[gi][0], gi, g2[gi][1], 0])
        continue
    if g['delim'] == 'e003' and cur is not None:
        turns[cur][3] += 1
railturns = defaultdict(list)
for rid, gi, r, na in turns:
    railturns[rid].append((gi, r, na))

# chains (side11 rule, fold-transition only)
railrefs = defaultdict(list); railgi = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    railrefs[rid].append(r); railgi[rid].append(gi)
info = {}
for rid, rs in railrefs.items():
    if rid in Sof:
        S = Sof[rid]
        info[rid] = dict(S=S, rlo=min(rs), rhi=max(rs), mlo=S-max(rs), mhi=S-min(rs),
                         g0=min(railgi[rid]), g1=max(railgi[rid]))
def ov(a0,a1,b0,b1): return max(0,min(a1,b1)-max(a0,b0)+1)
links={}
for A,ia in info.items():
    span=ia['mhi']-ia['mlo']+1; best=None
    for B,ib in info.items():
        if B==A: continue
        o=ov(ia['mlo'],ia['mhi'],ib['rlo'],ib['rhi'])
        if o<=0: continue
        frac=o/max(span,1); key=(frac,-abs(ib['g0']-ia['g1']))
        if best is None or key>best[0]: best=(key,B,frac)
    if best and best[2]>=0.5 and abs(info[best[1]]['S']-ia['S'])>=20:
        links[A]=best[1]
incoming=set(links.values())
chains=[]; seen=set()
for s in [r for r in info if r not in incoming]:
    c=[]; x=s; loc=set()
    while x is not None and x not in loc: c.append(x); loc.add(x); x=links.get(x)
    chains.append(c); seen|=loc
for r in info:
    if r not in seen:
        c=[]; x=r; loc=set()
        while x is not None and x not in loc: c.append(x); loc.add(x); x=links.get(x)
        chains.append(c); seen|=loc

def dlen(a,b):
    if not(0<=a<N and 0<=b<N): return 1e9
    return float(np.hypot(*(P[a,:2]-P[b,:2])))
def isgt(t):
    gs=[map11.get(s) for s in t]
    if any(x is None for x in gs) or len(set(gs))!=3: return None
    return faceset.get(tuple(sorted(gs)))

def emit(carry_across):
    tris=[]
    for chain in chains:
        prev=None
        for rid in chain:
            S=Sof[rid]
            for gi,r,na in railturns.get(rid,[]):
                n0=S-r
                if prev is not None:
                    rp,np1=prev
                    if dlen(rp,n0)<=dlen(np1,r):
                        for t in ((rp,np1,n0),(rp,n0,r)): tris.append(t)
                    else:
                        for t in ((np1,r,rp),(np1,r,n0)): tris.append(t)
                prev=(r,n0)
            if not carry_across:
                prev=None
    return tris

def score(tris,label):
    scor=good=0; hit=set()
    for t in tris:
        fi=isgt(t)
        if fi is None and len(set(t))==3:
            gs=[map11.get(s) for s in t]
            if all(x is not None for x in gs) and len(set(gs))==3: scor+=1
            continue
        if fi is not None:
            scor+=1; good+=1; hit.add(fi)
    print('%-26s tris %d scor %d correct %d (prec %.1f%%) distinct %d = %.1f%%'
          %(label,len(tris),scor,good,100*good/max(scor,1),len(hit),100*len(hit)/NF))
    return hit
print('chains %d (>=2 rails %d)'%(len(chains),sum(1 for c in chains if len(c)>=2)))
h1=score(emit(False),'per-quad, NO carry')
h2=score(emit(True),'per-quad, carry across seam')
print('NEW distinct from seam-carry:',len(h2-h1))
