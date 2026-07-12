"""Last-3-of-sequence replay over STITCHED strips (side10 chains).
Per chain: concatenate rails in link order; within each rail interleave
(ref r, alloc n=S_rail - r) in gi order; emit the last-3 triangle at each
new element. Score distinct GT faces / 5724 (honest coverage) + precision.
Compare to the per-quad baseline (525 distinct / 9.2%).
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
map11, _ = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
faceset = {tuple(sorted(f)): i for i, f in enumerate(F)}
NF = len(F)
g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# per-rail ordered turns: list of (gi, r, n_idless_count)
turns = []
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        cur = len(turns) if gi in g2 else None
        if gi in g2:
            turns.append([g2[gi][0], gi, g2[gi][1], 0])
        continue
    if g['delim'] == 'e003' and cur is not None:
        turns[cur][3] += 1
railturns = defaultdict(list)
for rid, gi, r, na in turns:
    railturns[rid].append((gi, r, na))

# rebuild chains (side10 rule)
railrefs = defaultdict(list); railgi = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    railrefs[rid].append(r); railgi[rid].append(gi)
info = {}
for rid, rs in railrefs.items():
    if rid in Sof:
        S = Sof[rid]
        info[rid] = dict(S=S, rlo=min(rs), rhi=max(rs), mlo=S-max(rs), mhi=S-min(rs),
                         g0=min(railgi[rid]), g1=max(railgi[rid]))
def ov(a0,a1,b0,b1): return max(0, min(a1,b1)-max(a0,b0)+1)
links = {}
for A, ia in info.items():
    span = ia['mhi']-ia['mlo']+1; best=None
    for B, ib in info.items():
        if B==A: continue
        o = ov(ia['mlo'],ia['mhi'],ib['rlo'],ib['rhi'])
        if o<=0: continue
        frac=o/max(span,1); key=(frac,-abs(ib['g0']-ia['g1']))
        if best is None or key>best[0]: best=(key,B,frac)
    # only link if it's a FOLD transition (S changes by ~column pitch), not same-fold
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

def emit_seq(seq, tris):
    for i in range(2, len(seq)):
        t = (seq[i-2], seq[i-1], seq[i])
        if len(set(t)) == 3:
            tris.append(t)

# replay: per chain, build merged sequence across rails
tris = []
for chain in chains:
    seq = []
    for rid in chain:
        S = Sof[rid]
        for gi, r, na in railturns.get(rid, []):
            seq.append(r)
            for _ in range(na):
                seq.append(S - r)
    emit_seq(seq, tris)

def score(tris, label):
    good = 0; scor = 0; hit = set()
    for t in tris:
        gs = [map11.get(s) for s in t]
        if any(x is None for x in gs) or len(set(gs)) != 3:
            continue
        scor += 1
        key = tuple(sorted(gs))
        if key in faceset:
            good += 1; hit.add(faceset[key])
    print('%-24s tris %d  scorable %d  correct %d (prec %.1f%%)  distinct GT %d = %.1f%% of mesh'
          % (label, len(tris), scor, good, 100*good/max(scor,1),
             len(hit), 100*len(hit)/NF))
    return hit

print('chains: %d (>=2 rails: %d)' % (len(chains), sum(1 for c in chains if len(c)>=2)))
h_stitch = score(tris, 'STITCHED last-3')

# baseline: same last-3 but per-rail (no stitching)
tris0 = []
for rid in info:
    S = Sof[rid]; seq = []
    for gi, r, na in railturns.get(rid, []):
        seq.append(r)
        for _ in range(na):
            seq.append(S - r)
    emit_seq(seq, tris0)
h_base = score(tris0, 'per-rail last-3 (base)')
print('NEW distinct faces from stitching:', len(h_stitch - h_base))
