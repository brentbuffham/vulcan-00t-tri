"""Validate the strip-stitch rule (GT-free): at a fold the ref/mirror columns
swap, so rail A's MIRROR range [S_A-rhi, S_A-rlo] should match some later
rail B's REF range [rlo_B, rhi_B]. Measure chain formation + lengths.
Uses side_rule_ext S. GT (map11/faces) not used here at all (pure structure).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
ext = pickle.load(open('side_rule_ext.pkl', 'rb'))
Sof = {rid: v[1] for rid, v in ext.items()}

# rail ref-values + birth/death gi
railrefs = defaultdict(list); railgi = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    railrefs[rid].append(r); railgi[rid].append(gi)

info = {}
for rid, rs in railrefs.items():
    if rid not in Sof:
        continue
    S = Sof[rid]
    rlo, rhi = min(rs), max(rs)
    mlo, mhi = S - rhi, S - rlo   # mirror range
    info[rid] = dict(S=S, rlo=rlo, rhi=rhi, mlo=mlo, mhi=mhi,
                     g0=min(railgi[rid]), g1=max(railgi[rid]), n=len(rs))
print('rails with S:', len(info))

def overlap(a0, a1, b0, b1):
    return max(0, min(a1, b1) - max(a0, b0) + 1)

# for each A, find best B whose ref-range matches A's mirror-range
links = {}
matched = 0
for A, ia in info.items():
    span = ia['mhi'] - ia['mlo'] + 1
    best = None
    for B, ib in info.items():
        if B == A:
            continue
        ov = overlap(ia['mlo'], ia['mhi'], ib['rlo'], ib['rhi'])
        if ov <= 0:
            continue
        frac = ov / max(span, 1)
        # prefer B that starts near/after A and best overlap
        dgi = ib['g0'] - ia['g1']
        key = (frac, -abs(dgi))
        if best is None or key > best[0]:
            best = (key, B, frac, dgi)
    if best and best[2] >= 0.5:
        links[A] = best[1]
        matched += 1
print('rails whose mirror-range matches another rail ref-range (>=50%%): %d/%d = %.1f%%'
      % (matched, len(info), 100*matched/len(info)))

# chain lengths (follow links, treat as directed graph, find path components)
seen = set(); chains = []
# build reverse to find chain starts (no incoming)
incoming = set(links.values())
starts = [r for r in info if r not in incoming]
for s in starts:
    chain = []; x = s; local = set()
    while x is not None and x not in local:
        chain.append(x); local.add(x); x = links.get(x)
    chains.append(chain)
    seen |= local
# cyclic leftovers
for r in info:
    if r not in seen:
        chain = []; x = r; local = set()
        while x is not None and x not in local:
            chain.append(x); local.add(x); x = links.get(x)
        chains.append(chain); seen |= local
clen = Counter(len(c) for c in chains)
print('chains:', len(chains), ' length dist:', sorted(clen.items())[:15])
print('rails covered by chains >=2:', sum(len(c) for c in chains if len(c) >= 2))
tot_turns = sum(info[r]['n'] for c in chains if len(c) >= 2 for r in c)
print('ref-turns in multi-rail chains:', tot_turns)

# sanity: do chained rails have DIFFERENT (stepping) S? (folds change apex)
dS = []
for A, B in links.items():
    dS.append(info[B]['S'] - info[A]['S'])
print('chain-link dS (S_B - S_A) census top12:', Counter(dS).most_common(12))
