"""Probe inputs for the column-partition task.
1. P_v11_intercepts.npy: shape, NaNs, spatial layout, PCA sweep axes.
2. full_flags.npy: per-slot FULL/axis flags — do FULLs cluster periodically?
3. rails_v3/refs_v3: teacher-forced fitS-implied column boundary key
   (r-values and n=S-r values across rails, grouped by contiguity).
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

P = np.load('P_v11_intercepts.npy')
print('P_v11 shape', P.shape, 'dtype', P.dtype)
print('  nan rows:', int(np.isnan(P).any(axis=1).sum()) if P.ndim == 2 else '?')
if P.ndim == 2:
    ok = ~np.isnan(P).any(axis=1)
    Q = P[ok]
    print('  extents:', Q.min(0), Q.max(0))
    # PCA on XY
    XY = Q[:, :2] - Q[:, :2].mean(0)
    C = np.cov(XY.T)
    w, V = np.linalg.eigh(C)
    print('  XY eig', w, 'major axis', V[:, -1], 'minor', V[:, 0])

ff = np.load('full_flags.npy')
print('full_flags shape', ff.shape, 'sums per row', ff.sum(1))
isfull = ff[0]
idx = np.where(isfull)[0]
d = np.diff(idx)
print('FULL count', len(idx), 'gap census', sorted(Counter(d).items())[:20])
print('FULL first 40 slots:', idx[:40])

# teacher-forced key: fitS columns
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)
byrail = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        byrail[g2[gi][0]].append((gi, g2[gi][1]))
fitS = {}
for rid, ts in byrail.items():
    votes = Counter()
    for gi, r in ts:
        gt = map11.get(r)
        if gt is None: continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3: votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2: fitS[rid] = S
print('rails with fitS:', len(fitS))

# collect (r, n) per rail; ranges of r per rail and n per rail
segs = []
for rid, S in fitS.items():
    rs = sorted(r for gi, r in byrail[rid])
    ns = sorted(S - r for gi, r in byrail[rid])
    segs.append((rid, S, rs[0], rs[-1], ns[0], ns[-1], len(rs)))
segs.sort(key=lambda t: t[2])
print('rail segs (rid,S,rlo,rhi,nlo,nhi,cnt) first 40:')
for s in segs[:40]:
    print('  ', s)
# S values census — S should = base(c_r)+top(c_n): boundaries implied
print('distinct S:', len(set(s[1] for s in segs)))
print('S sorted:', sorted(set(s[1] for s in segs))[:50])
