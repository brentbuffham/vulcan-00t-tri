"""Decisive GT-free S test: if the mirror column is CONTIGUOUS with the ref
column in slot space, S = r + n is fixed by the rail's OWN r-range.
  mirror below:  n in [.., r_lo-1]  => S = r_lo + (r_lo-1) = 2*r_lo - 1
  mirror above:  n in [r_hi+1, ..]  => S = r_hi + (r_hi+1) = 2*r_hi + 1
Also generic S = r_lo + r_hi + k (fold at column ends) and 2*r_mid.
Compare each rail's fitS (GT answer key, MECHANISM validation) to these
GT-free predictors. Win: a predictor matching fitS within +-2 at >=80%.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

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

preds = defaultdict(lambda: [0, 0])
detail = []
for rid, S in fitS.items():
    rs = [r for _, r in byrail[rid]]
    if len(rs) < 3: continue
    rlo, rhi = min(rs), max(rs)
    cands = {
        '2*rlo-1': 2*rlo - 1, '2*rlo': 2*rlo, '2*rlo+1': 2*rlo + 1,
        '2*rhi+1': 2*rhi + 1, '2*rhi': 2*rhi, '2*rhi-1': 2*rhi - 1,
        'rlo+rhi': rlo + rhi, 'rlo+rhi-1': rlo + rhi - 1,
    }
    for name, val in cands.items():
        preds[name][1] += 1
        preds[name][0] += abs(S - val) <= 2
    # record best-matching offset for the 2*rlo and 2*rhi families
    detail.append((S - 2*rlo, S - 2*rhi, rlo, rhi, S, len(rs)))

print('rails scored:', len(detail))
for name, (ok, t) in sorted(preds.items(), key=lambda kv: -kv[1][0]):
    print('  S == %-10s (+-2): %d/%d = %.1f%%' % (name, ok, t, 100*ok/max(t,1)))

# distribution of S-2*rlo and S-2*rhi -- is there a CONSTANT offset?
d_lo = Counter(x[0] for x in detail)
d_hi = Counter(x[1] for x in detail)
print('S - 2*rlo top12:', d_lo.most_common(12))
print('S - 2*rhi top12:', d_hi.most_common(12))

# maybe S = rlo + rhi + (column length) -- check S-(rlo+rhi) vs rhi-rlo
off = [(x[4]-(x[2]+x[3]), x[3]-x[2]) for x in detail]
print('sample (S-(rlo+rhi), rhi-rlo):', off[:20])
