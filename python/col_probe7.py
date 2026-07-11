"""Do coord-stream events (FULL flags, k0 sites) mark folds?
Compare distance-to-nearest-event for teacher folds vs random slots.
Check the 10 P_v11-invisible missed folds specifically.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

ff = np.load('full_flags.npy')
isfull = np.where(ff[0])[0]
fx, fy, fz = (np.where(ff[i])[0] for i in (1, 2, 3))
k0 = pickle.load(open('k0_sites.pkl', 'rb'))
print('k0 sites:', len(k0), 'sample keys:', list(k0[0].keys()) if isinstance(k0, list) else '?')
k0slots = []
for site in (k0 if isinstance(k0, list) else []):
    for key in ('slot', 'oi', 'vi', 'pt'):
        if key in site:
            k0slots.append(site[key])
            break
k0slots = np.array(sorted(set(k0slots)))
print('k0 slot-like values: n=%d range %s..%s' %
     (len(k0slots), k0slots.min() if len(k0slots) else '-', k0slots.max() if len(k0slots) else '-'))

# teacher folds
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for x, y in ((a, b), (b, c), (c, a)):
        nbr[x].add(y); nbr[y].add(x)
g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
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
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S
implied = sorted({(S - 1) // 2 for S in fitS.values() if S % 2 == 1})
missed = [235, 949, 973, 1004, 1503, 1546, 1874, 2277, 2808, 2922]

rng = np.random.default_rng(0)
rand = rng.integers(20, 2900, 500)

def stats(events, name):
    ev = np.asarray(sorted(events))
    if not len(ev):
        return
    def dmin(x):
        i = np.searchsorted(ev, x)
        c = []
        if i > 0: c.append(abs(x - ev[i - 1]))
        if i < len(ev): c.append(abs(x - ev[i]))
        return min(c)
    dt = [dmin(kf) for kf in implied]
    dr = [dmin(x) for x in rand]
    dm = [dmin(kf) for kf in missed]
    print('%s: n=%d  median dist teacher=%.1f rand=%.1f | <=1: teacher %.0f%% rand %.0f%% | missed folds dists %s' %
          (name, len(ev), np.median(dt), np.median(dr),
           100 * np.mean([d <= 1 for d in dt]), 100 * np.mean([d <= 1 for d in dr]),
           dm))

stats(isfull, 'FULL ')
stats(fx, 'fullX')
stats(fy, 'fullY')
stats(fz, 'fullZ')
if len(k0slots):
    stats(k0slots, 'k0   ')
