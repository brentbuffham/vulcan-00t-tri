"""Inspect side_rule.pkl and compare its GT-free S to fitS (coverage + agreement)."""
import pickle
import numpy as np
from collections import Counter, defaultdict

sr = pickle.load(open('side_rule.pkl', 'rb'))
print('side_rule type:', type(sr), 'len', len(sr))
items = list(sr.items())[:5]
print('sample:', items)

# rebuild fitS for comparison
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
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
            if s is not None and abs(s - r) > 3: votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2: fitS[rid] = S

# extract S from side_rule (value may be (side,S) or S)
def getS(v):
    if isinstance(v, (tuple, list)):
        for x in v:
            if isinstance(x, (int, np.integer)) and abs(x) > 50:
                return int(x)
        return int(v[-1])
    return int(v)

both = [rid for rid in sr if rid in fitS]
agree = sum(1 for rid in both if abs(getS(sr[rid]) - fitS[rid]) <= 2)
print('rails in side_rule:', len(sr), ' in fitS:', len(fitS), ' both:', len(both))
print('GT-free S vs fitS (+-2): %d/%d = %.1f%% [teacher-forced check]'
      % (agree, len(both), 100 * agree / max(len(both), 1)))
