"""SIDE-BIT HUNT 2, probe 11: PROPER teacher margin (apex-clustered votes).
margin1 (raw value ties) conflated +-1 stagger with genuine side ambiguity.
Recompute: cluster each rail's vote S values by +-3 into apexes; teacher
margin = votes(top apex) - votes(second apex). Re-split rule scores.
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P)
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']

g2 = {}
for (gi, r, fo, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)
byrail = defaultdict(list)
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        byrail[g2[gi][0]].append((gi, g2[gi][1]))

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for x, y in ((a, b), (b, c), (c, a)):
        nbr[x].add(y); nbr[y].add(x)

fitS = {}; amargin = {}; side = {}
for rid, ts in byrail.items():
    votes = Counter()
    for gi, r in ts:
        gt = map11.get(r)
        if gt is None: continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if not votes:
        continue
    # cluster votes by apex (+-3)
    sv = sorted(votes)
    cls = []; cur = [sv[0]]
    for s in sv[1:]:
        if s - cur[-1] <= 3: cur.append(s)
        else: cls.append(cur); cur = [s]
    cls.append(cur)
    scored = []
    for c in cls:
        w = sum(votes[s] for s in c)
        center = max(c, key=lambda s: votes[s])
        scored.append((w, center))
    scored.sort(reverse=True)
    w0, S = scored[0]
    if w0 < 2:
        continue
    fitS[rid] = S
    amargin[rid] = w0 - (scored[1][0] if len(scored) > 1 else 0)
    rs = [r for gi, r in ts]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1

print('labelled rails:', len(side))
h = Counter(min(amargin[r], 6) for r in side)
print('apex-margin histogram:', sorted(h.items()))

pred = pickle.load(open('side_rule.pkl', 'rb'))
for mmin in (0, 1, 2, 3, 4):
    sel = [r for r in side if r in pred and amargin[r] >= mmin]
    hs = sum(1 for r in sel if pred[r][0] == side[r])
    hS = sum(1 for r in sel if abs(pred[r][1] - fitS[r]) <= 2)
    print('apex-margin>=%d: n=%3d  side %.1f%%  S(+-2) %.1f%%'
          % (mmin, len(sel), 100*hs/max(len(sel),1), 100*hS/max(len(sel),1)))
sel = [r for r in side if r in pred and amargin[r] == 0]
hs = sum(1 for r in sel if pred[r][0] == side[r])
print('apex-margin==0 (true ambiguous): n=%d side %.1f%%'
      % (len(sel), 100*hs/max(len(sel),1)))
