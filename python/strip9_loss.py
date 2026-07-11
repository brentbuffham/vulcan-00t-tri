"""Where does strip8's loss live? Hit rate vs (a) |dr| step class,
(b) rail purity (fraction of +/-1 steps within rail), (c) map coverage.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v2.pkl', 'rb'))
rv = pickle.load(open('rails_v2.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
faceset = set(tuple(sorted(f)) for f in F)
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)

g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

turns = []
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        continue
    if g['refs']:
        if gi in g2:
            cur = len(turns)
            turns.append([g2[gi][0], gi, g2[gi][1], 0])
        else:
            cur = None
        continue
    if g['delim'] == 'e003' and cur is not None:
        turns[cur][3] += 1

byrail = defaultdict(list)
for t in turns:
    byrail[t[0]].append(t)
fitS = {}
for rid, ts in byrail.items():
    votes = Counter()
    for _, gi, r, na in ts:
        gt = map11.get(r)
        if gt is None:
            continue
        for v in nbr[gt]:
            s = gt2slot11.get(v)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S

def purity(rl):
    vs = [v for _, v, _ in rl['vals']]
    if len(vs) < 2:
        return 0.0
    st = [abs(b - a) for a, b in zip(vs, vs[1:])]
    return sum(1 for s in st if s == 1) / len(st)

def isface(*tri):
    return len(set(tri)) == 3 and tuple(sorted(tri)) in faceset

by_dr = defaultdict(lambda: [0, 0])
by_pur = defaultdict(lambda: [0, 0])
gap_ct = defaultdict(lambda: [0, 0])   # turn gi-gap between consecutive turns
for rid, ts in byrail.items():
    S = fitS.get(rid)
    if S is None:
        continue
    pur = round(purity(rails[rid]), 1)
    prev = None
    for _, gi, r, na in ts:
        if na == 0:
            prev = None if prev is None else prev
            continue
        n0 = S - r
        if prev is not None:
            rp, np1, gi_p = prev
            dr = r - rp
            mp = [map11.get(x) for x in (rp, np1, r, n0)]
            if all(x is not None for x in mp):
                grp, gnp, grk, gnk = mp
                if dr == 0:
                    hit = False  # mirror can't do fans; count separately
                    by_dr['fan'][1] += 1
                else:
                    A = isface(grp, grk, gnp) and isface(grk, gnp, gnk)
                    B = isface(grp, grk, gnk) and isface(grp, gnp, gnk)
                    hit = A or B
                    key = abs(dr) if abs(dr) <= 3 else '4+'
                    by_dr[key][0] += hit; by_dr[key][1] += 1
                    by_pur[pur][0] += hit; by_pur[pur][1] += 1
                    gk = min(gi - gi_p, 12)
                    gap_ct[gk][0] += hit; gap_ct[gk][1] += 1
        prev = (r, S - r, gi)

print('hit rate by |dr|:')
for k in sorted(by_dr, key=str):
    h, t = by_dr[k]
    print('  |dr|=%s: %d/%d = %.0f%%' % (k, h, t, 100 * h / max(t, 1)))
print('hit rate by rail +/-1 purity:')
for k in sorted(by_pur):
    h, t = by_pur[k]
    print('  pur=%.1f: %d/%d = %.0f%%' % (k, h, t, 100 * h / max(t, 1)))
print('hit rate by turn gi-gap:')
for k in sorted(gap_ct):
    h, t = gap_ct[k]
    print('  gap=%s: %d/%d = %.0f%%' % (k, h, t, 100 * h / max(t, 1)))
