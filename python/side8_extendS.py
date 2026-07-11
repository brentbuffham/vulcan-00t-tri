"""Extend GT-free S to rails side_rule missed (size-1 and no-S rails) by
snapping to the GLOBAL apex list. Grows coverage; may cost precision on weak
rails -- both reported. Saves side_rule_ext.pkl (merges side_rule).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

P = np.load('P_v11_intercepts.npy')
N = len(P); XY = P[:, :2]
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
sr = pickle.load(open('side_rule.pkl', 'rb'))
railrefs = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    if 0 <= r < N:
        railrefs[rid].append(r)

DMAX = 6.0
def vote(rs, sgn):
    lo = 2 * min(rs) - 320; hi = 2 * max(rs) + 320
    best = None
    for S in range(lo, hi + 1):
        cnt = 0; dsum = 0.0
        for r in rs:
            n = S - r
            if not (0 <= n < N) or abs(n - r) < 6: continue
            if sgn * (n - r) < 0: continue
            d = np.hypot(XY[n, 0] - XY[r, 0], XY[n, 1] - XY[r, 1])
            if d < DMAX:
                cnt += 1; dsum += d
        if cnt:
            key = (cnt, -dsum / cnt)
            if best is None or key > best[0]:
                best = (key, S)
    if best is None: return None
    (cnt, negd), S = best
    return (S, cnt, -negd)

# global apex list from all >=2 rails (same as side2_score)
allS = Counter()
for rid, rs in railrefs.items():
    if len(rs) >= 2:
        for sgn in (-1, 1):
            pk = vote(rs, sgn)
            if pk and pk[1] >= max(2, int(np.ceil(0.5*len(rs)))):
                allS[pk[0]] += pk[1]
svals = sorted(allS)
clusters = []; cur = [svals[0]]
def flush(c):
    w = sum(allS[s] for s in c)
    clusters.append(sum(s*allS[s] for s in c)/w)
for s in svals[1:]:
    if s - cur[-1] <= 3: cur.append(s)
    else: flush(cur); cur=[s]
flush(cur)
centers = np.array(clusters)
print('global apex centers:', len(centers))

# extend: for rails not in sr, snap each candidate S=2a to apex, keep if
# mirror geometry supports it. Tight band 2.5-5.0m (column pitch) for weak.
ext = dict(sr)
added = 0
for rid, rs in railrefs.items():
    if rid in sr or not rs:
        continue
    cand = []
    for a in centers:
        for sgn in (-1, 1):
            # S near 2a; refine S in +-3 around 2a by best mirror fit
            best = None
            for S in range(int(round(2*a))-3, int(round(2*a))+4):
                cnt = 0; dsum = 0.0
                for r in rs:
                    n = S - r
                    if not (0 <= n < N) or abs(n-r) < 6: continue
                    if sgn*(n-r) < 0: continue
                    d = np.hypot(XY[n,0]-XY[r,0], XY[n,1]-XY[r,1])
                    if 2.0 < d < 5.5:
                        cnt += 1; dsum += d
                if cnt and (best is None or cnt > best[0]):
                    best = (cnt, dsum/max(cnt,1), S, sgn)
            if best and best[0] >= max(1, int(np.ceil(0.5*len(rs)))):
                cand.append(best)
    if cand:
        # pick highest count, then tightest mean dist
        cand.sort(key=lambda x: (-x[0], x[1]))
        cnt, dmean, S, sgn = cand[0]
        ext[rid] = (sgn, S)
        added += 1

print('rails with S: side_rule %d -> extended %d (+%d)' % (len(sr), len(ext), added))
pickle.dump(ext, open('side_rule_ext.pkl', 'wb'))
print('saved side_rule_ext.pkl')
