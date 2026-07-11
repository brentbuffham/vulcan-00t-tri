"""SIDE-BIT HUNT 2, probe 9: apex-chain structural features for tied rails.
Chain of apex clusters = fold list -> line intervals. Features per candidate:
  H mirror containment: mirrors n=S-r must stay inside the adjacent line
    (between the two apexes bounding it). count violations; fewer = better.
  I apex proximity: |S/2 - rmed| smaller vs larger -> which is true?
  J position sanity: pmax <= implied gap length.
Also teacher-diagnostics: fitS vote margin on 2-cand rails (is the key firm?)
[teacher-forced check]
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P); XY = P[:, :2]
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
refs, assign = rv['refs'], rv['assign']
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
    if cnt >= max(2, int(np.ceil(0.5 * len(rs)))):
        return (S, cnt, -negd)
    return None

peaks = {}
for rid, rs in railrefs.items():
    if len(rs) >= 2:
        peaks[rid] = (vote(rs, -1), vote(rs, +1))

allS = Counter()
for rid, (pl, pr) in peaks.items():
    for pk in (pl, pr):
        if pk is not None:
            allS[pk[0]] += pk[1]
svals = sorted(allS)
clusters = []; cur = [svals[0]]
def flush(cur):
    w = sum(allS[s] for s in cur)
    clusters.append((sum(s * allS[s] for s in cur) / w, w))
for s in svals[1:]:
    if s - cur[-1] <= 3: cur.append(s)
    else: flush(cur); cur = [s]
flush(cur)
# apex chain: keep weight>=3 clusters, sorted
apexes = sorted(c / 2.0 for c, w in clusters if w >= 3)
apexes = np.array(apexes)
print('apex chain: %d apexes, spacing median %.1f' %
      (len(apexes), np.median(np.diff(apexes))))

# teacher key (SCORING ONLY)
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
fitS = {}; fitmargin = {}
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
        mc = votes.most_common()
        S, c = mc[0]
        if c >= 2:
            fitS[rid] = S
            fitmargin[rid] = c - (mc[1][1] if len(mc) > 1 else 0)
side = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1

two = [rid for rid, (pl, pr) in peaks.items()
       if pl is not None and pr is not None and rid in side]
tied = [rid for rid in two if peaks[rid][0][1] == peaks[rid][1][1]]
print('2-cand labelled: %d, strength-tied: %d' % (len(two), len(tied)))

def line_interval(x):
    """line containing slot x = between the two neighbouring apexes"""
    i = np.searchsorted(apexes, x)
    lo = apexes[i-1] if i > 0 else 0
    hi = apexes[i] if i < len(apexes) else N
    return lo, hi

def feats(rid, S):
    rs = sorted(railrefs[rid])
    ns = [S - r for r in rs if 0 <= S - r < N]
    if not ns:
        return None
    # containment: all mirrors within ONE line interval adjacent to r's line
    viol = 0
    lo, hi = line_interval(np.median(ns))
    for n in ns:
        if not (lo - 2 <= n <= hi + 2):
            viol += 1
    rmed = np.median(rs)
    prox = abs(S / 2.0 - rmed)
    # same-line check: mirror line must be ADJACENT to ref line
    rlo, rhi = line_interval(rmed)
    nlo, nhi = line_interval(np.median(ns))
    adjacent = (abs(rlo - nhi) < 3 or abs(rhi - nlo) < 3)
    sameline = (abs(rlo - nlo) < 3)
    return dict(viol=viol, prox=prox, adjacent=int(adjacent),
                sameline=int(sameline))

def run(subset, tag):
    sc = defaultdict(lambda: [0, 0])
    for rid in subset:
        pl, pr = peaks[rid]
        fl = feats(rid, pl[0]); fr = feats(rid, pr[0])
        if fl is None or fr is None: continue
        truth = side[rid]
        tests = {
            'H_viol_less': (fl['viol'], fr['viol'], 'less'),
            'I_prox_less': (fl['prox'], fr['prox'], 'less'),
            'I_prox_MORE': (fl['prox'], fr['prox'], 'more'),
            'K_adjacent': (-fl['adjacent'], -fr['adjacent'], 'less'),
            'L_not_sameline': (fl['sameline'], fr['sameline'], 'less'),
        }
        for name, (vl, vr, mode) in tests.items():
            if vl == vr: continue
            guess = (-1 if vl < vr else 1) if mode == 'less' else (-1 if vl > vr else 1)
            sc[name][1] += 1
            sc[name][0] += (guess == truth)
    print('\n%s (n=%d):' % (tag, len(subset)))
    for name, (h, d) in sorted(sc.items()):
        print('  %-14s %3d/%3d = %5.1f%%  (cov %.0f%%)'
              % (name, h, d, 100 * h / max(d, 1), 100 * d / max(len(subset), 1)))

run(two, 'ALL 2-cand')
run(tied, 'strength-TIED')

# teacher-key firmness on tied rails
m = [fitmargin[rid] for rid in tied]
print('\nfitS vote margin on tied rails: median %d, <=1: %d/%d'
      % (int(np.median(m)), sum(1 for x in m if x <= 1), len(m)))
