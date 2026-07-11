"""SIDE-BIT HUNT 2, probe 8: fine geometric discriminators for 2-cand rails.
For each candidate side: mirror set n = S-r. Features:
  d_mean, d_std of rung length |XY[n]-XY[r]|
  rung parallelism: circular std of rung direction
  mirror-walk continuity: step size between consecutive mirrors
  dz_med: |Z[n]-Z[r]| median
Scored on 2-cand labelled rails, overall and on D-strength-tied subset.
[teacher-forced check]
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P); XY = P[:, :2]; Z = P[:, 2]
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
side = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1

def geo_feats(rid, S):
    rs = sorted(railrefs[rid])
    rungs = []; ns = []
    for r in rs:
        n = S - r
        if 0 <= n < N:
            v = XY[n] - XY[r]
            rungs.append(v); ns.append(n)
    if len(rungs) < 2:
        return None
    rungs = np.array(rungs)
    d = np.hypot(rungs[:, 0], rungs[:, 1])
    ang = np.arctan2(rungs[:, 1], rungs[:, 0])
    R = np.hypot(np.mean(np.cos(ang)), np.mean(np.sin(ang)))  # 1=parallel
    steps = [np.hypot(*(XY[ns[i+1]] - XY[ns[i]])) for i in range(len(ns)-1)]
    dz = [abs(Z[S - r] - Z[r]) for r in rs if 0 <= S - r < N]
    return dict(dmean=float(np.mean(d)), dstd=float(np.std(d)),
                par=float(R), step=float(np.median(steps)),
                dz=float(np.median(dz)))

two = []
for rid, (pl, pr) in peaks.items():
    if pl is not None and pr is not None and rid in side:
        two.append(rid)
print('2-cand labelled rails:', len(two))

scores = defaultdict(lambda: [0, 0])
tied = []
for rid in two:
    pl, pr = peaks[rid]
    if pl[1] == pr[1]:
        tied.append(rid)
print('D-strength-tied:', len(tied))

def run(subset, tag):
    sc = defaultdict(lambda: [0, 0])
    for rid in subset:
        pl, pr = peaks[rid]
        gl = geo_feats(rid, pl[0]); gr = geo_feats(rid, pr[0])
        if gl is None or gr is None:
            continue
        truth = side[rid]
        tests = {
            'dmean_less': (gl['dmean'], gr['dmean'], 'less'),
            'dstd_less': (gl['dstd'], gr['dstd'], 'less'),
            'par_more': (gl['par'], gr['par'], 'more'),
            'step_sane': (abs(gl['step'] - 4.0), abs(gr['step'] - 4.0), 'less'),
            'dz_less': (gl['dz'], gr['dz'], 'less'),
        }
        for name, (vl, vr, mode) in tests.items():
            if vl == vr: continue
            guess = (-1 if vl < vr else 1) if mode == 'less' else (-1 if vl > vr else 1)
            sc[name][1] += 1
            sc[name][0] += (guess == truth)
        # combo: parallelism primary, dmean tiebreak
    print('\n%s (n=%d):' % (tag, len(subset)))
    for name, (h, d) in sorted(sc.items()):
        print('  %-12s %3d/%3d = %5.1f%%  (cov %.0f%%)'
              % (name, h, d, 100 * h / max(d, 1), 100 * d / max(len(subset), 1)))

run(two, 'ALL 2-cand')
run(tied, 'strength-TIED subset')
