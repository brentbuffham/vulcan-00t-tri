"""SIDE-BIT HUNT 2, probe 6: GLOBAL APEX SOLVER.
Insight (side2_look): S = 2 x fold apex of the serpentine; rails zip
symmetric pairs (a-k, a+k+1) around apex a. A rail's two geometry peaks are
the folds ABOVE/BELOW its line - both real folds; side = which one it zips.
S values are GLOBAL (many rails share each apex).

GT-free pipeline:
 1. per-rail two-sided geometry peaks (P_v11 XY, stream refs only)
 2. cluster all peaks -> global apex/S candidate list
 3. greedy + ICM assignment: rails pick one of their <=2 snapped candidates
    minimizing POSITION-OVERLAP within (apex, family) occupancy
 4. score side & S vs teacher [teacher-forced check, scoring only]
"""
import os, pickle
import numpy as np
from collections import Counter, defaultdict

os.chdir(os.path.dirname(os.path.abspath(__file__)))

P = np.load('P_v11_intercepts.npy')
N = len(P)
XY = P[:, :2]
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
    if len(rs) < 2:
        continue
    peaks[rid] = (vote(rs, -1), vote(rs, +1))
print('rails with peaks:', sum(1 for v in peaks.values() if v[0] or v[1]))

# ---- 2. cluster ALL peak S values (GT-free)
allS = Counter()
for rid, (pl, pr) in peaks.items():
    for pk in (pl, pr):
        if pk is not None:
            allS[pk[0]] += pk[1]          # weight by supporting ref count
# merge S values within +-3 into clusters (weighted)
svals = sorted(allS)
clusters = []          # list of (center, weight)
cur = [svals[0]]
def flush(cur):
    w = sum(allS[s] for s in cur)
    c = sum(s * allS[s] for s in cur) / w
    clusters.append((c, w))
for s in svals[1:]:
    if s - cur[-1] <= 3:
        cur.append(s)
    else:
        flush(cur); cur = [s]
flush(cur)
print('apex clusters (weight>=3): %d of %d' %
      (sum(1 for c, w in clusters if w >= 3), len(clusters)))

centers = np.array([c for c, w in clusters])
weights = np.array([w for c, w in clusters])

def snap(S):
    i = int(np.argmin(np.abs(centers - S)))
    if abs(centers[i] - S) <= 3:
        return i
    return None

# ---- teacher key (SCORING ONLY)
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

# teacher checks on the cluster list
hit = sum(1 for S in set(fitS.values())
          if np.min(np.abs(centers - S)) <= 2)
print('[teacher check] distinct fitS within +-2 of a cluster center: %d/%d'
      % (hit, len(set(fitS.values()))))
both_ok = 0; tot = 0
for rid in fitS:
    if rid not in peaks: continue
    pl, pr = peaks[rid]
    cands = [pk[0] for pk in (pl, pr) if pk is not None]
    if not cands: continue
    tot += 1
    both_ok += any(abs(S - fitS[rid]) <= 2 for S in cands)
print('[teacher check] true S among rail candidates: %d/%d = %.1f%%'
      % (both_ok, tot, 100 * both_ok / max(tot, 1)))

# ---- 3. global assignment with position-overlap penalty
# candidate list per rail: snapped clusters for each side peak
cands = {}
for rid, (pl, pr) in peaks.items():
    cc = {}
    for sgn, pk in ((-1, pl), (1, pr)):
        if pk is None: continue
        ci = snap(pk[0])
        if ci is None: continue
        cc[sgn] = (ci, pk)
    if cc:
        cands[rid] = cc

def positions(rid, S):
    rs = railrefs[rid]
    return set(int(round(abs(S - 2 * r) / 2)) for r in rs)

# order: single-candidate rails first, then by peak strength margin
def strength(pk):
    return (pk[1], -pk[2])
order = []
for rid, cc in cands.items():
    if len(cc) == 1:
        order.append((0, 0, rid))
    else:
        sL = strength(cc[-1][1]); sR = strength(cc[1][1])
        margin = abs(sL[0] - sR[0])
        order.append((1, -margin, rid))
order.sort()

occ = defaultdict(Counter)          # (cluster, family) -> position multiset
assign_rid = {}
def penalty(rid, sgn, ci):
    S = centers[ci]
    pos = positions(rid, S)
    fam = sgn
    return sum(occ[(ci, fam)][p] for p in pos)

for _, _, rid in order:
    cc = cands[rid]
    best = None
    for sgn, (ci, pk) in cc.items():
        pen = penalty(rid, sgn, ci)
        key = (pen, -strength(pk)[0])
        if best is None or key < best[0]:
            best = (key, sgn, ci)
    _, sgn, ci = best
    assign_rid[rid] = (sgn, ci)
    S = centers[ci]
    for p in positions(rid, S):
        occ[(ci, sgn)][p] += 1

# ICM refinement passes
for it in range(3):
    changed = 0
    for _, _, rid in order:
        cc = cands[rid]
        if len(cc) < 2:
            continue
        sgn0, ci0 = assign_rid[rid]
        S0 = centers[ci0]
        for p in positions(rid, S0):
            occ[(ci0, sgn0)][p] -= 1
        best = None
        for sgn, (ci, pk) in cc.items():
            pen = penalty(rid, sgn, ci)
            key = (pen, -strength(pk)[0])
            if best is None or key < best[0]:
                best = (key, sgn, ci)
        _, sgn, ci = best
        if (sgn, ci) != (sgn0, ci0):
            changed += 1
        assign_rid[rid] = (sgn, ci)
        S = centers[ci]
        for p in positions(rid, S):
            occ[(ci, sgn)][p] += 1
    print('ICM pass %d: %d changes' % (it, changed))
    if not changed:
        break

# ---- 4. score
pred_side = {rid: sgn for rid, (sgn, ci) in assign_rid.items()}
lab = [rid for rid in pred_side if rid in side]
hit = sum(1 for rid in lab if pred_side[rid] == side[rid])
print('\n[teacher-forced check] SIDE: %d/%d = %.1f%%  (coverage %d/%d labelled)'
      % (hit, len(lab), 100 * hit / max(len(lab), 1), len(lab), len(side)))
sh = 0; st = 0
for rid in lab:
    sgn, ci = assign_rid[rid]
    S = int(round(centers[ci]))
    st += 1
    sh += (abs(S - fitS[rid]) <= 2)
print('[teacher-forced check] S(+-2): %d/%d = %.1f%%' % (sh, st, 100 * sh / max(st, 1)))
# split: single vs double candidates
for tag, sel in (('1-cand', [r for r in lab if len(cands[r]) == 1]),
                 ('2-cand', [r for r in lab if len(cands[r]) == 2])):
    h = sum(1 for rid in sel if pred_side[rid] == side[rid])
    print('  %s: side %d/%d = %.1f%%' % (tag, h, len(sel), 100 * h / max(len(sel), 1)))
