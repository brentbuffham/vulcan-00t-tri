"""SIDE-BIT HUNT 2: FINAL end-to-end scorer.
GT-free pipeline: rails_v3 refs + P_v11 XY -> two-sided geometry peaks ->
global apex clusters -> same-family occupancy solver -> per-rail (side, S).
S_pred = the rail's OWN peak on the predicted side (unsnapped).
Teacher (SCORING ONLY): apex-clustered GT vertex-adjacency votes, margin =
top apex votes - runner-up apex votes. Report by margin band, rail-level
and ref-event-weighted. Saves side_rule.pkl {rid: (side, S_pred)}.
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
centers = np.array([c for c, w in clusters])
def snap(S):
    i = int(np.argmin(np.abs(centers - S)))
    return i if abs(centers[i] - S) <= 3 else None

cands = {}
for rid, (pl, pr) in peaks.items():
    cc = {}
    for sgn, pk in ((-1, pl), (1, pr)):
        if pk is None: continue
        ci = snap(pk[0])
        if ci is not None:
            cc[sgn] = (ci, pk)
    if cc:
        cands[rid] = cc

def positions(rid, S):
    return set(int(round(abs(S - 2 * r) / 2)) for r in railrefs[rid])
def strength(pk):
    return (pk[1], -pk[2])

order = []
for rid, cc in cands.items():
    if len(cc) == 1:
        order.append((0, 0, rid))
    else:
        sL = strength(cc[-1][1]); sR = strength(cc[1][1])
        order.append((1, -abs(sL[0] - sR[0]), rid))
order.sort()
occ = defaultdict(Counter)
assign_rid = {}
def penalty(rid, sgn, ci):
    return sum(occ[(ci, sgn)][p] for p in positions(rid, centers[ci]))
for _, _, rid in order:
    best = None
    for sgn, (ci, pk) in cands[rid].items():
        key = (penalty(rid, sgn, ci), -strength(pk)[0])
        if best is None or key < best[0]:
            best = (key, sgn, ci)
    _, sgn, ci = best
    assign_rid[rid] = (sgn, ci)
    for p in positions(rid, centers[ci]):
        occ[(ci, sgn)][p] += 1
for it in range(5):
    changed = 0
    for _, _, rid in order:
        if len(cands[rid]) < 2: continue
        sgn0, ci0 = assign_rid[rid]
        for p in positions(rid, centers[ci0]):
            occ[(ci0, sgn0)][p] -= 1
        best = None
        for sgn, (ci, pk) in cands[rid].items():
            key = (penalty(rid, sgn, ci), -strength(pk)[0])
            if best is None or key < best[0]:
                best = (key, sgn, ci)
        _, sgn, ci = best
        changed += ((sgn, ci) != (sgn0, ci0))
        assign_rid[rid] = (sgn, ci)
        for p in positions(rid, centers[ci]):
            occ[(ci, sgn)][p] += 1
    if not changed:
        break

pred = {}
for rid, (sgn, ci) in assign_rid.items():
    pk = cands[rid][sgn][1]
    pred[rid] = (sgn, pk[0])       # OWN peak S, unsnapped
with open('side_rule.pkl', 'wb') as f:
    pickle.dump(pred, f)
print('GT-free rule: %d rails predicted (side_rule.pkl saved)' % len(pred))

# ---------------- TEACHER (SCORING ONLY) ----------------
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
    sv = sorted(votes)
    cls = []; cur = [sv[0]]
    for s in sv[1:]:
        if s - cur[-1] <= 3: cur.append(s)
        else: cls.append(cur); cur = [s]
    cls.append(cur)
    scored = sorted(((sum(votes[s] for s in c),
                      max(c, key=lambda s: votes[s])) for c in cls),
                    reverse=True)
    w0, S = scored[0]
    if w0 < 2:
        continue
    fitS[rid] = S
    amargin[rid] = w0 - (scored[1][0] if len(scored) > 1 else 0)
    rs = [r for gi, r in ts]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side[rid] = 1 if (S - rmed) > rmed else -1

print('\n[teacher-forced checks] GT-free rule vs apex-clustered teacher')
print('%-18s %5s | %-6s %-8s | %-6s %-8s (event-weighted)' %
      ('band', 'rails', 'side', 'S(+-2)', 'side', 'S(+-2)'))
for mmin in (0, 1, 2, 3, 4):
    sel = [r for r in side if r in pred and amargin[r] >= mmin]
    if not sel: continue
    hs = sum(1 for r in sel if pred[r][0] == side[r])
    hS = sum(1 for r in sel if abs(pred[r][1] - fitS[r]) <= 2)
    wts = [len(railrefs[r]) for r in sel]
    whs = sum(w for r, w in zip(sel, wts) if pred[r][0] == side[r])
    whS = sum(w for r, w in zip(sel, wts) if abs(pred[r][1] - fitS[r]) <= 2)
    W = sum(wts)
    print('apex-margin>=%d     %5d | %5.1f%% %6.1f%%  | %5.1f%% %6.1f%%'
          % (mmin, len(sel), 100*hs/len(sel), 100*hS/len(sel),
             100*whs/W, 100*whS/W))
# coverage
allr = [r for r in side]
print('\ncoverage: rule predicts %d rails; teacher labels %d; overlap %d'
      % (len(pred), len(side), len([r for r in side if r in pred])))
