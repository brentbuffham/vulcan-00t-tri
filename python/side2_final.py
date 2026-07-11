"""SIDE-BIT HUNT 2, final: GT-free side/S rule + honest two-teacher scoring.

GT-FREE RULE (prediction): two-sided mirror-geometry peaks (P_v11 XY +
stream refs) -> global apex clusters -> assignment by same-family
position-conflict (occupancy) with peak-strength tiebreak (solver1).

TEACHERS (scoring only):
 T1 = fitS (vertex-adjacency vote). PROVEN AMBIGUOUS: every interior vertex
      has GT edges to BOTH adjacent lines -> tied rails' T1 side is a coin
      flip (margin 0). Split scores by T1 margin.
 T2 = EXACT-COVER teacher: each GT face may be claimed once. Rails claim
      diagonal-checked triangles per candidate S; global ICM minimizes
      double-claims. Decidable where the two candidates' scores differ.
Deliverable: side_rule.pkl {rid: (side, S_pred)} for the GT-free rule.
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

# ---------------- GT-FREE RULE ----------------
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
    S = centers[ci]
    return sum(occ[(ci, sgn)][p] for p in positions(rid, S))
for _, _, rid in order:
    cc = cands[rid]
    best = None
    for sgn, (ci, pk) in cc.items():
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
        cc = cands[rid]
        if len(cc) < 2: continue
        sgn0, ci0 = assign_rid[rid]
        for p in positions(rid, centers[ci0]):
            occ[(ci0, sgn0)][p] -= 1
        best = None
        for sgn, (ci, pk) in cc.items():
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

pred = {rid: (sgn, int(round(centers[ci])))
        for rid, (sgn, ci) in assign_rid.items()}
with open('side_rule.pkl', 'wb') as f:
    pickle.dump(pred, f)
print('GT-free rule: predictions for %d rails (saved side_rule.pkl)' % len(pred))

# ---------------- TEACHERS (SCORING ONLY) ----------------
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
F = np.load('faces_gt.npy')
faceset = set(tuple(sorted(f)) for f in F)
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

fitS = {}; margin1 = {}; top2 = {}
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
            margin1[rid] = c - (mc[1][1] if len(mc) > 1 else 0)
            top2[rid] = [s for s, cc2 in mc[:2] if cc2 >= 2]
side1 = {}; rmed_of = {}
for rid, S in fitS.items():
    rs = [r for gi, r in byrail[rid]]
    rmed = int(np.median(rs))
    if 0 <= rmed < N:
        side1[rid] = 1 if (S - rmed) > rmed else -1
        rmed_of[rid] = rmed

# T2 exact-cover teacher
def claims(rid, S):
    ts = byrail[rid]
    cl = set()
    for i in range(1, len(ts)):
        (gi0, rp), (gi, r) = ts[i-1], ts[i]
        if gi - gi0 > 60: continue
        n, np_ = S - r, S - rp
        ids = [map11.get(x) for x in (rp, np_, r, n)]
        if any(x is None for x in ids): continue
        grp, gnp, grk, gnk = ids
        for tri in ((grp, grk, gnp), (grk, gnp, gnk),
                    (grp, grk, gnk), (grp, gnp, gnk)):
            t = tuple(sorted(set(tri)))
            if len(t) == 3 and t in faceset:
                cl.add(t)
    return cl

tcands = {}
for rid in side1:
    cc = top2.get(rid, [])
    cs = {}
    for S in cc:
        cl = claims(rid, S)
        if cl:
            cs[S] = cl
    if cs:
        tcands[rid] = cs

claimed = Counter()
t2_assign = {}
torder = sorted(tcands, key=lambda r: -max(len(c) for c in tcands[r].values()))
def t2score(rid, S):
    cl = tcands[rid][S]
    return len(cl) - 2 * sum(1 for t in cl if claimed[t] > 0)
for rid in torder:
    best = max(tcands[rid], key=lambda S: t2score(rid, S))
    t2_assign[rid] = best
    for t in tcands[rid][best]:
        claimed[t] += 1
for it in range(5):
    changed = 0
    for rid in torder:
        if len(tcands[rid]) < 2: continue
        S0 = t2_assign[rid]
        for t in tcands[rid][S0]:
            claimed[t] -= 1
        best = max(tcands[rid], key=lambda S: t2score(rid, S))
        changed += (best != S0)
        t2_assign[rid] = best
        for t in tcands[rid][best]:
            claimed[t] += 1
    if not changed:
        break

side2 = {}; margin2 = {}
for rid, S in t2_assign.items():
    rmed = rmed_of[rid]
    side2[rid] = 1 if (S - rmed) > rmed else -1
    if len(tcands[rid]) >= 2:
        ss = sorted(tcands[rid], key=lambda S_: -t2score(rid, S_))
        margin2[rid] = t2score(rid, ss[0]) - t2score(rid, ss[1])
    else:
        margin2[rid] = len(tcands[rid][S])

# teacher agreement
both = [rid for rid in side2 if rid in side1]
ag = sum(1 for rid in both if side1[rid] == side2[rid])
print('\nT1 vs T2 side agreement: %d/%d = %.1f%%' % (ag, len(both), 100*ag/len(both)))
firm1 = [rid for rid in both if margin1[rid] >= 1]
ag1 = sum(1 for rid in firm1 if side1[rid] == side2[rid])
print('  on T1-firm(margin>=1): %d/%d = %.1f%%' % (ag1, len(firm1), 100*ag1/max(len(firm1),1)))

# ---------------- SCORE THE GT-FREE RULE ----------------
def score(teacher_side, teacher_S, tag, subset=None):
    rids = [r for r in pred if r in teacher_side and
            (subset is None or r in subset)]
    hs = sum(1 for r in rids if pred[r][0] == teacher_side[r])
    hS = sum(1 for r in rids if teacher_S.get(r) is not None and
             abs(pred[r][1] - teacher_S[r]) <= 2)
    print('%s: n=%d  side %.1f%%  S(+-2) %.1f%%'
          % (tag, len(rids), 100*hs/max(len(rids),1), 100*hS/max(len(rids),1)))

print('\n[teacher-forced checks of the GT-FREE rule]')
score(side1, fitS, 'vs T1 all')
score(side1, fitS, 'vs T1 firm(margin>=1)',
      set(r for r in side1 if margin1[r] >= 1))
score(side1, fitS, 'vs T1 tied(margin=0)',
      set(r for r in side1 if margin1[r] == 0))
score(side2, t2_assign, 'vs T2 all')
score(side2, t2_assign, 'vs T2 decidable(margin>=1)',
      set(r for r in side2 if margin2[r] >= 1))
score(side2, t2_assign, 'vs T2 firm(margin>=3)',
      set(r for r in side2 if margin2[r] >= 3))

# 1-cand vs 2-cand split vs T2 decidable
dec = set(r for r in side2 if margin2[r] >= 1)
for tag in (1, 2):
    sub = set(r for r in cands if len(cands[r]) == tag) & dec
    score(side2, t2_assign, '  T2-decidable, %d-cand' % tag, sub)
