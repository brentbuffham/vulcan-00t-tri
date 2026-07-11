"""SIDE-BIT HUNT 2, probe 2: the SHINGLE-CHAIN constraint.
Mechanism: rail allocs (mirror n = S-r) are FIRST USES; those slots may be
ref'd LATER (next strip refs the column this rail allocated) but never
EARLIER. The wrong-side interval (reflection about r) lies in an older
column: ref'd EARLIER. Refs are explicit in the stream -> GT-free signal.

Part 1 [teacher mechanism check]: for true n (fitS) vs reflected n, count
per-slot explicit refs BEFORE vs AFTER the alloc turn's gi.
Part 2 [GT-free rule, teacher-scored]: geometry peaks S_L/S_R (col_probe10
vote) + before/after-ref counts + single-peak fallback -> predicted side.
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
print('labelled rails:', len(side), 'balance:', Counter(side.values()))

# ---- GT-free: explicit-ref occurrence gi per slot (ALL refs, all rails)
refgi = defaultdict(list)
for (gi, r, fo, dl) in refs:
    if 0 <= r < N:
        refgi[r].append(gi)
for v in refgi.values():
    v.sort()

def before_after(nvals_gis):
    """for [(n, gi_of_turn)] count explicit refs to n before/after gi."""
    nb = na = 0
    for n, gi in nvals_gis:
        for g in refgi.get(n, ()):
            if g < gi: nb += 1
            elif g > gi: na += 1
    return nb, na

# ---- Part 1: teacher mechanism check
sep_ok = sep_bad = sep_tie = 0
agg = Counter()
for rid, S in fitS.items():
    ts = byrail[rid]
    rs = [r for gi, r in ts]
    rmed = int(np.median(rs))
    true_list = [(S - r, gi) for gi, r in ts if 0 <= S - r < N]
    refl_list = [(2 * rmed - (S - r), gi) for gi, r in ts
                 if 0 <= 2 * rmed - (S - r) < N]
    tb, ta = before_after(true_list)
    rb, ra = before_after(refl_list)
    agg['true_before'] += tb; agg['true_after'] += ta
    agg['refl_before'] += rb; agg['refl_after'] += ra
    # discriminant: true side should have (after - before) HIGHER
    dt, dr = ta - tb, ra - rb
    if dt > dr: sep_ok += 1
    elif dt < dr: sep_bad += 1
    else: sep_tie += 1
print('\nPart 1 [teacher mechanism check, %d rails]:' % len(fitS))
print('  aggregate: true n  refs before=%d after=%d | reflected n  before=%d after=%d'
      % (agg['true_before'], agg['true_after'], agg['refl_before'], agg['refl_after']))
print('  per-rail discriminant (after-before): true wins %d, loses %d, ties %d'
      % (sep_ok, sep_bad, sep_tie))

# ---- Part 2: GT-free rule with geometry peaks (from col_probe10)
DMAX = 6.0
railrefs = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    if 0 <= r < N:
        railrefs[rid].append(r)

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

pred = {}
cls_of = {}
for rid in side:            # evaluate on labelled rails
    rs = railrefs[rid]
    if len(rs) < 2:
        continue
    pl = vote(rs, -1); pr = vote(rs, +1)
    ts = byrail[rid]
    cand = {}
    for sgn, pk in ((-1, pl), (1, pr)):
        if pk is None: continue
        S = pk[0]
        lst = [(S - r, gi) for gi, r in ts if 0 <= S - r < N]
        nb, na = before_after(lst)
        cand[sgn] = (na - nb, pk)
    if not cand:
        cls_of[rid] = 'no_peak'
        continue
    if len(cand) == 1:
        pred[rid] = next(iter(cand))
        cls_of[rid] = 'single_peak'
    else:
        dL, dR = cand[-1][0], cand[1][0]
        if dL != dR:
            pred[rid] = -1 if dL > dR else 1
            cls_of[rid] = 'chain_decided'
        else:
            kL, kR = cand[-1][1], cand[1][1]
            pred[rid] = -1 if (kL[1], -kL[2]) > (kR[1], -kR[2]) else 1
            cls_of[rid] = 'tie_geofallback'

hit = sum(1 for rid in pred if pred[rid] == side[rid])
print('\nPart 2 [GT-free rule, teacher-forced check]:')
print('  predicted %d/%d labelled rails; correct %d = %.1f%%'
      % (len(pred), len(side), hit, 100 * hit / max(len(pred), 1)))
for cls in ('no_peak', 'single_peak', 'chain_decided', 'tie_geofallback'):
    sel = [rid for rid in cls_of if cls_of[rid] == cls]
    h = sum(1 for rid in sel if rid in pred and pred[rid] == side[rid])
    n = sum(1 for rid in sel if rid in pred)
    print('  %-16s n=%3d  correct %d/%d = %.1f%%'
          % (cls, len(sel), h, n, 100 * h / max(n, 1)))
