"""SIDE-BIT HUNT 2, probe 7: which feature separates 2-cand rails?
Context = ONLY the 1-cand anchor rails (95.6% reliable, GT-free).
For each 2-cand labelled rail score candidate features L vs R:
  A same-family position overlap with anchors (less = better)
  B cross-family position overlap with anchors (more = better)
  C gi proximity to the apex's anchor activity (closer = better)
  D peak strength (higher count = better)
  E cluster weight (higher = better)
  F chain-adjacency: positions adjacent to anchor-covered positions
  G mirror-slot coverage: candidate mirrors inside anchor REF territory
[teacher-forced check per feature]
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
railgi = defaultdict(list)
for (gi, r, fo, dl), rid in zip(refs, assign):
    railgi[rid].append(gi)

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
clusters = []
cur = [svals[0]]
def flush(cur):
    w = sum(allS[s] for s in cur)
    c = sum(s * allS[s] for s in cur) / w
    clusters.append((c, w))
for s in svals[1:]:
    if s - cur[-1] <= 3: cur.append(s)
    else: flush(cur); cur = [s]
flush(cur)
centers = np.array([c for c, w in clusters])
cweights = np.array([w for c, w in clusters])
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

# anchors = 1-cand rails
anchors = [rid for rid, cc in cands.items() if len(cc) == 1]
occ = defaultdict(set)          # (ci, fam) -> positions (anchors only)
apex_gi = defaultdict(list)     # ci -> anchor gi's
refslots = defaultdict(set)     # ci -> anchor ref slots
for rid in anchors:
    sgn, (ci, pk) = next(iter(cands[rid].items()))
    S = centers[ci]
    occ[(ci, sgn)] |= positions(rid, S)
    apex_gi[ci] += railgi[rid]
    refslots[ci] |= set(railrefs[rid])

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

two = [rid for rid, cc in cands.items() if len(cc) == 2 and rid in side]
print('2-cand labelled rails:', len(two))

scores = defaultdict(lambda: [0, 0])   # feature -> [hits, decided]
for rid in two:
    cc = cands[rid]
    feats = {}
    for sgn, (ci, pk) in cc.items():
        S = centers[ci]
        pos = positions(rid, S)
        mir = set(int(round(S - r)) for r in railrefs[rid])
        A = len(pos & occ[(ci, sgn)])
        B = len(pos & occ[(ci, -sgn)])
        Cg = (abs(np.median(railgi[rid]) - np.median(apex_gi[ci]))
              if apex_gi[ci] else 1e9)
        D = pk[1]
        E = cweights[ci]
        adj = sum(1 for p in pos
                  if p not in occ[(ci, sgn)] and
                  ((p - 1) in occ[(ci, sgn)] or (p + 1) in occ[(ci, sgn)]))
        G = len(mir & refslots[ci])
        feats[sgn] = dict(A=A, B=B, C=Cg, D=D, E=E, F=adj, G=G)
    fL, fR = feats[-1], feats[1]
    truth = side[rid]
    tests = {
        'A_less_samefam': (fL['A'], fR['A'], 'less'),
        'B_more_crossfam': (fL['B'], fR['B'], 'more'),
        'C_gi_closer': (fL['C'], fR['C'], 'less'),
        'D_strength': (fL['D'], fR['D'], 'more'),
        'E_clusterw': (fL['E'], fR['E'], 'more'),
        'F_chain_adj': (fL['F'], fR['F'], 'more'),
        'G_mirror_in_refs': (fL['G'], fR['G'], 'more'),
    }
    for name, (vl, vr, mode) in tests.items():
        if vl == vr:
            continue
        if mode == 'less':
            guess = -1 if vl < vr else 1
        else:
            guess = -1 if vl > vr else 1
        scores[name][1] += 1
        scores[name][0] += (guess == truth)

print('\nfeature -> accuracy on decided (of %d):' % len(two))
for name, (h, d) in sorted(scores.items()):
    print('  %-18s %3d/%3d = %5.1f%%  (coverage %.0f%%)'
          % (name, h, d, 100 * h / max(d, 1), 100 * d / len(two)))
