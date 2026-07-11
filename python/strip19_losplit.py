"""Split the lo alphabet: v<=8 as coordinate candidate vs v>=9 as event class.
  - v<=8: rate of v in {n>>8, (n>>8)-1} (verified-mirror events)
  - v>=9: context census -- dr of the current turn (fold/fan?), rail age,
    position in rail (birth/middle/death), delim of NEXT group.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)):
        nbr[u].add(v); nbr[v].add(u)
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
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
        if gt is None:
            continue
        for vv in nbr[gt]:
            s = gt2slot11.get(vv)
            if s is not None and abs(s - r) > 3:
                votes[s + r] += 1
    if votes:
        S, c = votes.most_common(1)[0]
        if c >= 2:
            fitS[rid] = S
vpos = {}
for rid, ts in byrail.items():
    for k, (gi, r) in enumerate(ts):
        vpos[gi] = (rid, k, len(ts))

lowc = Counter(); highc_ctx = Counter()
cur_gi = None
for gi, g in enumerate(groups):
    if g['refs'] and gi in g2:
        cur_gi = gi
        continue
    if g['delim'] != 'e003' or g['is01'] or g['refs'] or len(g['lo']) != 1:
        continue
    v = g['lo'][0]
    if not (1 <= v <= 13) or cur_gi is None:
        continue
    rid, k, nvis = vpos[cur_gi]
    r = g2[cur_gi][1]
    S = fitS.get(rid)
    # dr context
    ts = byrail[rid]
    dr_next = ts[k + 1][1] - r if k + 1 < nvis else None
    dr_prev = r - ts[k - 1][1] if k > 0 else None
    if v <= 8:
        if S is None:
            continue
        n = S - r
        a, b = map11.get(r), map11.get(n)
        if a is None or b is None or b not in nbr[a]:
            continue
        hi = n >> 8
        lowc[v == hi] += 1
        lowc[('pair', v in (hi, hi - 1))] += 1
    else:
        pos = ('birth' if k == 0 else 'death' if k == nvis - 1 else 'mid')
        fold = (dr_prev is not None and dr_next is not None and
                dr_next != dr_prev)
        fan = dr_next == 0 or dr_prev == 0
        highc_ctx[(v, pos, 'fold' if fold else 'fan' if fan else '-')] += 1

print('v<=8 verified: v==hi %d, v in {hi,hi-1} %d, total %d (%.1f%% / %.1f%%)' % (
    lowc[True], lowc[('pair', True)],
    lowc[True] + lowc[False],
    100 * lowc[True] / max(lowc[True] + lowc[False], 1),
    100 * lowc[('pair', True)] / max(lowc[('pair', True)] + lowc[('pair', False)], 1)))
print('v>=9 context census (v, rail-pos, fold/fan):')
for k, c in highc_ctx.most_common(25):
    print('  ', k, c)
tot9 = sum(highc_ctx.values())
fold9 = sum(c for k, c in highc_ctx.items() if k[2] == 'fold')
fan9 = sum(c for k, c in highc_ctx.items() if k[2] == 'fan')
birth9 = sum(c for k, c in highc_ctx.items() if k[1] == 'birth')
print('v>=9: total %d, at fold %d (%.0f%%), at fan %d (%.0f%%), at birth %d (%.0f%%)'
      % (tot9, fold9, 100 * fold9 / max(tot9, 1), fan9, 100 * fan9 / max(tot9, 1),
         birth9, 100 * birth9 / max(tot9, 1)))
