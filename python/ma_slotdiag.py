#!/usr/bin/env python3
"""DIAGNOSTIC: what is the 2964(v11)-vs-2975(GT) slot gap, really?
Establish BEFORE attempting alignment: is it 11 clean monotonic drops, or
unreferenced GT verts / decoder duplicates / framing skips? Also inspect the
ref_events structure to see whether explicit ref indices can ANCHOR alignment
(the strong signal the same-group-edge heuristic lacks). GT for labeling only.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict
from scipy.spatial import cKDTree

P = np.load('P_v11_intercepts.npy')
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
F = np.load('faces_gt.npy')
print(f'P_v11 rows {len(P)}   GT verts {len(G)}   GT faces {len(F)}   gap {len(G)-len(P)}')

# (1) unreferenced GT vertices (would explain part of the gap w/o any "drop")
used = set()
for a, b, c in F:
    used.update((int(a), int(b), int(c)))
unref = [i for i in range(len(G)) if i not in used]
print(f'\n(1) GT verts NOT referenced by any face: {len(unref)}  {unref[:20]}')
# expected simple-mesh count check
print(f'    t=2v-4 check: faces {len(F)} vs 2*{len(G)}-4 = {2*len(G)-4}  (diff {2*len(G)-4-len(F)})')

# (2) decoder duplicate positions (revisits emitted as separate rows?)
kd = cKDTree(P)
pairs = kd.query_pairs(0.01)
duprows = sorted({b for a, b in pairs})
print(f'\n(2) v11 rows within 1cm of an earlier row (possible dup emissions): {len(duprows)}  {duprows[:20]}')

# (3) how many GT verts does v11 actually hit (3D<5cm), and are the MISSES
#     concentrated (a contiguous region decode never reached) or scattered?
d3, g3 = cKDTree(G).query(P)
hit = d3 < 0.05
gt_hit = set(g3[hit])
gt_miss = [i for i in range(len(G)) if i not in gt_hit]
print(f'\n(3) GT verts hit by v11 (3D<5cm): {len(gt_hit)}/{len(G)}   missed {len(gt_miss)}')
# also XY-exact hits (yellow class counts as "reached", Z wrong)
dxy, gxy = cKDTree(G[:, :2]).query(P[:, :2])
gt_reach = set(gxy[dxy < 0.002]) | gt_hit
print(f'    GT verts REACHED (3D or XY-exact): {len(gt_reach)}/{len(G)}   '
      f'truly-unreached {len(G)-len(gt_reach)}')

# (4) ref_events structure: can explicit ref indices anchor slot alignment?
groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))
print(f'\n(4) rails.pkl: {len(groups)} groups, {len(rails)} rails, {len(ref_events)} ref_events')
g0 = groups[0]
print(f'    group[0] keys: {list(g0.keys())}')
for gi in (0, 1, 2, 100):
    if gi < len(groups):
        g = groups[gi]
        print(f'    group[{gi}]: '
              + ', '.join(f'{k}={g[k]}' for k in g if k in ('kind','refs','idless','op','arg','row','strip','n')))
# ref index range: do refs index into 0..2963 (v11 space) or 0..2974 (true)?
allrefs = []
for g in groups:
    if 'refs' in g and g['refs']:
        allrefs += list(g['refs'])
if allrefs:
    ar = np.array(allrefs)
    print(f'    ref index range: [{ar.min()}..{ar.max()}]  n={len(ar)}  '
          f'(>2963: {(ar>2963).sum()}, >2974: {(ar>2974).sum()})')
