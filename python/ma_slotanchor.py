#!/usr/bin/env python3
"""Can the EXPLICIT REF INDICES anchor slot alignment? The refs index the true
2975-slot space (proven: 6 refs in (2963,2970]). Test a STRONG objective the
same-group heuristic lacked: over ALL consecutive ref events in stream order,
does ref-slot -> GT vertex land on a mesh NEIGHBOR of the previous ref's GT
vertex? Sweep a global +k slot shift and the 20 drop candidates. GT = labeling
only. If signal stays near noise, coverage (1931/2975) is the ceiling, not the
realignment -- and that is the honest deliverable.
"""
import pickle
import numpy as np
from collections import defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))   # v11-row -> GT
F = np.load('faces_gt.npy')
nbr = defaultdict(set)
for a, b, c in F:
    for u, v in ((a, b), (b, c), (c, a)): nbr[u].add(v); nbr[v].add(u)
groups, rails, ref_events = pickle.load(open('rails.pkl', 'rb'))

# flat list of ref indices in stream (group) order
ref_seq = []
for g in groups:
    for r in g.get('refs', []):
        ref_seq.append(int(r))
print(f'ref_seq len {len(ref_seq)}  range [{min(ref_seq)}..{max(ref_seq)}]')

def rate(shiftfn):
    """consecutive refs whose shifted slots map to GT verts that are mesh nbrs"""
    hit = tot = 0
    prev = None
    for r in ref_seq:
        s = shiftfn(r)
        g = map11.get(s)
        if g is None:
            prev = None; continue
        if prev is not None and g != prev:
            tot += 1
            if g in nbr[prev]: hit += 1
        prev = g
    return hit, tot

# baseline: identity (refs already in v11-row space)
h, t = rate(lambda r: r)
print(f'identity (ref=v11 row):        {h}/{t} = {100*h/max(t,1):.1f}% mesh-nbr')
# global +k shift (if refs are in true space and v11 rows are compressed, a
# constant offset only works if all drops are before the ref region; sweep)
for k in range(-3, 4):
    h, t = rate(lambda r, k=k: r - k)
    print(f'  global shift {k:+d}:                {h}/{t} = {100*h/max(t,1):.1f}%')

# monotone drop model: true_slot = v11_row + (#drops <= row). Invert for refs
# (ref is true slot -> v11 row = ref - #drops < ref). Try the greedy drop set.
best = pickle.load(open('drops11.pkl', 'rb'))[0]
def unshift(r, drops):
    return r - sum(1 for d in drops if d < r)
h, t = rate(lambda r: unshift(r, best))
print(f'greedy-{len(best)}-drops unshift:        {h}/{t} = {100*h/max(t,1):.1f}%')

# ceiling: what fraction of refs even land on a MAPPED slot?
mapped = sum(1 for r in ref_seq if r in map11)
print(f'\nCEILING: refs landing on a mapped slot: {mapped}/{len(ref_seq)} '
      f'= {100*mapped/len(ref_seq):.1f}%  (coverage bound on any objective)')
