#!/usr/bin/env python3
"""Phase 11: delta census of consecutive decoded refs (GT-free structure)."""
import pickle
from collections import Counter
groups = pickle.load(open('refs_v2.pkl', 'rb'))
ref_seq = [r for g in groups for r in g['refs']]
c = Counter()
for i in range(1, len(ref_seq)):
    c[ref_seq[i]-ref_seq[i-1]] += 1
tot = sum(c.values())
small = sum(n for dd, n in c.items() if abs(dd) <= 6)
print(f'consecutive-ref |d|<=6: {small}/{tot} = {100*small/tot:.1f}%')
print('top deltas:', c.most_common(25))
for lag in (2, 3, 4):
    s = sum(1 for i in range(lag, len(ref_seq)) if abs(ref_seq[i]-ref_seq[i-lag]) <= 6)
    print(f'lag {lag} |d|<=6: {100*s/(len(ref_seq)-lag):.1f}%')
# per-form deltas: A->A only
aseq = []
for g in groups:
    for r, f in zip(g['refs'], g['forms']):
        aseq.append((r, f))
ca = Counter()
for i in range(1, len(aseq)):
    if aseq[i][1] == 'A' and aseq[i-1][1] == 'A':
        ca[aseq[i][0]-aseq[i-1][0]] += 1
print('A->A top deltas:', ca.most_common(15))
cs = Counter()
for i in range(1, len(aseq)):
    if aseq[i][1] == 'S':
        cs[aseq[i][0]-aseq[i-1][0]] += 1
print('*->S top deltas:', cs.most_common(15))
