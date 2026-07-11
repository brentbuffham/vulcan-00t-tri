"""Scope the exact-cover gap: of 5738 groups (each ~= 1 GT face), how many
does the current strip machine emit a face for, and WHY are the rest missed?
Buckets (GT-free): is01 non-face / no rail (unassigned ref or cur=None) /
rail-has-no-S / short-rail / emitted. Grow-coverage targets fall out.
"""
import pickle
from collections import Counter, defaultdict
import numpy as np

groups = pickle.load(open('refs_v3.pkl', 'rb'))
rv = pickle.load(open('rails_v3.pkl', 'rb'))
rails, assign, refs = rv['rails'], rv['assign'], rv['refs']
sr = pickle.load(open('side_rule.pkl', 'rb'))
Sgt = {rid: v[1] for rid, v in sr.items()}
g2 = {}
for (gi, r, f, dl), rid in zip(refs, assign):
    g2[gi] = (rid, r)

# rail sizes
rsize = Counter(assign)

bucket = Counter()
cur = None
for gi, g in enumerate(groups):
    if g['is01']:
        bucket['is01_nonface'] += 1
        continue
    if g['refs']:
        if gi in g2:
            rid = g2[gi][0]
            cur = rid
            if rid not in Sgt:
                bucket['ref: rail has no S'] += 1
            elif rsize[rid] < 3:
                bucket['ref: short rail (<3)'] += 1
            else:
                bucket['ref: emittable'] += 1
        else:
            cur = None
            bucket['ref: unassigned (no rail)'] += 1
        continue
    # idless
    if g['delim'] != 'e003':
        bucket['idless: non-e003 delim'] += 1
        continue
    if cur is None:
        bucket['idless: no current rail'] += 1
    elif cur not in Sgt:
        bucket['idless: rail has no S'] += 1
    else:
        bucket['idless: emittable'] += 1

print('=== group emission coverage (5738 groups ~= 5724 GT faces) ===')
tot = sum(bucket.values())
for k, v in bucket.most_common():
    print('  %-28s %5d  (%.1f%%)' % (k, v, 100*v/tot))
emit = bucket['ref: emittable'] + bucket['idless: emittable']
print('  ----')
print('  EMITTABLE total:            %5d  (%.1f%% of groups)' % (emit, 100*emit/tot))

# how many rails have S, and how many refs/idless they'd cover if S extended
print('\nrails: total %d, with side_rule S %d' % (len(set(assign)), len(Sgt)))
print('rail size dist:', sorted(Counter(rsize.values()).items())[:12])
nosrails = [rid for rid in set(assign) if rid not in Sgt and rsize[rid] >= 3]
print('rails >=3 refs WITHOUT S (S-extension targets):', len(nosrails))
