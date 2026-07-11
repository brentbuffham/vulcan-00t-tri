"""Alignment test: do stream groups correspond 1:1 (in order) to GT faces?

For each candidate face-group subset and global offset: running face index j;
score = P(map11[ref] is a vertex of GT_face[j+off]) over mapped ref groups.
Baseline ~ 3*avg_valence/2975 ~ tiny. GT used for mechanism discovery (stated).
"""
import pickle
from collections import Counter
import numpy as np

map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
groups = pickle.load(open('refs_v2.pkl', 'rb'))
F = np.load('faces_gt.npy')
NF = len(F)
fsets = [set(f) for f in F]

def score(subset_pred, off):
    j = 0
    hit = tot = 0
    for g in groups:
        if not subset_pred(g):
            continue
        if g['refs'] and not g['is01']:
            for r in g['refs']:
                gt = map11.get(r)
                if gt is None:
                    continue
                k = j + off
                if 0 <= k < NF:
                    tot += 1
                    hit += gt in fsets[k]
        j += 1
    return hit, tot, j

subsets = {
    'e003 only': lambda g: g['delim'] == 'e003',
    'e003+e0ff+e1xx': lambda g: g['delim'] == 'e003' or g['delim'].startswith('e0f') or g['delim'].startswith('e1'),
    'all': lambda g: True,
    'all-not-is01': lambda g: not g['is01'],
    'e003 not-is01': lambda g: g['delim'] == 'e003' and not g['is01'],
}
for name, pred in subsets.items():
    best = (0, 0, 0)
    for off in range(-40, 41):
        h, t, j = score(pred, off)
        if t and h / t > (best[0] / best[1] if best[1] else 0):
            best = (h, t, off)
    h, t, off = best
    _, _, j = score(pred, 0)
    print('%-16s n_groups=%d  best off=%+d  hit %d/%d = %.1f%%' % (
        name, j, off, h, t, 100 * h / max(t, 1)))
