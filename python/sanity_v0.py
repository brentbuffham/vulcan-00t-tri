#!/usr/bin/env python3
"""Sanity: is vertex 0 (known-correct from full doubles) actually in the GT key
set? If not, the recall comparison is methodologically broken (rounding / vertex
0 is not a surface vertex). Also probe near-jitter."""
import sys, pickle, itertools
SP = sys.argv[1]
GT = pickle.load(open(f'{SP}/gt_keys.pkl', 'rb'))
v0 = (round(60657.694 * 100), round(214684.770 * 100), round(515.609 * 100))
print('vertex0 key', v0, 'in GT?', v0 in GT)
for dx, dy, dz in itertools.product(range(-3, 4), repeat=3):
    k = (v0[0] + dx, v0[1] + dy, v0[2] + dz)
    if k in GT:
        print('  hit near v0:', k, 'delta', (dx, dy, dz))
print('sample GT keys:', list(GT)[:5])
# What X/Y/Z ranges do GT keys span (in key units = value*100)?
xs = [k[0] for k in itertools.islice(GT, 200000)]
ys = [k[1] for k in itertools.islice(GT, 200000)]
zs = [k[2] for k in itertools.islice(GT, 200000)]
print('GT key X range', min(xs), max(xs))
print('GT key Y range', min(ys), max(ys))
print('GT key Z range', min(zs), max(zs))
