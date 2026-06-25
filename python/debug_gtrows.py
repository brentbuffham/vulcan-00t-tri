#!/usr/bin/env python3
"""Show GT structure near the top corner: rows (by Y desc) with column counts
and (X->Z) pairs. Reveals the traversal so we can align the .00t stream."""
import sys, pickle
from collections import defaultdict
SP=sys.argv[1]
GT=pickle.load(open(f'{SP}/gt_keys.pkl','rb'))
rows=defaultdict(list)
for (xk,yk,zk) in GT: rows[yk].append((xk,zk))
ys=sorted(rows, reverse=True)
print(f'total rows (distinct Y): {len(ys)}')
print('row col-counts (top 20, Y desc):', [len(rows[y]) for y in ys[:20]])
print('row col-counts (bottom 10):', [len(rows[y]) for y in ys[-10:]])
import numpy as np
counts=np.array([len(rows[y]) for y in ys])
print(f'cols/row: min={counts.min()} max={counts.max()} mean={counts.mean():.1f} median={np.median(counts)}')
for y in ys[:8]:
    cells=sorted(rows[y])
    print(f'\nY={y/100:.3f} ({len(cells)} cols):')
    print('   X:', [f'{x/100:.3f}' for x,_ in cells][:25])
    print('   Z:', [f'{z/100:.3f}' for _,z in cells][:25])
