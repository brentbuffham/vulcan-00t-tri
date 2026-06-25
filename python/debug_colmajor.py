#!/usr/bin/env python3
"""Test COLUMN-MAJOR hypothesis. Group GT by X-column; show Y/Z structure per
column. Then take a constant-X run from the decoded stream and compare its Z
sequence to the GT column's (Y sorted -> Z)."""
import sys, struct, pickle
import numpy as np
from collections import defaultdict
SP=sys.argv[1]
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
GT=pickle.load(open(f'{SP}/gt_keys.pkl','rb'))
cols=defaultdict(list)
for (xk,yk,zk) in GT: cols[xk].append((yk,zk))
xs=sorted(cols)
cnts=np.array([len(cols[x]) for x in xs])
print(f'distinct X columns: {len(xs)}  (GT rows=2907, verts=1.21M)')
print(f'pts/column: min={cnts.min()} max={cnts.max()} mean={cnts.mean():.1f} median={np.median(cnts):.0f}')
# show a few columns near X=60660.70 (the constant-X run we saw)
for xt in (6065770, 6066070, 6066095):
    # nearest column key
    near=min(xs,key=lambda x:abs(x-xt))
    cells=sorted(cols[near])
    print(f'\ncolumn X={near/100:.3f} ({len(cells)} pts):')
    print('   Y(sorted):', [f'{y/100:.2f}' for y,_ in cells][:20])
    print('   Z(by Y)  :', [f'{z/100:.3f}' for _,z in cells][:20])
    # Y spacing within column
    yy=np.array(sorted(y for y,_ in cells))
    if len(yy)>1:
        dy=np.diff(yy)
        from collections import Counter
        print('   Y-steps:', Counter(np.round(dy/100,2).tolist()).most_common(6))
