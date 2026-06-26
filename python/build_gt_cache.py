#!/usr/bin/env python3
"""Build GT cache from HEAVE_CSV: sorted-unique per-axis arrays + key set.
Cache is for SCORING ONLY (recall), never fed to the decoder."""
import sys, os, pickle, numpy as np
csv=r'C:/Users/brent/OneDrive/Test Files/POINTCLOUDS/HEAVE_CSV.csv'
cachedir=sys.argv[1]
os.makedirs(cachedir, exist_ok=True)
print('loading CSV...')
a=np.loadtxt(csv, delimiter=',', dtype=np.float64)
print('rows', a.shape)
x,y,z=a[:,0],a[:,1],a[:,2]
np.save(f'{cachedir}/gt_x.npy', np.unique(x))
np.save(f'{cachedir}/gt_y.npy', np.unique(y))
np.save(f'{cachedir}/gt_z.npy', np.unique(z))
keys=set(zip(np.round(x*100).astype(np.int64).tolist(),
             np.round(y*100).astype(np.int64).tolist(),
             np.round(z*100).astype(np.int64).tolist()))
pickle.dump(keys, open(f'{cachedir}/gt_keys.pkl','wb'))
print(f'unique X={len(np.unique(x)):,} Y={len(np.unique(y)):,} Z={len(np.unique(z)):,}  keys(unique verts)={len(keys):,}')
print(f'X range {x.min():.3f}..{x.max():.3f}  Y {y.min():.3f}..{y.max():.3f}  Z {z.min():.3f}..{z.max():.3f}')
