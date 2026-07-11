"""Inspect GT-free coord-decode column artifacts: full_flags.npy, k0_sites.pkl.
Want: per-slot column-boundary flags to replace the holey map11 columns.
"""
import pickle
import numpy as np

ff = np.load('full_flags.npy', allow_pickle=True)
print('full_flags:', type(ff), getattr(ff, 'shape', None), getattr(ff, 'dtype', None))
try:
    print('  head:', ff[:20])
    print('  unique (first col if 2d):', np.unique(ff.reshape(len(ff), -1)[:, 0])[:20] if ff.ndim >= 1 else ff)
except Exception as e:
    print('  err', e)

print()
k0 = pickle.load(open('k0_sites.pkl', 'rb'))
print('k0_sites:', type(k0))
if isinstance(k0, dict):
    for k, v in list(k0.items())[:10]:
        print('  ', k, '->', str(v)[:80])
elif isinstance(k0, (list, tuple)):
    print('  len', len(k0), 'head', k0[:15])
elif isinstance(k0, np.ndarray):
    print('  shape', k0.shape, 'head', k0[:15])
