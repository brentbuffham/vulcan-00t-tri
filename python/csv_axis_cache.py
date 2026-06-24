#!/usr/bin/env python3
"""Stream the ground-truth CSV once; save sorted-unique X/Y/Z arrays so the
fitting harness can do tolerance membership tests without re-streaming."""
import sys, numpy as np

csv = sys.argv[1]
outdir = sys.argv[2]
xs, ys, zs = [], [], []
with open(csv, 'rb') as f:
    buf = b''
    while True:
        chunk = f.read(1 << 22)
        if not chunk:
            break
        buf = (buf + chunk).replace(b'\r', b'\n')
        parts = buf.split(b'\n')
        buf = parts.pop()
        for line in parts:
            if not line:
                continue
            try:
                a, b, c = line.split(b',')
                xs.append(float(a)); ys.append(float(b)); zs.append(float(c))
            except Exception:
                continue

for name, arr in (('x', xs), ('y', ys), ('z', zs)):
    a = np.unique(np.round(np.asarray(arr, dtype=np.float64), 3))
    np.save(f'{outdir}/gt_{name}.npy', a)
    print(f'{name}: {len(arr):,} values -> {len(a):,} unique  '
          f'range {a[0]:.3f}..{a[-1]:.3f}')
print('cache written to', outdir)
