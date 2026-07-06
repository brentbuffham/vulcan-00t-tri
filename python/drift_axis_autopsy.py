#!/usr/bin/env python3
"""Autopsy of bad points: is error single-axis? which axis? magnitude spectrum.
Uses P_base.npy (v5-P2 decode) + GT for scoring only."""
import numpy as np
from scipy.spatial import cKDTree

P = np.load('P_base.npy')
gt = np.loadtxt('intercepts_gt.csv', delimiter=',')
Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu)
err, ii = kd.query(P)
G = Gu[ii]
D = P - G
bad = err > 10.0
print(f'pts {len(P)} bad {bad.sum()}')

ax = np.abs(D[bad])
dom = ax.argmax(axis=1)
frac = ax.max(axis=1) / (ax.sum(axis=1) + 1e-12)
single = frac > 0.9
print(f'single-axis-dominant (>90% of L1 err on one axis): {single.sum()}/{bad.sum()} ({100*single.mean():.0f}%)')
for a, name in enumerate('XYZ'):
    m = dom == a
    print(f'  dominant {name}: {m.sum():5d}  ({100*m.mean():.0f}%)   median|err| {np.median(ax[m, a]):9.2f}  p90 {np.percentile(ax[m, a], 90):10.2f}')

# magnitude spectrum: log2 of dominant-axis error — mis-splice at byte k shifts by ~2^(8k)*mantissa-scale
mag = ax[np.arange(len(ax)), dom]
h, edges = np.histogram(np.log2(mag), bins=np.arange(0, 24, 1))
print('\nlog2(|dominant err|) histogram (bin lower edge : count):')
for e, c in zip(edges[:-1], h):
    if c: print(f'  2^{int(e):2d} ({2.0**e:10.0f}m): {"#" * min(c // 8 + 1, 60)} {c}')

# Do errors persist as a CONSTANT offset within a band (register stuck) or wander?
# take runs of bad, check std of dominant-axis delta within run
i = 0; const_runs = 0; wander_runs = 0
badf = bad.astype(int)
while i < len(P):
    if bad[i]:
        j = i
        while j + 1 < len(P) and bad[j + 1]: j += 1
        if j - i + 1 >= 5:
            seg = D[i:j + 1]
            a = np.abs(seg).mean(axis=0).argmax()
            sd = seg[:, a].std(); md = np.abs(seg[:, a]).mean()
            if sd < 0.2 * md: const_runs += 1
            else: wander_runs += 1
        i = j + 1
    else: i += 1
print(f'\nbands>=5: constant-offset {const_runs}  wandering {wander_runs}')
