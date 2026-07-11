"""Probe perpendicular coordinate w = P . u_perp along slots (GT-free).
If columns are parallel lines, w is ~constant per column with a jump at folds.
Print w around known folds (461/462, 485/486) and census of |dw| for
within-column vs across-fold consistent steps. Also diagnose missed folds:
distribution of my column lengths, and where teacher folds have no match.
"""
import pickle
import numpy as np
from collections import Counter

P = np.load('P_v11_intercepts.npy')
cv = pickle.load(open('columns_v1.pkl', 'rb'))
u = cv['u']; folds = cv['folds']; bounds = cv['bounds']
up = np.array([-u[1], u[0]])
t = P[:, :2] @ u
w = P[:, :2] @ up
V = P[1:, :2] - P[:-1, :2]
L = np.hypot(V[:, 0], V[:, 1])
sane = (L > 1.0) & (L < 8.0)

for lo, hi in [(435, 495)]:
    print('slot   t        w        sane_step')
    for s in range(lo, hi):
        print(' %4d %9.2f %9.2f %s' % (s, t[s], w[s], sane[s-1] if s > 0 else '-'))

dw = w[1:] - w[:-1]
print('|dw| percentiles on sane steps:', np.percentile(np.abs(dw[sane]), [25,50,75,90,95]).round(2))

clen = np.diff(bounds)
print('my column length census:', sorted(Counter(clen).items()))
