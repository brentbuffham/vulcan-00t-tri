"""Step-vector statistics on P_v11 (GT-free) to design the fold detector.
- distribution of |step| (XY)
- distribution of step direction (angle)
- fraction of steps consistent with +/- the modal direction
Also: GT-side fold answer key (teacher-forced) from map11+GT positions:
detect direction reversals on GT-mapped consecutive slots.
"""
import pickle
import numpy as np
from collections import Counter

P = np.load('P_v11_intercepts.npy')
N = len(P)
V = P[1:, :2] - P[:-1, :2]
L = np.hypot(V[:, 0], V[:, 1])
print('|step| percentiles:', np.percentile(L, [5, 25, 50, 75, 90, 95, 99]).round(2))
inl = (L > 1.0) & (L < 8.0)
print('inlier steps (1<|v|<8):', inl.sum(), '/', len(L))
ang = np.arctan2(V[:, 1], V[:, 0])
# modal direction from inliers, folded to half-circle
a2 = np.mod(ang[inl], np.pi)
hist, edges = np.histogram(a2, bins=90)
k = hist.argmax()
theta = (edges[k] + edges[k+1]) / 2
print('modal axis angle (deg):', np.degrees(theta).round(1),
      'expected atan2(3.28,2.29)=', np.degrees(np.arctan2(3.28, 2.29)).round(1))
u = np.array([np.cos(theta), np.sin(theta)])
proj = V @ u
sgn = np.sign(proj)
good = inl & (np.abs(proj) > 2.0)
print('steps with |proj|>2 among inliers:', good.sum(), '/', inl.sum())
# angle alignment: |cos| of angle between step and u
ca = np.abs(proj) / np.maximum(L, 1e-9)
print('|cos(angle to u)| percentiles (inliers):',
      np.percentile(ca[inl], [5, 25, 50, 75, 95]).round(3))

# GT fold key (teacher-forced): consecutive mapped slots direction reversal
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
t_gt = {}
for s, g in map11.items():
    t_gt[s] = G[g, :2] @ u
ss = sorted(t_gt)
# fold at slot s if t peaks (local extremum) among mapped neighbors
folds_gt = []
for i in range(1, len(ss) - 1):
    s0, s1, s2 = ss[i-1], ss[i], ss[i+1]
    if s2 - s0 > 6:  # too holey to judge
        continue
    d1, d2 = t_gt[s1] - t_gt[s0], t_gt[s2] - t_gt[s1]
    if d1 * d2 < 0 and abs(d1) > 1 and abs(d2) > 1:
        folds_gt.append(s1)
print('GT-implied fold slots (teacher key):', len(folds_gt))
print(folds_gt[:80])
dd = np.diff(folds_gt)
print('fold spacing census:', sorted(Counter(dd).items())[:25])
