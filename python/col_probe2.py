"""Look at the serpentine directly: per-slot X and Y (P_v11, GT-free) along
emission order. Expect column-major: one axis ~constant per column (staircase),
other sweeps monotonically alternating direction. Print run structure.
Also compare with GT positions via map11 (answer key, for calibration ONLY).
"""
import pickle
import numpy as np
from collections import Counter

P = np.load('P_v11_intercepts.npy')
N = len(P)
X, Y, Z = P[:, 0], P[:, 1], P[:, 2]

# print a window of slot -> (X, Y) to see structure
for lo, hi in [(0, 60), (430, 500), (900, 950)]:
    print(f'--- slots {lo}..{hi} (P_v11 GT-free) ---')
    for s in range(lo, hi):
        print(f'  {s:4d}  X={X[s]:10.2f}  Y={Y[s]:9.2f}  Z={Z[s]:7.2f}')

# GT check of same windows
map11, gt2slot11 = pickle.load(open('map11.pkl', 'rb'))
G = np.loadtxt('intercepts_gt.csv', delimiter=',')
print()
print('--- GT (map11 answer key, calibration only) slots 430..500 ---')
for s in range(430, 500):
    g = map11.get(s)
    if g is None:
        print(f'  {s:4d}  unmapped')
    else:
        print(f'  {s:4d}  X={G[g,0]:10.2f}  Y={G[g,1]:9.2f}  Z={G[g,2]:7.2f}')
