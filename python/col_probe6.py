"""Debug the reversal splitter on known missed folds (973, 1546, 2277)."""
import pickle
import numpy as np

P = np.load('P_v11_intercepts.npy')
XY = P[:, :2].astype(float)
cv = pickle.load(open('columns_v1.pkl', 'rb'))
bounds = cv['bounds']
N = len(cv['colof'])

def robust_line(a, b):
    A = XY[a:b]
    M = A - A.mean(0)
    C = M.T @ M
    wv, Vv = np.linalg.eigh(C)
    d = Vv[:, -1]
    perp = np.abs(M @ np.array([-d[1], d[0]]))
    kkeep = max(2, int(np.ceil(len(A) * 0.75)))
    idx = np.argsort(perp)[:kkeep]
    c0 = A[idx].mean(0)
    M2 = A[idx] - c0
    C2 = M2.T @ M2
    wv2, Vv2 = np.linalg.eigh(C2)
    return c0, Vv2[:, -1]

for kf in (973, 1546, 2277, 235):
    ks = [k for k in range(len(bounds) - 1) if bounds[k] <= kf < bounds[k + 1]]
    k = ks[0]
    a, b = bounds[k], bounds[k + 1]
    print(f'--- fold {kf}: column {k} = [{a},{b})')
    c0, d = robust_line(a, b)
    npv = np.array([-d[1], d[0]])
    for s in range(a, b):
        perp = (XY[s] - c0) @ npv
        q = (XY[s] - c0) @ d
        print('  %4d q=%8.2f perp=%8.2f %s' % (s, q, perp, '*' if abs(perp) < 1.5 else ''))
