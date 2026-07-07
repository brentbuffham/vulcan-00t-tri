import numpy as np, sys
for case in ('SYLVANIA', 'OB34'):
    P = np.load(f'P_v9_{case}.npy')
    print(case, P.shape)
    for a, name in ((0, 'X'), (1, 'Y'), (2, 'Z')):
        seq = P[:, a]
        res = []
        for lag in range(1, 400):
            dd = np.abs(seq[lag:] - seq[:-lag])
            res.append((float(np.median(dd)), lag))
        srt = sorted(res)
        print(' ', name, 'top-8 minima:', [(round(m, 3), l) for m, l in srt[:8]])
        # also: any lag beating lag-1?
        m1 = res[0][0]
        beat = [l for m, l in res if m < m1 and l > 1]
        print(f'    lag-1 median {m1:.3f}; lags beating lag-1: {beat[:10]}')
