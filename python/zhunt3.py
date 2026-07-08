#!/usr/bin/env python3
"""zhunt3 -- test SURFACE-PREDICTION references for Z: at Z-decode time the
vertex's X,Y are already decoded; predict Z from earlier DECODED vertices near
(X,Y) (planar fit / IDW / nearest). Success = |pred - trueZ| < half-window.
GT only to label trueZ (pinned via exact X/Y). Usage: python zhunt3.py <case>
"""
import struct, sys, collections
import numpy as np
case = sys.argv[1] if len(sys.argv) > 1 else 'intercepts'
exec(open(__file__.replace('zhunt3', 'zhunt1')).read().split("# ---- k computation ----")[0])
# have: allmeta, P, hist, ok, yel, mid, G, be, band
from scipy.spatial import cKDTree

okset = {vi for (vi, tz, dz) in ok}
def halfwin2(dz):
    b = bytearray(struct.pack('>d', dz))
    h = int.from_bytes(b[:3], 'big')
    b2 = bytearray(b); b2[:3] = (h + 1).to_bytes(3, 'big')
    return abs(struct.unpack('>d', bytes(b2))[0] - dz) / 2

txyP = cKDTree(P[:, :2])
def predictors(vi):
    """earlier decoded vertices near (x,y) of vertex vi"""
    x, y = P[vi, 0], P[vi, 1]
    dd, ii = txyP.query([x, y], k=40)
    m = (ii < vi) & (ii != vi)
    ii, dd = ii[m], dd[m]
    out = {}
    if len(ii) == 0: return out
    out['nnXY'] = P[ii[0], 2]
    if len(ii) >= 3:
        # plane through 3 nearest earlier
        sel = ii[:3]
        A = np.c_[P[sel, 0], P[sel, 1], np.ones(3)]
        try:
            coef, *_ = np.linalg.lstsq(A, P[sel, 2], rcond=None)
            out['plane3'] = coef[0] * x + coef[1] * y + coef[2]
        except Exception: pass
    if len(ii) >= 6:
        sel = ii[:6]
        A = np.c_[P[sel, 0], P[sel, 1], np.ones(len(sel))]
        w = 1.0 / (dd[:6] + 0.5)
        try:
            coef, *_ = np.linalg.lstsq(A * w[:, None], P[sel, 2] * w, rcond=None)
            out['plane6w'] = coef[0] * x + coef[1] * y + coef[2]
        except Exception: pass
        out['idw6'] = float(np.sum(P[sel, 2] / (dd[:6] + 1e-3)) / np.sum(1 / (dd[:6] + 1e-3)))
    return out

names = ['nnXY', 'plane3', 'plane6w', 'idw6', 'last']
succ = collections.Counter(); tot = collections.Counter(); errs = collections.defaultdict(list)
for lab, group in (('yel', yel), ('ok', ok)):
    for (vi, tz, dz) in group:
        m = allmeta[2].get(vi)
        if m is None or m['kind'] != 'V': continue
        hw = halfwin2(dz)
        pr = predictors(vi)
        pr['last'] = struct.unpack('>d', m['Rbefore'])[0]
        for nm in names:
            if nm not in pr: continue
            tot[(nm, lab)] += 1
            e = abs(pr[nm] - tz)
            errs[(nm, lab)].append(e)
            if e < hw: succ[(nm, lab)] += 1
print('=== surface-prediction reference success (|pred-trueZ| < half-window ~0.0625) ===')
for nm in names:
    for lab in ('yel', 'ok'):
        s, t = succ[(nm, lab)], tot[(nm, lab)]
        ee = np.array(errs[(nm, lab)]) if errs[(nm, lab)] else np.array([np.nan])
        print(f'  {nm:8s} {lab:3s}: {s}/{t} ({100*s/max(t,1):.0f}%)  err median {np.median(ee):.3f} p90 {np.percentile(ee,90):.3f}')
# also: how often within 1 window, 2 windows (nearest-congruent would then need small dh search)
print('\nwithin N windows (0.125m) of trueZ (yellow):')
for nm in names:
    ee = np.array(errs[(nm, 'yel')])
    for N in (0.5, 1.5, 2.5, 4.5):
        print(f'  {nm:8s} <{N}w: {(ee < N*0.125).sum()}/{len(ee)}', end='')
    print()
