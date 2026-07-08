#!/usr/bin/env python3
"""zhunt4 -- ORACLE: can ANY surface-geometry reference supply Z's half-window?
Plane through nearest GT verts (excluding the vertex itself) evaluated at the
exact (x,y). If even this misses 0.0625m, geometry cannot carry k -> it must
be transmitted in the stream. Also: dh-vs-stream-byte correlation matrix on
the 104 onsets. Usage: python zhunt4.py <case>
"""
import struct, sys, collections
import numpy as np
case = sys.argv[1] if len(sys.argv) > 1 else 'intercepts'
exec(open(__file__.replace('zhunt4', 'zhunt1')).read().split("# ---- k computation ----")[0])
from scipy.spatial import cKDTree

okset = {vi for (vi, tz, dz) in ok}
tG = cKDTree(G[:, :2])
def gt_plane(x, y, tz, k=12):
    dd, ii = tG.query([x, y], k=k)
    # exclude the vertex itself (same xy)
    m = dd > 1e-3
    ii, dd = ii[m], dd[m]
    res = {}
    if len(ii) >= 1: res['gt_nn'] = G[ii[0], 2]
    if len(ii) >= 3:
        sel = ii[:3]
        A = np.c_[G[sel, 0], G[sel, 1], np.ones(3)]
        try:
            coef, *_ = np.linalg.lstsq(A, G[sel, 2], rcond=None)
            res['gt_plane3'] = coef[0] * x + coef[1] * y + coef[2]
        except Exception: pass
    # best over any 3-subset of nearest 8 (upper bound)
    best = None
    from itertools import combinations
    for sub in combinations(range(min(8, len(ii))), 3):
        sel = ii[list(sub)]
        A = np.c_[G[sel, 0], G[sel, 1], np.ones(3)]
        try:
            coef, *_ = np.linalg.lstsq(A, G[sel, 2], rcond=None)
            p = coef[0] * x + coef[1] * y + coef[2]
            e = abs(p - tz)
            if best is None or e < best: best = e
        except Exception: continue
    if best is not None: res['gt_best3of8_err'] = best
    return res

errs = collections.defaultdict(list)
for (vi, tz, dz) in yel:
    x, y = P[vi, 0], P[vi, 1]
    r = gt_plane(x, y, tz)
    if 'gt_nn' in r: errs['gt_nn'].append(abs(r['gt_nn'] - tz))
    if 'gt_plane3' in r: errs['gt_plane3'].append(abs(r['gt_plane3'] - tz))
    if 'gt_best3of8_err' in r: errs['gt_best3of8_err'].append(r['gt_best3of8_err'])
print('=== GT-surface ORACLE on yellow (err vs trueZ) ===')
for nm, ee in errs.items():
    ee = np.array(ee)
    print(f'  {nm:16s} median {np.median(ee):.4f}  <0.0625: {(ee<0.0625).sum()}/{len(ee)}  <0.125: {(ee<0.125).sum()}/{len(ee)}')

# === dh vs stream bytes at onsets ===
def be_(b): return struct.unpack('>d', bytes(b))[0]
def tf_min(R, payload, tv, k0only=3, span=300):
    nb = len(payload); hb = k0only
    if hb + nb > 8: return None
    tail = R[hb + nb:]
    hi = int.from_bytes(R[:hb], 'big')
    best = None
    for dh in range(-span, span + 1):
        h2 = hi + dh
        if not (0 <= h2 < (1 << (8 * hb))): continue
        vb = h2.to_bytes(hb, 'big') + bytes(payload) + bytes(tail)
        v = be_(vb)
        if np.isfinite(v) and abs(v - tv) < 1e-6:
            if best is None or abs(dh) < abs(best): best = dh
    return best

rows = []
for (vi, tz, dz) in yel:
    if (vi - 1) not in okset: continue
    m = allmeta[2].get(vi)
    if m is None or m['kind'] != 'V': continue
    dh = tf_min(m['Rbefore'], m['payload'], tz)
    if dh is None: continue
    mx = allmeta[0].get(vi); my = allmeta[1].get(vi)
    feat = dict(dh=dh, vi=vi, nb=m['nb'],
                T1=m['T'][0] if m['T'] else -1, T2=m['T'][1] if m['T'] else -1,
                b=m['b'], prev_nb=m['prev_nb'],
                xT1=mx['T'][0] if mx and mx.get('T') else -1,
                xT2=mx['T'][1] if mx and mx.get('T') else -1,
                yT1=my['T'][0] if my and my.get('T') else -1,
                yT2=my['T'][1] if my and my.get('T') else -1,
                xnb=mx['nb'] if mx else -1, ynb=my['nb'] if my else -1,
                p0=m['payload'][0], p1=m['payload'][1])
    rows.append(feat)
print(f'\n=== onset dh correlation set: {len(rows)} sites ===')
dha = np.array([r['dh'] for r in rows])
print(f'dh: median|.|={np.median(np.abs(dha))}  range {dha.min()}..{dha.max()}')
for f in ('T1', 'T2', 'b', 'prev_nb', 'xT1', 'xT2', 'yT1', 'yT2', 'xnb', 'ynb', 'p0', 'p1', 'nb'):
    fa = np.array([r[f] for r in rows], dtype=float)
    if fa.std() < 1e-9: print(f'  {f}: constant {fa[0]}'); continue
    c = np.corrcoef(fa, dha)[0, 1]
    ca = np.corrcoef(fa, np.abs(dha))[0, 1]
    print(f'  {f}: corr(dh)={c:+.2f}  corr(|dh|)={ca:+.2f}')
# T2 high 5 bits vs dh explicitly
t2h = np.array([r['T2'] >> 3 for r in rows])
print('  T2>>3 vs dh pairs (first 30):', list(zip(t2h[:30], dha[:30])))
