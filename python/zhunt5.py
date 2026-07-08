#!/usr/bin/env python3
"""zhunt5 -- diagnose v11 residual yellow: run one more pass with logging.
For each pinned-yellow Z record: is zref good (<1.5 windows of trueZ)?
If good, why did the candidate fail (placement? band? tail?).
Usage: python zhunt5.py <case> <ZTH>
"""
import struct, sys, collections
import numpy as np
case = sys.argv[1] if len(sys.argv) > 1 else 'intercepts'
sys.argv = ['x', case, sys.argv[2] if len(sys.argv) > 2 else '0.5']
exec(open('decode_v11_z.py').read())   # runs full multi-pass decode; leaves P, toks, band, etc.

# rebuild static surface from final P
sg = Grid(); sg.set_cell(cell if cell else 8.0)
for vi in range(len(P)):
    sg.add(P[vi, 0], P[vi, 1], P[vi, 2], vi, int(ANCH[vi]))

# pin via exact XY
TOL = 1e-3
from scipy.spatial import cKDTree
txy = cKDTree(G[:, :2])
nn = txy.query_ball_point(P[:, :2], r=TOL)
pins = {}
for vi in range(len(P)):
    if not nn[vi]: continue
    zs = np.unique(np.round(G[nn[vi], 2], 6))
    if len(zs) != 1: continue
    pins[vi] = float(zs[0])
yel = {vi: tz for vi, tz in pins.items() if abs(tz - P[vi, 2]) >= 0.25}
okp = {vi: tz for vi, tz in pins.items() if abs(tz - P[vi, 2]) < TOL}
print(f'\n[diag] pinned {len(pins)} yellow {len(yel)} clean {len(okp)}')

# replay decode (one more pass) with logging
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
hist = [[be(regs[0])], [be(regs[1])], [be(regs[2])]]
ph = 0; pts2 = [(be(regs[0]), be(regs[1]), be(regs[2]))]
prev_nb = None
cens = collections.Counter(); refErrY = []; refErrO = []
exY = []
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]; hist[a].append(be(regs[a]))
        if a == 2 and ph == 2: pts2.append((be(regs[0]), be(regs[1]), be(regs[2])))
        ph = (a + 1) % 3; prev_nb = 8; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    zref = None
    if a == 2:
        vi_next = len(pts2)
        zref = plane_ref(sg, be(regs[0]), be(regs[1]), exclude=vi_next)
        if zref is not None and band(zref) != 2: zref = None
    vb = r2_v11(bytes(regs[a]), payload, t[2], a, be(regs[a]), prev_nb, zref)
    if a == 2:
        vi_next = len(pts2)
        if vi_next in yel or vi_next in okp:
            tz = yel.get(vi_next, okp.get(vi_next))
            lab = 'Y' if vi_next in yel else 'O'
            nb = len(payload); T = t[2]
            k0r = k0_rule(T, nb)
            if k0r + nb > 8: k0r = 8 - nb
            if nb == 5 and k0r == 2 and prev_nb == 6: k0r = 3
            if zref is None:
                cens[(lab, 'noref')] += 1
            else:
                re_ = abs(zref - tz)
                (refErrY if lab == 'Y' else refErrO).append(re_)
                good = re_ < 0.1875
                # would ref_cands at rule placement hit trueZ?
                c1 = ref_cands(bytes(regs[a]), payload, k0r, a, zref)
                hit1 = c1 is not None and abs(be(c1[1]) - tz) < 0.25
                k0l = 8 - nb
                c2 = ref_cands(bytes(regs[a]), payload, k0l, a, zref) if k0l != k0r else None
                hit2 = c2 is not None and abs(be(c2[1]) - tz) < 0.25
                cens[(lab, 'refgood' if good else 'refbad',
                      f'k0r{k0r}hit' if hit1 else (f'k0l{k0l}hit' if hit2 else 'nohit'),
                      f'c1inband' if c1 is not None else 'c1out')] += 1
                if lab == 'Y' and good and not hit1 and len(exY) < 15:
                    exY.append((vi_next, nb, T, k0r, tz, zref,
                                be(c1[1]) if c1 is not None else None,
                                be(c2[1]) if c2 is not None else None))
    if vb is not None: regs[a][:] = vb
    hist[a].append(be(regs[a]))
    if a == 2: pts2.append((be(regs[0]), be(regs[1]), be(regs[2])))
    ph = (ph + 1) % 3; prev_nb = len(payload)
print('\n[diag] census (Y=yellow O=clean):')
for k_, c in sorted(cens.items(), key=lambda x: -x[1])[:25]: print(f'  {k_}: {c}')
ry, ro = np.array(refErrY), np.array(refErrO)
if len(ry): print(f'refErr yellow: med {np.median(ry):.3f} <0.0625 {(ry<0.0625).sum()}/{len(ry)}  <0.1875 {(ry<0.1875).sum()}/{len(ry)}')
if len(ro): print(f'refErr clean : med {np.median(ro):.3f} <0.0625 {(ro<0.0625).sum()}/{len(ro)}  <0.1875 {(ro<0.1875).sum()}/{len(ro)}')
print('\nexamples yellow refgood but rule-placement no hit:')
for e in exY: print('  ', e)
