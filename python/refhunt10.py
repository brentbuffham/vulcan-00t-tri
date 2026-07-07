#!/usr/bin/env python3
"""refhunt10 -- context census for the REVERSE placement flip:
nb=5, rule k0=3 (T1=0x20/T2<0x60 or 40-5F), truth k0=2 dh0.
What distinguishes those sites from rule-correct plc3 sites?
Census prev-record nb, T1, T2 at both. LABELING ONLY.
Usage: python refhunt10.py <case>
"""
import struct, sys
import numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
exec(open(__file__.replace('refhunt10', 'refhunt4')).read().split("# decode, recording")[0])

# decode recording prev_nb + T + payload + R per vertex-axis
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
info2 = [ {} ]; cur = {}; prev_nb = None
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        cur[a] = None
        regs[a][:] = t[1]
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2]))); info2.append(cur); cur = {}
        ph = (a + 1) % 3; prev_nb = 8; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    cur[a] = (bytes(payload), t[2], bytes(regs[a]), prev_nb)
    vb = r2_v9(bytes(regs[a]), payload, t[2], a, be(regs[a]))
    if vb is not None: regs[a][:] = vb
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2]))); info2.append(cur); cur = {}
    ph = (ph + 1) % 3; prev_nb = len(payload)
P = np.array(pts)
from scipy.spatial import cKDTree
dist, idx = cKDTree(G).query(P) if False else (None, None)
def dxfv(path):
    seen = set(); in3d = False; cur = {}
    with open(path, 'r', errors='ignore') as f:
        prev = None
        for line in f:
            s = line.strip()
            if prev is None: prev = s; continue
            code, val = prev, s; prev = None
            if code == '0':
                if in3d:
                    for kk in range(4):
                        if (kk, 0) in cur and (kk, 1) in cur and (kk, 2) in cur:
                            seen.add((round(cur[(kk, 0)], 3), round(cur[(kk, 1)], 3), round(cur[(kk, 2)], 3)))
                in3d = (val.upper() == '3DFACE'); cur = {}
            elif in3d:
                try: ci = int(code); fv = float(val)
                except Exception: continue
                if abs(fv) < 1e8:
                    for base, ax in ((10, 0), (20, 1), (30, 2)):
                        if base <= ci <= base + 3: cur[(ci - base, ax)] = fv
    return np.array(list(seen))
G = dxfv(DXF)
dist, idx = cKDTree(G).query(P)
broken = np.where(dist >= 1)[0]
TOL = 1e-3
pins = []
for i in broken:
    p = P[i]
    for wa in range(3):
        oa = [x for x in range(3) if x != wa]
        m = (np.abs(G[:, oa[0]] - p[oa[0]]) < TOL) & (np.abs(G[:, oa[1]] - p[oa[1]]) < TOL)
        cand = np.where(m)[0]
        if len(cand) == 1 and abs(G[cand[0], wa] - p[wa]) >= 0.5:
            pins.append((i, wa, G[cand[0], wa])); break

from collections import Counter
# find nb=5 rule3 truth-plc2 sites among pinned onsets
flip = Counter(); ctrl = Counter()
for (i, wa, tv) in pins:
    rec = info2[i].get(wa)
    if rec is None: continue
    pay, T, R, pnb = rec
    nb = len(pay)
    if nb != 5: continue
    k0r = k0_rule(T, nb)
    if k0r != 3: continue
    # is truth plc2/dh0-4?
    hit2 = False
    for dh in range(-4, 5):
        hi = int.from_bytes(R[:2], 'big') + dh
        if not (0 <= hi < 65536): continue
        vb = hi.to_bytes(2, 'big') + pay + R[7:]
        if np.isfinite(be(vb)) and abs(be(vb) - tv) < 1.0: hit2 = True
    if hit2:
        T1 = T[0] if T else None; T2 = T[1] if T else None
        flip[(pnb, hex(T1) if T1 is not None else None, hex(T2 & 0xF0) if T2 is not None else None)] += 1
# control: clean nb=5 rule3 sites
clean = np.where(dist < TOL)[0]
import random
random.seed(4)
for i in random.sample(list(clean), min(3000, len(clean))):
    for a in range(3):
        rec = info2[i].get(a)
        if rec is None: continue
        pay, T, R, pnb = rec
        if len(pay) != 5: continue
        if k0_rule(T, 5) != 3: continue
        T1 = T[0] if T else None; T2 = T[1] if T else None
        ctrl[(pnb, hex(T1) if T1 is not None else None, hex(T2 & 0xF0) if T2 is not None else None)] += 1
print('FLIP sites (nb=5, rule plc3, truth plc2) by (prev_nb, T1, T2hi):')
for k, c in flip.most_common(15): print('  ', k, c)
print('CLEAN control (nb=5, rule plc3, correct) by (prev_nb, T1, T2hi):')
for k, c in ctrl.most_common(15): print('  ', k, c)
