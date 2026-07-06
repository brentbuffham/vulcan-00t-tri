#!/usr/bin/env python3
"""decode_v5p3 — GT-FREE decode with candidate amended k0_rule.
GT (intercepts_gt.csv) used ONLY to SCORE the finished decode, never as input.

Candidate rule (from k0_event_extract cross-tab): for band-onset failures the
teacher-forced winner was k0=3 (42/43) where k0_rule chose k0=2 for T1 in
0x21..0x3F.  We test making that class return 3 instead of 2, and variants,
and report GT-free scores vs the v5-P2 baseline (anchor<1m 760/2937; XZ map 970).
"""
import struct, sys
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
GTCSV = 'intercepts_gt.csv'
d = open(OOT, 'rb').read()
occ = [i for i in range(8326, len(d) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = len(d)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break

def be(b): return struct.unpack('>d', bytes(b))[0]
def sane(v):
    a = abs(v); return (500 < a < 1000) or (50000 < a < 60000) or (160000 < a < 166000)
def band(v):
    x = abs(v)
    if 500 < x < 1000: return 2
    if 50000 < x < 60000: return 0
    if 160000 < x < 166000: return 1
    return -1
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if sane(v): return v
    return None

toks = []; pos = 8350; lastT = None
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    if full_at(pos) is not None:
        toks.append(('F', d[pos:pos + 8], lastT, None)); lastT = None; pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        toks.append(('Fe', d[pos + 1:pos + 9], lastT, None)); lastT = None; pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        toks.append(('V', d[pos + 1:end], lastT, b)); lastT = None; pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; pos += 3; continue
    if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
    pos += 1

def spl(R, payload, k0, c=0):
    nb = len(payload); end = k0 + nb
    if k0 < 0 or end > 8: return None
    bb = bytearray(R[:k0]) + bytearray(payload) + bytearray(R[end:])
    if c != 0:
        kk = k0 - 1
        if kk < 0: return None
        nv = bb[kk] + c
        if not (0 <= nv <= 255): return None
        bb[kk] = nv
    return bytes(bb)

def make_k0_rule(variant):
    def k0_rule(T, nb):
        if T is not None:
            T1, T2 = T
            if variant in ('v5',) and nb == 4:
                return 3  # uniform nb==4 -> k0=3 (across all T classes that reach here)
            if 0x21 <= T1 <= 0x3F:
                if variant == 'v1': return 3
                if variant in ('v2', 'v4') and nb == 4: return 3
                if variant == 'v3' and nb in (4, 5): return 3
                return 2
            if 0x40 <= T1 <= 0x5F: return 3
            if T1 == 0x20:
                if variant == 'v4' and nb == 4: return 3
                return 3 if T2 < 0x60 else 2
        return {4: 3, 5: 3, 6: 2}.get(nb, max(0, 8 - nb))
    return k0_rule

def make_r2(k0_rule):
    def r2_value(R, payload, T, a):
        nb = len(payload)
        if nb == 0 or nb > 8: return None
        k0r = k0_rule(T, nb)
        if k0r + nb > 8: k0r = 8 - nb
        vb = spl(R, payload, k0r)
        if vb is not None and band(be(vb)) == a: return vb
        for c in (-1, 1, -2, 2, -3, 3, -4, 4):
            vb = spl(R, payload, k0r, c)
            if vb is not None and band(be(vb)) == a: return vb
        pv = be(R); best = None
        for k0 in range(0, 8 - nb + 1):
            vb = spl(R, payload, k0)
            if vb is not None and band(be(vb)) == a:
                dv = abs(be(vb) - pv)
                if best is None or dv < best[0]: best = (dv, vb)
        return best[1] if best else None
    return r2_value

def run(variant):
    r2 = make_r2(make_k0_rule(variant))
    regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
    ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
    for t in toks:
        if t[0] in ('F', 'Fe'):
            v = be(t[1]); a = band(v)
            if a < 0: continue
            regs[a][:] = t[1]
            if a == 2 and ph == 2:
                pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            ph = (a + 1) % 3; continue
        payload = t[1]
        if len(payload) == 0: continue
        a = ph
        vb = r2(bytes(regs[a]), payload, t[2], a)
        if vb is not None: regs[a][:] = vb
        if a == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        ph = (ph + 1) % 3
    return np.array(pts)

gt = np.loadtxt(GTCSV, delimiter=','); Gu = np.unique(gt, axis=0); kd = cKDTree(Gu)
kd2 = cKDTree(gt[:, [0, 2]])
def score(P, tag):
    dist, _ = kd.query(P)
    anchor1 = (dist < 1.0).sum()
    anchor2mm = (dist < 0.002).sum()
    cand = kd2.query_ball_point(P[:, [0, 2]], 0.002)
    gtcount = Counter(); s2g = {}
    for s, cs in enumerate(cand):
        if len(cs) == 1: s2g[s] = cs[0]; gtcount[cs[0]] += 1
    s2g = {s: g for s, g in s2g.items() if gtcount[g] == 1}
    print(f'{tag:16s} pts {len(P)}  anchor<1m {anchor1:4d}  anchor<2mm {anchor2mm:4d}  XZmap {len(s2g):4d}')
    return anchor1, len(s2g)

print('GT-FREE decode scores (GT for scoring only):')
for v in ['base', 'v1', 'v2', 'v3', 'v4', 'v5']:
    P = run(v)
    score(P, v)

# ---- LOCKED final rule = v5 == "nb==4 -> k0=3 always" (subsumes v2 & v4) ----
print('\nLOCKED v5-P3 rule: for nb==4, k0=3 (else original v5-P2 k0_rule).')
Pf = run('v5')
np.save('P_v5p3.npy', Pf)
score(Pf, 'v5p3 FINAL')
print('saved P_v5p3.npy')
