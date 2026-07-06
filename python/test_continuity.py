#!/usr/bin/env python3
"""Test a GT-FREE hypothesis: single-axis drift = mis-splice landing an in-band
but far value. The TRUE value should sit near the recent trajectory on that axis
(surface is continuous). So among all valid splices of a token, prefer the one
closest to the running median of that axis's recent accepted values -- NOT just
the first in-band one. Measure how many first-500 vertices this recovers.
GT used for SCORING ONLY.
"""
import struct
import numpy as np
from scipy.spatial import cKDTree

d = open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t', 'rb').read(); n = len(d)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90:
        face_start = occ[k]; break
def be(b): return struct.unpack('>d', bytes(b))[0]
RATIO = 1.15
SEED = [abs(be(d[8326:8334])), abs(be(d[8334:8342])), abs(be(d[8342:8350]))]
def derive_ranges():
    bk = {0: [], 1: [], 2: []}
    pos = 8350
    while pos + 8 <= face_start:
        if d[pos] in (0x40, 0x41, 0xC0, 0xC1):
            v = abs(be(d[pos:pos + 8]))
            if np.isfinite(v) and v > 0:
                r = [max(v, s) / min(v, s) for s in SEED]
                a = int(np.argmin(r))
                if r[a] < RATIO: bk[a].append(v)
        pos += 1
    return [(np.array(bk[a]).min(), np.array(bk[a]).max()) for a in range(3)]
(XL, XH), (YL, YH), (ZL, ZH) = derive_ranges()
def band(v):
    x = abs(v)
    if ZL <= x <= ZH: return 2
    if XL <= x <= XH: return 0
    if YL <= x <= YH: return 1
    return -1
def sane(v): return band(v) >= 0
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

def r2_continuity(R, payload, a, recent):
    """Return the in-band splice whose value is CLOSEST to `recent` (running
    reference for this axis). No T, no k0 rule -- pure continuity. GT-free."""
    nb = len(payload)
    if nb == 0 or nb > 8: return None
    cands = []
    for k0 in range(0, 8 - nb + 1):
        for c in (0, -1, 1, -2, 2, -3, 3, -4, 4):
            vb = spl(R, payload, k0, c)
            if vb is not None and band(be(vb)) == a:
                cands.append(vb)
    if not cands: return None
    if recent is None:
        return cands[0]
    return min(cands, key=lambda vb: abs(be(vb) - recent))

def run(mode):
    regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
    ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
    hist = [[be(regs[0])], [be(regs[1])], [be(regs[2])]]  # accepted values per axis
    for t in toks:
        if t[0] in ('F', 'Fe'):
            v = be(t[1]); a = band(v)
            if a < 0: continue
            regs[a][:] = t[1]; hist[a].append(v)
            if a == 2 and ph == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            ph = (a + 1) % 3; continue
        payload = t[1]
        if len(payload) == 0: continue
        a = ph
        recent = np.median(hist[a][-8:]) if hist[a] else None
        vb = r2_continuity(bytes(regs[a]), payload, a, recent)
        if vb is not None: regs[a][:] = vb; hist[a].append(be(vb))
        if a == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        ph = (ph + 1) % 3
    return np.array(pts)

gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0); kd = cKDTree(Gu)
P = run('cont')
dist, _ = kd.query(P)
N = min(500, len(P))
print(f'CONTINUITY decode: total {len(P)} pts')
print(f'[SCORING] first {N}: correct<1m {(dist[:N]<1).sum()}/{N}   (v6-clean baseline was 76/500)')
print(f'[SCORING] all: anchor<1m {(dist<1).sum()}/{len(P)}   (v6-clean baseline 601)')
