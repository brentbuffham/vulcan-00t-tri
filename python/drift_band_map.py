#!/usr/bin/env python3
"""Map decoded-point outlier bands (v5-P2, rebuild_pipeline.py) to coord-section
byte positions and section markers. GT used for SCORING ONLY.
Outputs: drift_band_report.txt
"""
import struct
import numpy as np
from scipy.spatial import cKDTree

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
GTCSV = 'intercepts_gt.csv'

d = open(OOT, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
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

# --- tokenize, recording byte pos per token ---
toks = []; pos = 8350; lastT = None
e0_skips = []          # positions where the 3-byte e0-class skip fired
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    if full_at(pos) is not None:
        toks.append(('F', d[pos:pos + 8], lastT, None, pos)); lastT = None; pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        toks.append(('Fe', d[pos + 1:pos + 9], lastT, None, pos)); lastT = None; pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        toks.append(('V', d[pos + 1:end], lastT, b, pos)); lastT = None; pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start:
        e0_skips.append(pos); lastT = None; pos += 3; continue
    if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
    pos += 1

def k0_rule(T, nb):
    if T is not None:
        T1, T2 = T
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {4: 3, 5: 3, 6: 2}.get(nb, max(0, 8 - nb))
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

# --- run decode, recording byte pos + token idx + FULL flag per emitted point ---
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0
pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
meta = [(8326, -1, 'init')]           # (byte_pos, token_idx, kind) per point
fulls_seen = 0
for ti, t in enumerate(toks):
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        fulls_seen += 1
        regs[a][:] = t[1]
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            meta.append((t[4], ti, 'FULLz'))
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    vb = r2_value(bytes(regs[a]), payload, t[2], a)
    if vb is not None: regs[a][:] = vb
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        meta.append((t[4], ti, 'V' if vb is not None else 'Vfail'))
    ph = (ph + 1) % 3
P = np.array(pts)

# --- score vs GT (scoring only) ---
gt = np.loadtxt(GTCSV, delimiter=',')
Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu)
err, _ = kd.query(P)

# --- find outlier bands: runs of consecutive points with err > 10m ---
bad = err > 10.0
bands = []
i = 0
while i < len(P):
    if bad[i]:
        j = i
        while j + 1 < len(P) and bad[j + 1]: j += 1
        bands.append((i, j))
        i = j + 1
    else:
        i += 1

# markers inside coord region
coord_markers = [p for p in occ if 8350 <= p < face_start]

lines = []
lines.append(f'points {len(P)}  good(<1m) {(err<1).sum()}  bad(>10m) {bad.sum()}  bands {len(bands)}')
lines.append(f'coord e0-03 markers: {len(coord_markers)}  e0-class 3B skips: {len(e0_skips)}  FULLs consumed: {fulls_seen}')
lines.append('')
lines.append('band  ptIdx range   bytePos range        len   onset kind   nearest e0-skip before onset (gap)   FULLz inside')
big_bands = [b for b in bands if b[1] - b[0] + 1 >= 5]
for bi, (a, b2) in enumerate(big_bands):
    p0, t0, k0 = meta[a]
    p1, _, _ = meta[b2]
    # nearest e0 skip at or before onset byte pos
    prior = [e for e in e0_skips if e <= p0]
    gap = p0 - prior[-1] if prior else -1
    nf = sum(1 for i2 in range(a, b2 + 1) if meta[i2][2] == 'FULLz')
    lines.append(f'{bi:3d}  {a:5d}-{b2:5d}  {p0:8d}-{p1:8d}  {b2-a+1:4d}   {k0:6s}   gap={gap:6d}   fullz={nf}')
lines.append('')

# recovery analysis: what kind of point ENDS a band (first good point after)?
rec = {'FULLz': 0, 'V': 0, 'Vfail': 0}
for (a, b2) in bands:
    if b2 + 1 < len(meta): rec[meta[b2 + 1][2]] = rec.get(meta[b2 + 1][2], 0) + 1
lines.append(f'point kind starting recovery after a band: {rec}')

# onset analysis: kind of first bad point
onset = {}
for (a, b2) in bands:
    onset[meta[a][2]] = onset.get(meta[a][2], 0) + 1
lines.append(f'point kind at band onset: {onset}')

# do band onsets sit right after an e0 skip? histogram of gaps
gaps = []
for (a, b2) in bands:
    p0 = meta[a][0]
    prior = [e for e in e0_skips if e <= p0]
    if prior: gaps.append(p0 - prior[-1])
gaps = np.array(gaps)
if len(gaps):
    lines.append(f'onset gap to previous e0-skip: median {np.median(gaps):.0f}  p25 {np.percentile(gaps,25):.0f}  p75 {np.percentile(gaps,75):.0f}  min {gaps.min()}  <=16B: {(gaps<=16).sum()}/{len(gaps)}')
# control: gaps for GOOD points (random baseline)
gidx = np.where(~bad)[0]
np.random.seed(0)
ctrl = []
for i2 in np.random.choice(gidx, min(500, len(gidx)), replace=False):
    p0 = meta[i2][0]
    prior = [e for e in e0_skips if e <= p0]
    if prior: ctrl.append(p0 - prior[-1])
ctrl = np.array(ctrl)
if len(ctrl):
    lines.append(f'CONTROL (good pts)  gap: median {np.median(ctrl):.0f}  <=16B: {(ctrl<=16).sum()}/{len(ctrl)}')

# per-axis error at band onset: which register is wrong?
lines.append('')
lines.append('first 15 big bands: decoded (X,Y,Z) at onset vs nearest GT')
for (a, b2) in big_bands[:15]:
    p = P[a]; _, ii = kd.query(p)
    g = Gu[ii]
    lines.append(f'  pt{a:5d} dec=({p[0]:11.2f},{p[1]:10.2f},{p[2]:8.2f})  gtNN=({g[0]:11.2f},{g[1]:10.2f},{g[2]:8.2f})  dX={p[0]-g[0]:10.2f} dY={p[1]-g[1]:9.2f} dZ={p[2]-g[2]:8.2f}')

rep = '\n'.join(lines)
open('drift_band_report.txt', 'w').write(rep)
print(rep)
