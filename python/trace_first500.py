#!/usr/bin/env python3
"""PART B: bin vertices by 500; focus on the FIRST 500. Instrument every emitted
vertex (byte pos, the 3 tokens that built it, phase) and — using GT for SCORING
ONLY — mark correct(<1m)/wrong, find the FIRST drift onset, and classify each
error as VALUE (right axis, wrong number) vs PHASE (value belongs to another
axis). Dump the token trace around the first onsets so the mechanism is visible.
Decoder = decode_v6_clean (file-derived ranges, GT-free)."""
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
        toks.append(('F', d[pos:pos + 8], lastT, None, pos)); lastT = None; pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        toks.append(('Fe', d[pos + 1:pos + 9], lastT, None, pos)); lastT = None; pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        toks.append(('V', d[pos + 1:end], lastT, b, pos)); lastT = None; pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; pos += 3; continue
    if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
    pos += 1
def k0_rule(T, nb):
    if T is not None:
        T1, T2 = T
        if nb == 4: return 3
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {5: 3, 6: 2}.get(nb, max(0, 8 - nb))
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

# ---- decode with per-vertex provenance ----
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0
pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
prov = [dict(bytepos=8326, toks=('init', 'init', 'init'))]
cur = {0: ('init', 8326), 1: ('init', 8326), 2: ('init', 8326)}
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]; cur[a] = (t[0] + f'[{t[4]}]', t[4])
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            prov.append(dict(bytepos=t[4], toks=(cur[0][0], cur[1][0], cur[2][0])))
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    vb = r2_value(bytes(regs[a]), payload, t[2], a)
    if vb is not None: regs[a][:] = vb
    cur[a] = (f'V{len(payload)}b[{t[4]}]', t[4])
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        prov.append(dict(bytepos=t[4], toks=(cur[0][0], cur[1][0], cur[2][0])))
    ph = (ph + 1) % 3
P = np.array(pts)

# ---- score (GT for SCORING ONLY) ----
gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu); dist, idx = kd.query(P)
# per-axis: nearest GT along each single axis, to classify value vs phase error
kdX = cKDTree(Gu[:, [0]]); kdY = cKDTree(Gu[:, [1]]); kdZ = cKDTree(Gu[:, [2]])

N = min(500, len(P))
correct = dist[:N] < 1.0
print(f'=== FIRST {N} emitted vertices (bin 0) ===')
print(f'correct(<1m): {correct.sum()}/{N}   first WRONG at emit index: {int(np.argmax(~correct)) if (~correct).any() else "none"}')
# runs
runs = []; i = 0
while i < N:
    g = correct[i]; j = i
    while j + 1 < N and correct[j + 1] == g: j += 1
    runs.append((g, i, j)); i = j + 1
print('runs (G=correct,B=wrong): ' + ' '.join(f'{"G" if g else "B"}{a}-{b}' for g, a, b in runs[:40]))

# classify the first 12 wrong onsets
print('\n=== first wrong onsets: VALUE vs PHASE, with token trace ===')
shown = 0
for i in range(1, N):
    if not correct[i] and correct[i - 1]:
        p = P[i]; g = Gu[idx[i]]
        # is each decoded axis near SOME gt value on that axis? (value plausible)
        dX = float(kdX.query([[p[0]]])[0][0]); dY = float(kdY.query([[p[1]]])[0][0]); dZ = float(kdZ.query([[p[2]]])[0][0])
        pr = prov[i]
        print(f'emit#{i:3d} @byte{pr["bytepos"]}  dec=({p[0]:.2f},{p[1]:.2f},{p[2]:.2f})  d3={dist[i]:.1f}')
        print(f'         per-axis nearest-GT gap: X{dX:8.2f} Y{dY:8.2f} Z{dZ:8.2f}   built-by toks X:{pr["toks"][0]} Y:{pr["toks"][1]} Z:{pr["toks"][2]}')
        shown += 1
        if shown >= 12: break
