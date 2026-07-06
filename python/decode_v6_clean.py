#!/usr/bin/env python3
"""decode_v6_clean — HONEST, provably GT-FREE vertex decode.

No hardcoded coordinate ranges. Axis ranges are derived from the file's OWN data:
  - 3 seed coordinates read at offset 8326/8334/8342 (vertex 0, stored in the file)
  - the FULL records (self-contained 8-byte doubles) that fall within a 1.15x
    window of a seed; each axis range = [min,max] of its in-window FULLs.
The 1.15x window is fixed by a GT-free principle: the three seeds (656/55963/
162948) keep disjoint multiplicative windows only for factor < 1.706, so 1.15
guarantees clean axis separation with margin. NO ground truth anywhere except
the final score line, which is clearly labeled and never feeds the decoder.

Supersedes decode_v5p3.py, whose band()/sane() used hand-tightened literals
(50000-60000 / 160000-166000 / 500-1000) narrower than the file justifies.
"""
import struct, sys
import numpy as np

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(OOT, 'rb').read(); n = len(d)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90:
        face_start = occ[k]; break

def be(b): return struct.unpack('>d', bytes(b))[0]

RATIO = 1.15  # GT-free: < 1.706 guarantees disjoint axis windows
SEED = [abs(be(d[8326:8334])), abs(be(d[8334:8342])), abs(be(d[8342:8350]))]

def derive_ranges():
    buckets = {0: [], 1: [], 2: []}
    pos = 8350
    while pos + 8 <= face_start:
        if d[pos] in (0x40, 0x41, 0xC0, 0xC1):
            v = abs(be(d[pos:pos + 8]))
            if np.isfinite(v) and v > 0:
                ratios = [max(v, s) / min(v, s) for s in SEED]
                a = int(np.argmin(ratios))
                if ratios[a] < RATIO:
                    buckets[a].append(v)
        pos += 1
    rng = []
    for a in range(3):
        b = np.array(buckets[a])
        rng.append((b.min(), b.max()) if len(b) >= 3 else (SEED[a] / RATIO, SEED[a] * RATIO))
    return rng

RNG = derive_ranges()
(XL, XH), (YL, YH), (ZL, ZH) = RNG

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

def run():
    regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
    ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
    for t in toks:
        if t[0] in ('F', 'Fe'):
            v = be(t[1]); a = band(v)
            if a < 0: continue
            regs[a][:] = t[1]
            if a == 2 and ph == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            ph = (a + 1) % 3; continue
        payload = t[1]
        if len(payload) == 0: continue
        a = ph
        vb = r2_value(bytes(regs[a]), payload, t[2], a)
        if vb is not None: regs[a][:] = vb
        if a == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        ph = (ph + 1) % 3
    return np.array(pts)

P = run()
np.save('P_v6clean.npy', P)
np.savetxt('P_v6clean.csv', P, delimiter=',', fmt='%.6f')
print(f'GT-FREE ranges  X[{XL:.1f}..{XH:.1f}]  Y[{YL:.1f}..{YH:.1f}]  Z[{ZL:.1f}..{ZH:.1f}]')
print(f'decoded {len(P)} vertices  -> P_v6clean.npy / .csv')

if '--score' in sys.argv:
    from scipy.spatial import cKDTree
    gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
    dist, _ = cKDTree(Gu).query(P)
    print(f'[SCORING ONLY, GT never fed to decoder] anchor<1m {(dist<1).sum()}/{len(P)}  ({100*(dist<1).mean():.1f}%)')
