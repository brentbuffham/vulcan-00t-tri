#!/usr/bin/env python3
"""Trace every write to the Y register (axis 1) around the two corruption
episodes (vtx ~440 and ~2743) to find the ROOT mis-decode that flipped
byte1 from 0x03 to 0x05. GT used only to report the true vertex (pin)."""
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
RNG = derive_ranges()
(XL, XH), (YL, YH), (ZL, ZH) = RNG
print(f'ranges X[{XL:.1f}..{XH:.1f}] Y[{YL:.1f}..{YH:.1f}] Z[{ZL:.1f}..{ZH:.1f}]')
def band(v):
    x = abs(v)
    if ZL <= x <= ZH: return 2
    if XL <= x <= XH: return 0
    if YL <= x <= YH: return 1
    return -1
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if band(v) >= 0: return v
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
    if nb == 0 or nb > 8: return None, None
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    vb = spl(R, payload, k0r)
    if vb is not None and band(be(vb)) == a: return vb, ('rule', k0r, 0)
    for c in (-1, 1, -2, 2, -3, 3, -4, 4):
        vb = spl(R, payload, k0r, c)
        if vb is not None and band(be(vb)) == a: return vb, ('rule+c', k0r, c)
    pv = be(R); best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - pv)
            if best is None or dv < best[0]: best = (dv, vb, k0)
    if best: return best[1], ('search', best[2], 0)
    return None, None

gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu)

WINDOWS = [(425, 445), (2725, 2748)]
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0; vtx = 1
log = []
for t in toks:
    ttype, body, T, b, fpos = t
    if ttype in ('F', 'Fe'):
        v = be(body); a = band(v)
        if a < 0: continue
        if a == 1:
            log.append((vtx, ttype, None, None, bytes(regs[1]), bytes(body), None, fpos))
        regs[a][:] = body
        if a == 2 and ph == 2: vtx += 1
        ph = (a + 1) % 3; continue
    payload = body
    if len(payload) == 0: continue
    a = ph
    if a == 1:
        Rb = bytes(regs[1])
        vb, how = r2_value(Rb, payload, T, a)
        log.append((vtx, 'V', T, b, Rb, vb, how, fpos))
        if vb is not None: regs[a][:] = vb
    else:
        vb, how = r2_value(bytes(regs[a]), payload, T, a)
        if vb is not None: regs[a][:] = vb
    if a == 2: vtx += 1
    ph = (ph + 1) % 3

for lo, hi in WINDOWS:
    print(f'\n===== Y-register writes, vtx {lo}..{hi} =====')
    for (v, tt, T, b, Rb, emitted, how, fpos) in log:
        if not (lo <= v <= hi): continue
        Ts = f'{T[0]:02x},{T[1]:02x}' if T else '--,--'
        em = emitted.hex() if emitted else 'REJECT'
        flip = ''
        if emitted and Rb[1] != emitted[1]:
            flip = f'  <<< byte1 {Rb[1]:02x}->{emitted[1]:02x}'
        val = f'{be(emitted):12.3f}' if emitted else '     --     '
        print(f'v{v:5d} {tt:2s} T={Ts} b={b if b is None else f"{b:02x}"} '
              f'R={Rb.hex()} -> {em} {val} how={how} pos={fpos}{flip}')

# GT reference: Y values near the flip
print('\nGT Y stats: min %.3f max %.3f' % (Gu[:, 1].min(), Gu[:, 1].max()))
print('GT count Y>170000:', int((Gu[:, 1] > 170000).sum()),
      ' Y in [178000,182000]:', int(((Gu[:, 1] > 178000) & (Gu[:, 1] < 182000)).sum()))
