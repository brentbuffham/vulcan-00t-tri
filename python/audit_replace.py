#!/usr/bin/env python3
"""AUDIT step 2: replace the hardcoded axis ranges with a classifier derived
ONLY from the file's own vertex-0 seed registers (offset 8326), then check it
reproduces the v5-P3 decode byte-for-byte. If it does, the hardcoded ranges
carried NO answer-derived information beyond the file's own init coords.

band()/sane() are rebuilt from seeds sX,sY,sZ read at 8326/8334/8342.
Axis = nearest seed (in log10 space, since seeds span 656..162948).
Reject = value too far from its nearest seed (factor window, GT-free).
NO GT loaded except an optional final score (clearly the only GT touch).
"""
import struct, sys
import numpy as np

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d = open(OOT, 'rb').read(); n = len(d)
occ = [i for i in range(8326, n - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = n
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break

def be(b): return struct.unpack('>d', bytes(b))[0]

# --- seeds from the file itself (vertex 0), no DXF ---
SEED = [abs(be(d[8326:8334])), abs(be(d[8334:8342])), abs(be(d[8342:8350]))]
# reorder to axis convention used by decoder: band 0=X(50-60k),1=Y(160k),2=Z(500-1000)
# decoder axis a: 0->reg0(X seed 55963), 1->reg1(Y seed 162948), 2->reg2(Z seed 656)
sX, sY, sZ = SEED[0], SEED[1], SEED[2]
logseed = [np.log10(sX), np.log10(sY), np.log10(sZ)]  # axis-indexed 0,1,2
print(f'seeds  X={sX:.2f}  Y={sY:.2f}  Z={sZ:.2f}')

WIN = float(sys.argv[1]) if len(sys.argv) > 1 else 0.30  # allowed log10 distance

def band_seed(v):
    x = abs(v)
    if x <= 0: return -1
    lx = np.log10(x)
    dists = [abs(lx - logseed[a]) for a in range(3)]
    a = int(np.argmin(dists))
    if dists[a] > WIN: return -1
    return a
def sane_seed(v):
    return band_seed(v) >= 0

# ---- decoder identical to decode_v5p3, but band/sane are seed-derived ----
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if sane_seed(v): return v
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
        if nb == 4: return 3          # v5-P3 locked rule
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
    if vb is not None and band_seed(be(vb)) == a: return vb
    for c in (-1, 1, -2, 2, -3, 3, -4, 4):
        vb = spl(R, payload, k0r, c)
        if vb is not None and band_seed(be(vb)) == a: return vb
    pv = be(R); best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band_seed(be(vb)) == a:
            dv = abs(be(vb) - pv)
            if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None

def run():
    regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
    ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
    for t in toks:
        if t[0] in ('F', 'Fe'):
            v = be(t[1]); a = band_seed(v)
            if a < 0: continue
            regs[a][:] = t[1]
            if a == 2 and ph == 2:
                pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            ph = (a + 1) % 3; continue
        payload = t[1]
        if len(payload) == 0: continue
        a = ph
        vb = r2_value(bytes(regs[a]), payload, t[2], a)
        if vb is not None: regs[a][:] = vb
        if a == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        ph = (ph + 1) % 3
    return np.array(pts)

P = run()
np.save('P_v5p3_seedband.npy', P)
print(f'seed-derived decode: {len(P)} points  (WIN={WIN})')

# compare to the hardcoded-range decode
try:
    Pold = np.load('P_v5p3.npy')
    m = min(len(P), len(Pold))
    same = np.all(np.isclose(P[:m], Pold[:m], atol=1e-6), axis=1).sum()
    print(f'identical points vs hardcoded-range decode: {same}/{m}  (len old={len(Pold)}, new={len(P)})')
except FileNotFoundError:
    print('P_v5p3.npy not found for comparison')

# the ONLY GT touch: score, clearly labeled
if '--score' in sys.argv:
    from scipy.spatial import cKDTree
    gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
    dist, _ = cKDTree(Gu).query(P)
    print(f'[SCORING ONLY] anchor<1m {(dist<1).sum()}/{len(P)}')
