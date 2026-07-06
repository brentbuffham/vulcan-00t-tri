#!/usr/bin/env python3
"""decode_v7_carry — GT-FREE decode with ROBUST (shorth) axis bands.

Root cause found by selector_hunt.py: the "hidden carry selector" is NOT a
per-token encoder state. The carry(-2) tokens are contiguous EPISODES of
inherited register corruption: one upstream mis-splice pushes the register's
byte1 out of the true coordinate range (e.g. Y: 163k -> 179k), and every
subsequent splice keeps bytes 0-1, propagating the error. v6's axis bands
(min/max of a sliding-window FULL harvest, contaminated by misframed junk)
were too loose to reject the drifted values, so the existing carry search
never fired.

Fix (all GT-free):
  pass 1: loose bands (v6 method) -> tokenize -> harvest FRAMED FULLs
  pass 2: per-axis band = shorth(50%) of framed FULLs, expanded +/- 5*width
          (shorth = shortest interval containing half the points; a classical
          robust estimator, fixed constants, no per-file tuning)
  decode with tight bands: out-of-band splices are rejected and the existing
  carry/k0 search recovers the in-band (correct) value -> episodes self-heal.

GT (intercepts_gt.csv) is used for the final SCORE LINE ONLY.
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
RATIO = 1.15
SEED = [abs(be(d[8326:8334])), abs(be(d[8334:8342])), abs(be(d[8342:8350]))]

# ---------- pass 1: loose bands (v6) ----------
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
LOOSE = [(np.array(bk[a]).min(), np.array(bk[a]).max()) for a in range(3)]

def make_band(rng):
    (xl, xh), (yl, yh), (zl, zh) = rng
    def band(v):
        x = abs(v)
        if zl <= x <= zh: return 2
        if xl <= x <= xh: return 0
        if yl <= x <= yh: return 1
        return -1
    return band

def make_full_at(band):
    def full_at(p):
        if p + 8 <= face_start and d[p] in (0x40, 0x41, 0xC0, 0xC1):
            v = be(d[p:p + 8])
            if band(v) >= 0: return v
        return None
    return full_at

def tokenize(full_at):
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
    return toks

band1 = make_band(LOOSE)
toks1 = tokenize(make_full_at(band1))

# ---------- shorth bands from framed FULLs ----------
def shorth(vals, frac=0.5):
    s = np.sort(np.asarray(vals)); m = len(s)
    k = max(2, int(np.ceil(m * frac)))
    best = None
    for i in range(m - k + 1):
        w = s[i + k - 1] - s[i]
        if best is None or w < best[0]: best = (w, s[i], s[i + k - 1])
    return best[1], best[2]

fr = {0: [], 1: [], 2: []}
for t in toks1:
    if t[0] in ('F', 'Fe'):
        a = band1(be(t[1]))
        if a >= 0: fr[a].append(abs(be(t[1])))
TIGHT = []
for a in range(3):
    if len(fr[a]) >= 4:
        lo, hi = shorth(fr[a])
        w = max(hi - lo, 1.0)
        TIGHT.append((lo - 5 * w, hi + 5 * w))
    else:
        TIGHT.append(LOOSE[a])
band = make_band(TIGHT)
toks = tokenize(make_full_at(band))

# ---------- decode (identical machinery to v6, tight bands) ----------
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
np.save('P_v7carry.npy', P)
print('GT-FREE shorth bands:', '  '.join(f'{"XYZ"[a]}[{TIGHT[a][0]:.1f}..{TIGHT[a][1]:.1f}]' for a in range(3)))
print(f'decoded {len(P)} vertices -> P_v7carry.npy')
if '--score' in sys.argv:
    from scipy.spatial import cKDTree
    gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
    dist, _ = cKDTree(Gu).query(P)
    N = min(500, len(P))
    print(f'[SCORING ONLY, GT never fed to decoder] first500 {int((dist[:N] < 1).sum())}/{N}   '
          f'full {int((dist < 1).sum())}/{len(P)}  ({100 * (dist < 1).mean():.1f}%)')
