#!/usr/bin/env python3
"""refhunt4 -- teacher-force pinned sites: which (placement k0, hi-delta dh)
reconstructs the TRUE value bit-exact from (register R, payload)?

If a (k0,dh) exists: info is in the record; census which k0/dh vs the current
rule (placement fix vs reference fix). If none: register corrupted or value
needs external data. GT used ONLY to pin true values (labeling).
Usage: python refhunt4.py <case>
"""
import struct, sys
import numpy as np
CASES = {
    'intercepts': (r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t',
                   r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'),
    'SYLVANIA':   (r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topo.00t',
                   r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topoDXF.dxf'),
    'OB34':       (r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_Topo.00t',
                   r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_TopoDXF.dxf'),
}
case = sys.argv[1] if len(sys.argv) > 1 else 'intercepts'
OOT, DXF = CASES[case]
d = open(OOT, 'rb').read(); n = len(d)
def be(b): return struct.unpack('>d', bytes(b))[0]
geo_end = struct.unpack('<15i', d[0:60])[11]
def coordlike(v): return np.isfinite(v) and 1 < abs(v) < 1e7
seed_off = None
for off in range(8240, 8400):
    vs = [be(d[off + 8 * k:off + 8 * k + 8]) for k in range(3) if off + 8 * k + 8 <= n]
    if len(vs) == 3 and all(coordlike(v) for v in vs): seed_off = off; break
coord_start = seed_off + 24
occ = [i for i in range(seed_off, min(n, geo_end) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = min(n, geo_end)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break
SEED = [abs(be(d[seed_off + 8 * k:seed_off + 8 * k + 8])) for k in range(3)]
def make_band(rng):
    (a0, b0), (a1, b1), (a2, b2) = rng
    def band(v):
        x = abs(v)
        if a2 <= x <= b2: return 2
        if a0 <= x <= b0: return 0
        if a1 <= x <= b1: return 1
        return -1
    return band
RATIO = 1.15
bk = {0: [], 1: [], 2: []}
_pos = coord_start
while _pos + 8 <= face_start:
    if d[_pos] in (0x40, 0x41, 0xC0, 0xC1):
        _v = abs(be(d[_pos:_pos + 8]))
        if np.isfinite(_v) and _v > 0:
            _r = [max(_v, s) / min(_v, s) for s in SEED]
            _a = int(np.argmin(_r))
            if _r[_a] < RATIO: bk[_a].append(_v)
    _pos += 1
LOOSE = [(np.array(bk[a]).min(), np.array(bk[a]).max()) if len(bk[a]) >= 1 else (SEED[a] / 1.5, SEED[a] * 1.5) for a in range(3)]
def make_full_at(band):
    def full_at(pos):
        if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
            v = be(d[pos:pos + 8])
            if band(v) >= 0: return v
        return None
    return full_at
def tokenize(full_at):
    toks = []; pos = coord_start; lastT = None
    while pos < face_start:
        b = d[pos]
        if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
            while pos < face_start and d[pos] == 0: pos += 1
            continue
        if full_at(pos) is not None:
            toks.append(('F', d[pos:pos + 8], lastT, None)); lastT = None; pos += 8; continue
        if full_at(pos + 1) is not None:
            toks.append(('Fe', d[pos + 1:pos + 9], lastT, None)); lastT = None
            pos += 9
            if pos < face_start and (d[pos] & 7) == 7: pos += 1
            continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            if end > face_start: end = face_start
            toks.append(('V', d[pos + 1:end], lastT, b)); lastT = None; pos = end; continue
        if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; pos += 3; continue
        if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
        pos += 1
    return toks
band1 = make_band(LOOSE); toks1 = tokenize(make_full_at(band1))
def shorth(vals, frac=0.5):
    v = np.sort(np.asarray(vals)); m = len(v)
    if m == 0: return (np.nan, np.nan)
    k = max(1, int(np.ceil(frac * m)))
    if k >= m: return (v[0], v[-1])
    w = v[k - 1:] - v[:m - k + 1]; i = int(np.argmin(w))
    return (v[i], v[i + k - 1])
fr = {0: [], 1: [], 2: []}
for t in toks1:
    if t[0] in ('F', 'Fe'):
        a = band1(be(t[1]))
        if a >= 0: fr[a].append(abs(be(t[1])))
TIGHT = []
for a in range(3):
    if len(fr[a]) >= 3:
        lo, hi = shorth(fr[a]); w = max(hi - lo, 1e-6); TIGHT.append((lo - 5 * w, hi + 5 * w))
    else: TIGHT.append(LOOSE[a])
band = make_band(TIGHT); toks = tokenize(make_full_at(band))
def k0_rule(T, nb):
    if T is not None:
        T1, T2 = T
        if nb == 4: return 3
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {5: 3, 6: 2}.get(nb, max(0, 8 - nb))
def hi_cands(R, payload, k0, a, ref_v, span=4):
    nb = len(payload); hb = k0
    if hb < 0 or k0 + nb > 8: return None
    tail = R[k0 + nb:]
    hi = int.from_bytes(R[:hb], 'big') if hb else 0
    best = None
    for dh in range(-span, span + 1):
        h2 = hi + dh
        if hb and not (0 <= h2 < (1 << (8 * hb))): continue
        if not hb and dh != 0: continue
        vb = (h2.to_bytes(hb, 'big') if hb else b'') + payload + tail
        v = be(vb)
        if not np.isfinite(v) or band(v) != a: continue
        dv = (abs(v - ref_v), abs(dh))
        if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None
def spl(R, payload, k0):
    nb = len(payload); end = k0 + nb
    if k0 < 0 or end > 8: return None
    return bytes(bytearray(R[:k0]) + bytearray(payload) + bytearray(R[end:]))
def r2_v9(R, payload, T, a, ref_v):
    nb = len(payload)
    if nb == 0 or nb > 8: return None
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    c1 = hi_cands(R, payload, k0r, a, ref_v)
    if c1 is not None: return c1
    k0l = 8 - nb
    if k0l != k0r:
        c2 = hi_cands(R, payload, k0l, a, ref_v)
        if c2 is not None: return c2
    best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - ref_v)
            if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None

# decode, recording per-vertex-axis token info
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
info = [ {} ]  # per vertex: axis -> (kind, payload, T, Rbefore)
cur = {}
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        cur[a] = ('F', bytes(t[1]), None, bytes(regs[a]))
        regs[a][:] = t[1]
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2]))); info.append(cur); cur = {}
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    cur[a] = ('V', bytes(payload), t[2], bytes(regs[a]))
    vb = r2_v9(bytes(regs[a]), payload, t[2], a, be(regs[a]))
    if vb is not None: regs[a][:] = vb
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2]))); info.append(cur); cur = {}
    ph = (ph + 1) % 3
P = np.array(pts)
print(f'{case}: decoded {len(P)} vertices')

def dxf_verts(path):
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
from scipy.spatial import cKDTree
G = dxf_verts(DXF)
dist, idx = cKDTree(G).query(P)
print(f'[SCORE] full <1m {int((dist<1).sum())}/{len(P)} ({100*(dist<1).mean():.1f}%)')
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
print(f'pinned: {len(pins)}')

# teacher-force each pinned site
from collections import Counter
cens = {0: Counter(), 1: Counter(), 2: Counter()}
noex = {0: Counter(), 1: Counter(), 2: Counter()}
onset_cens = {0: Counter(), 1: Counter(), 2: Counter()}
dh_vals = {0: [], 1: [], 2: []}
examples = []
for (i, wa, tv) in pins:
    rec = info[i].get(wa)
    onset = dist[i - 1] < TOL if i >= 1 else False
    if rec is None:
        noex[wa][('NOREC', onset)] += 1; continue
    kind, payload, T, R = rec
    if kind == 'F':
        noex[wa][('FULL', onset)] += 1; continue
    nb = len(payload)
    T1c = ('20' if T and T[0] == 0x20 else '21-3F' if T and 0x21 <= T[0] <= 0x3F
           else '40-5F' if T and 0x40 <= T[0] <= 0x5F else 'none')
    hits = []
    tvb = struct.pack('>d', tv)
    for k0 in range(0, 8 - nb + 1):
        hb = k0; tail = R[k0 + nb:]
        hi = int.from_bytes(R[:hb], 'big') if hb else 0
        for dh in range(-260, 261):
            h2 = hi + dh
            if hb and not (0 <= h2 < (1 << (8 * hb))): continue
            if not hb and dh != 0: continue
            vb = (h2.to_bytes(hb, 'big') if hb else b'') + payload + tail
            if abs(be(vb) - tv) < 1e-6:
                hits.append((k0, dh))
    if hits:
        # prefer smallest |dh|
        k0, dh = min(hits, key=lambda h: (abs(h[1]), h[0]))
        key = (nb, T1c, k0, 'dh0' if dh == 0 else f'dh{dh:+d}' if abs(dh) <= 4 else 'dhBIG')
        cens[wa][key] += 1
        if onset: onset_cens[wa][key] += 1
        dh_vals[wa].append(dh)
        if len(examples) < 20 and abs(dh) > 4:
            examples.append((i, wa, nb, T1c, k0, dh, tv, be(R)))
    else:
        noex[wa][(f'nb{nb}', T1c, onset)] += 1
for a in range(3):
    print(f'\n=== axis {"XYZ"[a]} ===')
    print('  EXACT reconstructions (nb, T1, k0, dh) [pref min|dh|]:')
    for k, c in cens[a].most_common(12): print(f'    {k}: {c}')
    print('  NO exact reconstruction:', dict(noex[a]))
    print('  onset-only census:', dict(onset_cens[a]))
    if dh_vals[a]:
        dv = np.array(dh_vals[a])
        print(f'  dh: 0:{(dv==0).sum()}  |dh|<=4:{(np.abs(dv)<=4).sum()}  |dh|>4:{(np.abs(dv)>4).sum()}')
print('\nbig-dh examples (i, axis, nb, T1, k0, dh, true, R):')
for e in examples: print(' ', e)
