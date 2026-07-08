#!/usr/bin/env python3
"""zhunt1 -- characterize k (Z window-count error) on the yellow class.

Instrumented v10 decode: for every Z emission record, log lead byte, nb, T,
register-before, prev-record class, E0-token context, last Z FULL, etc.
Pin yellow sites via bit-exact X/Y (GT for LABEL/SCORE ONLY), compute
k = hi3(true) - hi3(decoded) (integer byte-2 window count), census candidates.

Usage: python zhunt1.py <case>
"""
import struct, sys, pickle
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
    """extended: every token gets a stream pos; E0-class 3-byte tokens are KEPT."""
    toks = []; pos = coord_start; lastT = None
    while pos < face_start:
        b = d[pos]
        if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
            while pos < face_start and d[pos] == 0: pos += 1
            continue
        if full_at(pos) is not None:
            toks.append(('F', pos, d[pos:pos + 8], lastT, None)); lastT = None; pos += 8; continue
        if full_at(pos + 1) is not None:
            toks.append(('Fe', pos, d[pos + 1:pos + 9], lastT, None)); lastT = None
            pos += 9
            if pos < face_start and (d[pos] & 7) == 7: pos += 1
            continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            if end > face_start: end = face_start
            toks.append(('V', pos, d[pos + 1:end], lastT, b)); lastT = None; pos = end; continue
        if 0xe0 <= b <= 0xff and pos + 3 <= face_start:
            toks.append(('E', pos, d[pos:pos + 3], lastT, b)); lastT = None; pos += 3; continue
        if pos + 2 <= face_start:
            lastT = (d[pos], d[pos + 1])
            toks.append(('T', pos, d[pos:pos + 2], None, b)); pos += 2; continue
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
        a = band1(be(t[2]))
        if a >= 0: fr[a].append(abs(be(t[2])))
TIGHT = []
for a in range(3):
    if len(fr[a]) >= 3:
        lo, hi = shorth(fr[a]); w = max(hi - lo, 1e-6); TIGHT.append((lo - 5 * w, hi + 5 * w))
    else: TIGHT.append(LOOSE[a])
band = make_band(TIGHT); toks = tokenize(make_full_at(band))
print(f'{case}: {len(toks)} tokens')

def k0_rule(T, nb):
    if T is not None:
        T1, T2 = T
        if nb == 4: return 3
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {5: 3, 6: 2}.get(nb, max(0, 8 - nb))
def spl(R, payload, k0):
    nb = len(payload); end = k0 + nb
    if k0 < 0 or end > 8: return None
    return bytes(bytearray(R[:k0]) + bytearray(payload) + bytearray(R[end:]))
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
    return best if best else None
def r2_v10(R, payload, T, a, pred_v, prev_nb=None):
    nb = len(payload)
    if nb == 0 or nb > 8: return None, None
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    if nb == 5 and k0r == 2 and prev_nb == 6:
        k0r = 3
    last = be(R)
    c1 = hi_cands(R, payload, k0r, a, last)
    k0l = 8 - nb
    c2 = hi_cands(R, payload, k0l, a, last) if k0l != k0r else None
    if c1 is not None: return c1[1], k0r
    if c2 is not None: return c2[1], k0l
    best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - last)
            if best is None or dv < best[0]: best = (dv, vb, k0)
    return (best[1], best[2]) if best else (None, None)

# ---- decode with instrumentation ----
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
hist = [[be(regs[0])], [be(regs[1])], [be(regs[2])]]
ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
prev_nb = None
lastF = [None, None, None]      # last FULL value per axis
lastFi = [None, None, None]     # vertex index of it
recent_E = []                   # E-tokens since last V/F record
zmeta = {}                      # vertex idx -> dict (record that WROTE Z for this vertex)
allmeta = {0: {}, 1: {}, 2: {}} # per-axis record meta by vertex idx
for ti, t in enumerate(toks):
    kind = t[0]
    if kind == 'E':
        recent_E.append((ti, bytes(t[2]))); continue
    if kind == 'T':
        continue
    if kind in ('F', 'Fe'):
        v = be(t[2]); a = band(v)
        if a < 0: recent_E = []; continue
        meta = dict(kind=kind, ti=ti, pos=t[1], b=None, nb=8, T=None,
                    Rbefore=bytes(regs[a]), prev_nb=prev_nb,
                    lastF=lastF[a], lastFi=lastFi[a],
                    E=list(recent_E), k0=None)
        regs[a][:] = t[2]; hist[a].append(be(regs[a]))
        lastF[a] = be(regs[a])
        meta['dec'] = be(regs[a])
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        vi = len(pts) - 1
        lastFi[a] = vi
        allmeta[a][vi] = meta
        ph = (a + 1) % 3; prev_nb = 8; recent_E = []; continue
    payload = t[2]
    if len(payload) == 0: continue
    a = ph
    h = hist[a]
    pred = 2 * h[-1] - h[-2] if len(h) >= 2 else h[-1]
    if band(pred) != a: pred = h[-1]
    meta = dict(kind='V', ti=ti, pos=t[1], b=t[4], nb=len(payload), T=t[3],
                Rbefore=bytes(regs[a]), prev_nb=prev_nb,
                lastF=lastF[a], lastFi=lastFi[a],
                E=list(recent_E), payload=bytes(payload))
    vb, k0used = r2_v10(bytes(regs[a]), payload, t[3], a, pred, prev_nb)
    if vb is not None: regs[a][:] = vb
    meta['dec'] = be(regs[a]); meta['k0'] = k0used
    hist[a].append(be(regs[a]))
    if a == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
    vi = len(pts) - 1
    allmeta[a][vi] = meta
    ph = (ph + 1) % 3; prev_nb = len(payload); recent_E = []
P = np.array(pts)
print(f'decoded {len(P)} vertices')

# ---- GT pinning (LABEL/SCORE ONLY) ----
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
                            seen.add((cur[(kk, 0)], cur[(kk, 1)], cur[(kk, 2)]))
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
dist, _ = cKDTree(G).query(P)
print(f'[SCORING ONLY] 3D<0.25m: {int((dist<0.25).sum())}/{len(P)} ({100*(dist<0.25).mean():.1f}%)')

# pin via exact X/Y
TOL = 1e-3
txy = cKDTree(G[:, :2])
pins = []   # (vi, trueZ, decZ, class)
nn = txy.query_ball_point(P[:, :2], r=TOL)
for vi in range(len(P)):
    cands = nn[vi]
    if not cands: continue
    zs = np.unique(np.round(G[cands, 2], 6))
    if len(zs) != 1: continue   # ambiguous pin
    tz = float(zs[0]); dz = float(P[vi, 2])
    pins.append((vi, tz, dz))
pins = [(vi, tz, dz) for (vi, tz, dz) in pins]
ok  = [(vi, tz, dz) for (vi, tz, dz) in pins if abs(tz - dz) < TOL]
yel = [(vi, tz, dz) for (vi, tz, dz) in pins if abs(tz - dz) >= 0.25]
mid = [(vi, tz, dz) for (vi, tz, dz) in pins if TOL <= abs(tz - dz) < 0.25]
print(f'pinned {len(pins)}: cleanZ {len(ok)}  yellowZ {len(yel)}  mid {len(mid)}')

# ---- k computation ----
def hi3(v): return int.from_bytes(struct.pack('>d', v)[:3], 'big')
def low5(v): return struct.pack('>d', v)[3:]
def kwin(tz, dz):
    """integer window count if low bytes 3..7 agree, else None"""
    tb, db = struct.pack('>d', tz), struct.pack('>d', dz)
    if tb[3:] == db[3:]: return hi3(tz) - hi3(dz)
    return None
rows = []
for (vi, tz, dz) in yel:
    m = allmeta[2].get(vi)
    k = kwin(tz, dz)
    rows.append((vi, tz, dz, k, m))
kx = [r[3] for r in rows if r[3] is not None]
print(f'\nyellow with EXACT low-window congruence (bytes 3..7 identical): {len(kx)}/{len(rows)}')
if kx:
    kxa = np.array(kx)
    print(f'k stats: min {kxa.min()} max {kxa.max()} median {np.median(kxa):.0f}  sign +:{(kxa>0).sum()} -:{(kxa<0).sum()}')
    import collections
    print('k histogram (top20):', collections.Counter(kx).most_common(20))

# ---- record-class census: yellow vs clean ----
import collections
def cls(m):
    if m is None: return 'NOREC'
    if m['kind'] != 'V': return m['kind']
    T = m['T']
    T1c = ('none' if T is None else '20' if T[0] == 0x20 else '21-3F' if 0x21 <= T[0] <= 0x3F
           else '40-5F' if 0x40 <= T[0] <= 0x5F else f'{T[0]:02x}')
    return (m['nb'], f"b{m['b']:02x}", T1c, f"prev{m['prev_nb']}")
cy = collections.Counter(cls(r[4]) for r in rows)
co = collections.Counter(cls(allmeta[2].get(vi)) for (vi, tz, dz) in ok)
print('\nrecord class at YELLOW-Z (top15):')
for k_, c in cy.most_common(15): print(f'  {k_}: {c}')
print('record class at CLEAN-Z (top15):')
for k_, c in co.most_common(15): print(f'  {k_}: {c}')

# ---- reference-candidate scan: |ref - trueZ| < half-window? ----
def halfwin(dz):
    b = bytearray(struct.pack('>d', dz))
    h = int.from_bytes(b[:3], 'big')
    b2 = bytearray(b); b2[:3] = (h + 1).to_bytes(3, 'big')
    return abs(be(bytes(b2)) - dz) / 2
zhist_all = np.array(hist[2])
# rebuild per-vertex Z sequence index: hist[2][j] corresponds to j-th Z emission = vertex j
def refs_for(vi, m):
    """candidate references available GT-free at decode time of vertex vi's Z record"""
    Rb = be(m['Rbefore'])
    out = {'last': Rb}
    out['lastFULL'] = m['lastF'] if m['lastF'] is not None else Rb
    j = vi  # Z emission index == vertex index (Z closes each vertex)
    zh = zhist_all
    if j >= 2:
        out['para'] = 2 * zh[j - 1] - zh[j - 2]
        out['delta_run'] = zh[j - 1] + (zh[j - 1] - zh[j - 2])
    if j >= 4:
        out['mean4'] = zh[j - 4:j].mean()
        out['med4'] = float(np.median(zh[j - 4:j]))
    if m['lastFi'] is not None and m['lastFi'] >= 1 and j > m['lastFi']:
        fj = m['lastFi']
        steps = j - fj
        if fj >= 1:
            out['full_plus_run'] = zh[fj] + steps * (zh[j - 1] - zh[fj]) / max(steps - 0, 1) if steps > 0 else zh[fj]
    return out
scores = collections.Counter(); tot = collections.Counter()
for (vi, tz, dz) in yel + ok:
    m = allmeta[2].get(vi)
    if m is None or m['kind'] != 'V': continue
    hw = halfwin(dz)
    lab = 'yel' if abs(tz - dz) >= 0.25 else 'ok'
    for name, rv in refs_for(vi, m).items():
        tot[(name, lab)] += 1
        if abs(rv - tz) < hw: scores[(name, lab)] += 1
print('\nreference-candidate success (|ref-trueZ| < half-window):')
for name in ['last', 'lastFULL', 'para', 'delta_run', 'mean4', 'med4', 'full_plus_run']:
    y, ty = scores[(name, 'yel')], tot[(name, 'yel')]
    o, to = scores[(name, 'ok')], tot[(name, 'ok')]
    print(f'  {name:14s} yellow {y}/{ty}   clean {o}/{to}')

# ---- save meta for follow-up ----
with open(f'zmeta_{case}.pkl', 'wb') as f:
    pickle.dump(dict(pins=pins, ok=ok, yel=yel, rows=[(vi, tz, dz, k) for (vi, tz, dz, k, m) in rows],
                     P=P, hist2=zhist_all), f)
print(f'\nsaved zmeta_{case}.pkl')
