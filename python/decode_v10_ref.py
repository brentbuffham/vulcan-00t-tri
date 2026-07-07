#!/usr/bin/env python3
"""decode_v10_ref -- v9 + CONTEXT-CONDITIONAL PLACEMENT (GT-free). CURRENT BEST.

REFERENCE_COLUMN_HUNT findings: residual onsets are NOT a wrong reference lag
(no column period exists on any file: GT-free lag scan monotone, best-lag
histogram flat, even the oracle nearest-neighbor fails the Z half-window) and
NOT fixable by placement competition on distance-to-ref (the smaller-window
placement always parks nearest the reference; sweeps M=4..1024 all regress).
They are k0_rule placement EXCEPTIONS keyed by stream CONTEXT.

v10 = v9 + Rule A: an nb=5 record whose T-rule says plc2 is placed at plc3
when the previous V record was nb=6 (the fold signature). Cross-file NET:
intercepts 52.1->54.5%, SYLVANIA cold 41.2->49.0%, OB34 cold 10.4->11.0%.
(Rule B post-FULL/no-T->plc2 was tried and REJECTED: cold regression.)

Usage: python decode_v10_ref.py <case>   (MARGIN arg retained but unused)
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
MARGIN = float(sys.argv[2]) if len(sys.argv) > 2 else 16.0
OOT, DXF = CASES[case]
d = open(OOT, 'rb').read(); n = len(d)
def be(b): return struct.unpack('>d', bytes(b))[0]

# ---- container location (identical to decode_v8_frame) ----
geo_end = struct.unpack('<15i', d[0:60])[11]
def coordlike(v): return np.isfinite(v) and 1 < abs(v) < 1e7
seed_off = None
for off in range(8240, 8400):
    vs = [be(d[off + 8 * k:off + 8 * k + 8]) for k in range(3) if off + 8 * k + 8 <= n]
    if len(vs) == 3 and all(coordlike(v) for v in vs):
        seed_off = off; break
assert seed_off is not None, 'coord section not located'
coord_start = seed_off + 24
occ = [i for i in range(seed_off, min(n, geo_end) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = min(n, geo_end)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break
SEED = [abs(be(d[seed_off + 8 * k:seed_off + 8 * k + 8])) for k in range(3)]
print(f'{case} (v9): seed_off {seed_off} coord_start {coord_start} face_start {face_start}  seeds {[round(s,1) for s in SEED]}')

# ---- pass 1: loose bands (unchanged) ----
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

# ---- v8b tokenizer (unchanged) ----
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

# ---- shorth bands (unchanged) ----
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
    else:
        TIGHT.append(LOOSE[a])
band = make_band(TIGHT); toks = tokenize(make_full_at(band))
print('shorth bands:', '  '.join(f'{"XYZ"[a]}[{TIGHT[a][0]:.1f}..{TIGHT[a][1]:.1f}]' for a in range(3)))

# ---- v9 value reconstruction ----
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
def wrap_fill(pred_v, payload, k0, R):
    """place payload at k0; bytes AFTER the window copied from R; bytes BEFORE
    the window = the value (of pred_hi-1/pred_hi/pred_hi+1) nearest pred."""
    nb = len(payload); hb = k0
    if hb < 0 or k0 + nb > 8: return None
    tail = R[k0 + nb:]
    pb = struct.pack('>d', pred_v)
    hi = int.from_bytes(pb[:hb], 'big') if hb else 0
    best = None
    for dh in (-1, 0, 1) if hb else (0,):
        h2 = hi + dh
        if not (0 <= h2 < (1 << (8 * hb))) and hb: continue
        vb = (h2.to_bytes(hb, 'big') if hb else b'') + payload + tail
        v = be(vb)
        if not np.isfinite(v): continue
        dv = abs(v - pred_v)
        if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None
def hi_cands(R, payload, k0, a, ref_v, span=4):
    """placement k0, tail from R; hi bytes = R's hi +- dh. Return (dist, vb)
    of the IN-BAND candidate NEAREST ref_v. dh=0 wins ties."""
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
    if nb == 0 or nb > 8: return None
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    # CONTEXT RULE A (VALUE_SPLICE_HUNT sec2 fold signal): nb=5 records whose
    # T-rule says plc2 are actually plc3 when the PREVIOUS V record was nb=6.
    if nb == 5 and k0r == 2 and prev_nb == 6:
        k0r = 3
    # CONTEXT RULE B -- REJECTED cross-file (do not re-add): nb=5/no-T/post-
    # FULL -> plc2 gained +37 on intercepts (48 flips vs 4 controls) but
    # regressed SYLVANIA 49.0->44.9% and OB34 11.0->10.2%. Fingerprint.
    last = be(R)
    c1 = hi_cands(R, payload, k0r, a, last)     # rule placement
    k0l = 8 - nb
    c2 = hi_cands(R, payload, k0l, a, last) if k0l != k0r else None
    if c1 is not None: return c1[1]
    if c2 is not None: return c2[1]
    # fallback: classic register splices, closest to prev
    best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - last)
            if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None

regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
hist = [[be(regs[0])], [be(regs[1])], [be(regs[2])]]
ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
prev_nb = None
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]; hist[a].append(be(regs[a]))
        if a == 2 and ph == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        ph = (a + 1) % 3; prev_nb = 8; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    h = hist[a]
    pred = 2 * h[-1] - h[-2] if len(h) >= 2 else h[-1]
    if band(pred) != a: pred = h[-1]          # extrapolation left the band: fall back to last
    vb = r2_v10(bytes(regs[a]), payload, t[2], a, pred, prev_nb)
    if vb is not None: regs[a][:] = vb
    hist[a].append(be(regs[a]))
    if a == 2: pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
    ph = (ph + 1) % 3; prev_nb = len(payload)
P = np.array(pts)
np.save(f'P_v10_{case}.npy', P)
print(f'decoded {len(P)} vertices')

# ---- score vs DXF (SCORING ONLY) ----
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
                try:
                    ci = int(code); fv = float(val)
                except Exception:
                    continue
                if abs(fv) < 1e8:
                    for base, ax in ((10, 0), (20, 1), (30, 2)):
                        if base <= ci <= base + 3: cur[(ci - base, ax)] = fv
    return np.array(list(seen))
from scipy.spatial import cKDTree
G = dxf_verts(DXF)
dist, _ = cKDTree(G).query(P)
N = min(500, len(P))
print(f'[SCORING ONLY] GT verts {len(G)}  first{N} <1m {int((dist[:N]<1).sum())}/{N}  '
      f'full <1m {int((dist<1).sum())}/{len(P)}  ({100*(dist<1).mean():.1f}%)')
