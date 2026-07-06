#!/usr/bin/env python3
"""Quantify the two misframe mechanisms on any case (GT used to LABEL only):
A) Fe 10-byte consumption swallowing a following FULL's lead (full_at(pos+9))
B) V-truncation: F fired inside a declared V payload -- are those F clean or junk?
Usage: python trunc_probe.py <case>
"""
import struct, sys
from collections import Counter
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
    if len(vs) == 3 and all(coordlike(v) for v in vs):
        seed_off = off; break
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
            toks.append(('F', d[pos:pos + 8], lastT, None, pos)); lastT = None; pos += 8; continue
        if b >= 0x20 and full_at(pos + 1) is not None:
            toks.append(('Fe', d[pos + 1:pos + 9], lastT, b, pos)); lastT = None; pos += 10; continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            trunc = False
            for j in range(pos + 1, min(end, face_start)):
                if full_at(j) is not None: end = j; trunc = True; break
            if end > face_start: end = face_start
            toks.append(('Vt' if trunc else 'V', d[pos + 1:end], lastT, b, pos)); lastT = None; pos = end; continue
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
    else:
        TIGHT.append(LOOSE[a])
band = make_band(TIGHT); full_at = make_full_at(band)
toks = tokenize(full_at)

# GT extents for labeling
def dxf_extents(path):
    lo = [1e18] * 3; hi = [-1e18] * 3; in3d = False
    with open(path, 'r', errors='ignore') as f:
        prev = None
        for line in f:
            s = line.strip()
            if prev is None: prev = s; continue
            code, val = prev, s; prev = None
            if code == '0': in3d = (val.upper() == '3DFACE'); continue
            if in3d:
                try:
                    ci = int(code); fv = float(val)
                except Exception:
                    continue
                if abs(fv) < 1e8:
                    for base, ax in ((10, 0), (20, 1), (30, 2)):
                        if base <= ci <= base + 3:
                            a = ci - base if False else ax
                            lo[ax] = min(lo[ax], abs(fv)); hi[ax] = max(hi[ax], abs(fv))
    return list(zip(lo, hi))
GEXT = dxf_extents(DXF)
MARG = 2.0
def gt_ok_val(v):
    x = abs(v)
    return any(GEXT[a][0] - MARG <= x <= GEXT[a][1] + MARG for a in range(3))

print(f'== {case} ==  toks {len(toks)}')
kinds = Counter(t[0] for t in toks)
print('token kinds (pass2 tight):', dict(kinds))

# A) Fe swallow census (pass2)
fe = [t for t in toks if t[0] == 'Fe']
sw = sum(1 for t in fe if t[4] + 9 < face_start and full_at(t[4] + 9) is not None)
print(f'A) Fe swallowing a following in-band FULL lead: {sw}/{len(fe)}')

# B) truncation census: the F that immediately follows a Vt -- clean or junk?
cln = jnk = 0; follow = Counter()
prev = None
for t in toks:
    if prev is not None and prev[0] == 'Vt':
        follow[t[0]] += 1
        if t[0] in ('F', 'Fe'):
            if gt_ok_val(be(t[1])): cln += 1
            else: jnk += 1
    prev = t
print(f'B) V-truncation events: {kinds.get("Vt",0)}; token right after Vt: {dict(follow)}; '
      f'following F/Fe clean {cln} junk {jnk}  [GT-labeled]')

# B2) ALL F/Fe in pass2: clean vs junk by whether preceded by Vt
cc = Counter()
prev = None
for t in toks:
    if t[0] in ('F', 'Fe'):
        pv = prev[0] if prev is not None else '-'
        cc[(t[0], pv == 'Vt', gt_ok_val(be(t[1])))] += 1
    prev = t
print('B2) (kind, after-Vt?, clean?):', dict(cc))

# C) pass1 harvest purity: same but for toks1 (what builds the bands)
cc1 = Counter()
prev = None
for t in toks1:
    if t[0] in ('F', 'Fe'):
        pv = prev[0] if prev is not None else '-'
        cc1[(t[0], pv == 'Vt', gt_ok_val(be(t[1])))] += 1
    prev = t
print('C) pass1 harvest (kind, after-Vt?, clean?):', dict(cc1))
