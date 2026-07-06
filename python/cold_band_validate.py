#!/usr/bin/env python3
"""COLD VALIDATION of the shorth-band method (decode_v7_carry) on files it never
saw. For each file: locate coord section dynamically (seed triple -> coord_start;
e0-03 gap -> face_start), harvest FRAMED FULLs, compute shorth bands, and compare
to the file's TRUE extent parsed from its DXF. Does shorth recover the real range
and reject misframed junk on a cold file? DXF used for SCORING/extent ONLY.
"""
import struct
import numpy as np

CASES = {
    'intercepts (control)': (r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t',
                             r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'),
    'SYLVANIA (cold)':      (r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topo.00t',
                             r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topoDXF.dxf'),
    'OB34 (cold)':          (r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_Topo.00t',
                             r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_TopoDXF.dxf'),
}
def be(b): return struct.unpack('>d', bytes(b))[0]

def locate(d):
    n = len(d); geo_end = struct.unpack('<15i', d[0:60])[11]
    # seed triple: first run of 3 coord-like BE doubles in a small window
    def coordlike(v): return np.isfinite(v) and 1 < abs(v) < 1e7
    seed_off = None
    for off in range(8240, 8400):
        vs = [be(d[off + 8 * k:off + 8 * k + 8]) for k in range(3) if off + 8 * k + 8 <= n]
        if len(vs) == 3 and all(coordlike(v) for v in vs):
            seed_off = off; break
    if seed_off is None: return None
    coord_start = seed_off + 24
    occ = [i for i in range(seed_off, min(n, geo_end) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
    face_start = min(n, geo_end)
    for k in range(len(occ) - 3):
        if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break
    return seed_off, coord_start, face_start

def seeds_of(d, seed_off):
    return [abs(be(d[seed_off + 8 * k:seed_off + 8 * k + 8])) for k in range(3)]

def harvest_framed_fulls(d, coord_start, face_start, seeds):
    """Tokenize like v7 (loose seed-window bands for pass 1) and collect FRAMED
    FULL doubles (tokenizer-aligned), assigned to nearest seed."""
    # pass-1 loose band: within 1.5x of a seed
    def loose_band(v):
        x = abs(v)
        if x <= 0: return -1
        r = [max(x, s) / min(x, s) for s in seeds]
        a = int(np.argmin(r))
        return a if r[a] < 1.5 else -1
    def full_at(pos):
        if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
            v = be(d[pos:pos + 8])
            if loose_band(v) >= 0: return v
        return None
    fr = {0: [], 1: [], 2: []}
    pos = coord_start
    while pos < face_start:
        b = d[pos]
        if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
            while pos < face_start and d[pos] == 0: pos += 1
            continue
        v = full_at(pos)
        if v is not None:
            fr[loose_band(v)].append(abs(v)); pos += 8; continue
        if b >= 0x20 and full_at(pos + 1) is not None:
            v = full_at(pos + 1); fr[loose_band(v)].append(abs(v)); pos += 10; continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            for j in range(pos + 1, min(end, face_start)):
                if full_at(j) is not None: end = j; break
            pos = min(end, face_start); continue
        if 0xe0 <= b <= 0xff and pos + 3 <= face_start: pos += 3; continue
        if pos + 2 <= face_start: pos += 2; continue
        pos += 1
    return fr

def shorth(vals, frac=0.5):
    v = np.sort(np.asarray(vals)); m = len(v)
    if m == 0: return (np.nan, np.nan)
    k = max(1, int(np.ceil(frac * m)))
    if k >= m: return (v[0], v[-1])
    w = v[k - 1:] - v[:m - k + 1]
    i = int(np.argmin(w))
    return (v[i], v[i + k - 1])

def dxf_extent(path):
    """Stream the DXF, track min/max of 3DFACE vertex coords. Low memory."""
    mn = [1e18, 1e18, 1e18]; mx = [-1e18, -1e18, -1e18]; in3d = False; nfac = 0
    with open(path, 'r', errors='ignore') as f:
        prev = None
        for line in f:
            s = line.strip()
            if prev is None:
                prev = s; continue
            code, val = prev, s; prev = None
            if code == '0':
                if val.upper() == '3DFACE': in3d = True; nfac += 1
                else: in3d = False
            elif in3d:
                try:
                    ci = int(code); fv = float(val)
                except Exception:
                    continue
                axis = None
                if 10 <= ci <= 13: axis = 0
                elif 20 <= ci <= 23: axis = 1
                elif 30 <= ci <= 33: axis = 2
                if axis is not None and abs(fv) < 1e8:
                    if fv < mn[axis]: mn[axis] = fv
                    if fv > mx[axis]: mx[axis] = fv
    return mn, mx, nfac

for name, (ootp, dxfp) in CASES.items():
    d = open(ootp, 'rb').read()
    loc = locate(d)
    print(f'\n===== {name} =====')
    if loc is None:
        print('  could not locate coord section'); continue
    seed_off, coord_start, face_start = loc
    seeds = seeds_of(d, seed_off)
    fr = harvest_framed_fulls(d, coord_start, face_start, seeds)
    print(f'  seed_off {seed_off}  coord_start {coord_start}  face_start {face_start}')
    print(f'  seeds X/Y/Z: {[round(s,1) for s in seeds]}   framed FULL counts: {[len(fr[a]) for a in range(3)]}')
    mn, mx, nfac = dxf_extent(dxfp)
    labels = 'XYZ'
    # map decoder axis (0=nearest seed to X-magnitude, etc.) -> DXF axis by matching seed to extent
    for a in range(3):
        b = np.array(fr[a])
        if len(b) < 3:
            print(f'  axis{a} seed~{seeds[a]:.0f}: <3 FULLs, skip'); continue
        lo, hi = shorth(b); w = hi - lo
        band_lo, band_hi = lo - 5 * w, hi + 5 * w
        # which DXF axis does this seed belong to?
        da = int(np.argmin([abs(seeds[a] - (mn[k] + mx[k]) / 2) for k in range(3)]))
        te_lo, te_hi = mn[da], mx[da]
        covers = band_lo <= te_lo and band_hi >= te_hi
        raw_lo, raw_hi = b.min(), b.max()
        print(f'  axis{a}->DXF {labels[da]}: shorth[{lo:.1f}..{hi:.1f}] band(+-5w)[{band_lo:.1f}..{band_hi:.1f}] '
              f'vs TRUE[{te_lo:.1f}..{te_hi:.1f}]  covers={covers}  (raw FULL span [{raw_lo:.0f}..{raw_hi:.0f}])')
