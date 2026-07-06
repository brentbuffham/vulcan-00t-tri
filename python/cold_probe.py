#!/usr/bin/env python3
"""Probe cold .00t files: does the intercepts container layout (seeds @8326,
coord stream @8350, e0-03 face markers) generalize? Report per file so we know
whether decode_v7 can run unchanged or needs offset derivation. GT-free."""
import struct, sys
import numpy as np

FILES = {
    'intercepts': r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t',
    'SOLID_MM':   r'C:/Users/brent/Downloads/SOLID_MM_O31A_0504_8123.00t',
    'SYLVANIA':   r'C:/Users/brent/Downloads/eph_20170720_SYLVANIA_Surv_topo.00t',
    'OB34':       r'C:/Users/brent/Downloads/eph_20170820_OB34_Surv_Topo.00t',
}
def bed(b): return struct.unpack('>d', b)[0]

for name, path in FILES.items():
    d = open(path, 'rb').read(); n = len(d)
    geo_end = struct.unpack('<15i', d[0:60])[11]
    # e0-03 markers
    occ = [i for i in range(8326, min(n, geo_end) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
    face_start = n
    for k in range(len(occ) - 3):
        if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break
    # candidate seeds at 8326/8334/8342 (big-endian doubles)
    seeds = []
    for off in (8326, 8334, 8342):
        try:
            v = bed(d[off:off + 8]); seeds.append(v)
        except Exception:
            seeds.append(float('nan'))
    # scan a wider window 8240..8400 for the FIRST run of 3 coord-like doubles
    def coordlike(v): return np.isfinite(v) and 1 < abs(v) < 1e7
    first_triple = None
    for off in range(8240, 8400):
        vs = [bed(d[off + 8 * k:off + 8 * k + 8]) for k in range(3) if off + 8 * k + 8 <= n]
        if len(vs) == 3 and all(coordlike(v) for v in vs):
            first_triple = (off, vs); break
    print(f'\n=== {name} ===  size {n}  geo_end(dir[11]) {geo_end}')
    print(f'  e0-03 markers from 8326: {len(occ)}   face_start {face_start}')
    print(f'  seeds@8326/34/42 (BE dbl): {[round(s,2) if np.isfinite(s) else s for s in seeds]}')
    if first_triple:
        off, vs = first_triple
        print(f'  first coord-like triple @{off}: {[round(v,2) for v in vs]}')
    else:
        print('  no coord-like triple found in 8240..8400')
