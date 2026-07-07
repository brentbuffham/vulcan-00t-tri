#!/usr/bin/env python3
"""refhunt7 -- is skipped stream content (extra 2-byte tokens, 0xE0-class
3-byte groups) enriched immediately before BROKEN-onset V records?
LABELING ONLY (GT pins the broken set).
Usage: python refhunt7.py <case>
"""
import struct, sys
import numpy as np
sys.argv = [sys.argv[0]] + (sys.argv[1:] or ['intercepts'])
# reuse refhunt4 up to the decode loop (defs + toks + bands)
exec(open(__file__.replace('refhunt7', 'refhunt4')).read().split("# decode, recording")[0])

# retokenize WITH skip counters
def tokenize2(full_at):
    toks = []; pos = coord_start; lastT = None; n2 = 0; ne0 = 0
    while pos < face_start:
        b = d[pos]
        if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
            while pos < face_start and d[pos] == 0: pos += 1
            continue
        if full_at(pos) is not None:
            toks.append(('F', d[pos:pos + 8], lastT, None, n2, ne0)); lastT = None; n2 = ne0 = 0; pos += 8; continue
        if full_at(pos + 1) is not None:
            toks.append(('Fe', d[pos + 1:pos + 9], lastT, None, n2, ne0)); lastT = None; n2 = ne0 = 0
            pos += 9
            if pos < face_start and (d[pos] & 7) == 7: pos += 1
            continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            if end > face_start: end = face_start
            toks.append(('V', d[pos + 1:end], lastT, b, n2, ne0)); lastT = None; n2 = ne0 = 0; pos = end; continue
        if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; ne0 += 1; pos += 3; continue
        if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); n2 += 1; pos += 2; continue
        pos += 1
    return toks
toks2 = tokenize2(make_full_at(band))

# decode with v9 rule, tracking per-vertex-axis skip counts
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
skipinfo = [ {} ]; cur = {}
for t in toks2:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        cur[a] = (t[4], t[5], 'F')
        regs[a][:] = t[1]
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2]))); skipinfo.append(cur); cur = {}
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    cur[a] = (t[4], t[5], 'V')
    vb = r2_v9(bytes(regs[a]), payload, t[2], a, be(regs[a]))
    if vb is not None: regs[a][:] = vb
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2]))); skipinfo.append(cur); cur = {}
    ph = (ph + 1) % 3
P = np.array(pts)
from scipy.spatial import cKDTree
G = dxf_verts(DXF) if 'dxf_verts' in dir() else None
def dxf_verts2(path):
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
G = dxf_verts2(DXF)
dist, idx = cKDTree(G).query(P)
print(f'[SCORE] full <1m {int((dist<1).sum())}/{len(P)}')
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
            pins.append((i, wa)); break
onsets = [(i, wa) for (i, wa) in pins if dist[i - 1] < TOL]
print(f'pinned {len(pins)}, onsets {len(onsets)}')

# enrichment: skipped content before the wrong-axis record at onsets vs clean
def stats(rows, label):
    n2s = []; ne0s = []; anyskip = 0
    for (i, wa) in rows:
        si = skipinfo[i].get(wa)
        if si is None: continue
        n2s.append(si[0]); ne0s.append(si[1])
        if si[0] > 1 or si[1] > 0: anyskip += 1
    if n2s:
        print(f'{label}: n={len(n2s)}  mean 2-byte-skips {np.mean(n2s):.2f}  '
              f'mean e0-skips {np.mean(ne0s):.2f}  frac(>1 twobyte or e0) {anyskip/len(n2s):.3f}')
clean = [(i, a) for i in np.where(dist < TOL)[0] if i > 0 for a in range(3)]
import random
random.seed(2); clean = random.sample(clean, min(2000, len(clean)))
stats(onsets, 'BROKEN onsets ')
stats(pins,   'BROKEN all    ')
stats(clean,  'CLEAN control ')
