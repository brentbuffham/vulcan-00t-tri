#!/usr/bin/env python3
"""SELECTOR HUNT — find the hidden state that decides carry(-2) vs carry(0)
for token class T1=0x21..0x3F, nb=5 (the cleanest carry class).

GT (intercepts_gt.csv) is used ONLY to (a) pin the true value of the wrong
axis on single-axis breaks -> LABEL tokens NEEDS-CARRY vs CARRY-0, and
(b) score. It never feeds the decoder. Every candidate feature below is
computable from bytes the encoder emits.

Outputs a labeled feature table + per-feature separation report.
"""
import struct, sys
import numpy as np
from collections import Counter, defaultdict
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
(XL, XH), (YL, YH), (ZL, ZH) = derive_ranges()
def band(v):
    x = abs(v)
    if ZL <= x <= ZH: return 2
    if XL <= x <= XH: return 0
    if YL <= x <= YH: return 1
    return -1
def sane(v): return band(v) >= 0
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if sane(v): return v
    return None

# ---- tokenize, keeping file positions + last e0-class record ----
toks = []; pos = 8350; lastT = None; lastTpos = None
last_e0 = None; last_e0_pos = None; e0_count = 0
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    if full_at(pos) is not None:
        toks.append(('F', d[pos:pos + 8], lastT, None, pos, last_e0, e0_count, lastTpos))
        lastT = None; lastTpos = None; pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        toks.append(('Fe', d[pos + 1:pos + 9], lastT, None, pos, last_e0, e0_count, lastTpos))
        lastT = None; lastTpos = None; pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        toks.append(('V', d[pos + 1:end], lastT, b, pos, last_e0, e0_count, lastTpos))
        lastT = None; lastTpos = None; pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start:
        last_e0 = bytes(d[pos:pos + 3]); last_e0_pos = pos; e0_count += 1
        lastT = None; lastTpos = None; pos += 3; continue
    if pos + 2 <= face_start:
        lastT = (d[pos], d[pos + 1]); lastTpos = pos; pos += 2; continue
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

# ---- decode with rich per-write context ----
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0
pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
CTX = []                      # one entry per V/F write: dict of everything
ctx_idx = {0: None, 1: None, 2: None}
provctx = [(None, None, None)]
since_full = {0: 0, 1: 0, 2: 0}
emis_idx = {0: 0, 1: 0, 2: 0}
prev_tok_on_axis = {0: None, 1: None, 2: None}   # index into CTX
for ti, t in enumerate(toks):
    ttype, body, T, b, fpos, e0b, e0c, Tpos = t
    if ttype in ('F', 'Fe'):
        v = be(body); a = band(v)
        if a < 0: continue
        regs[a][:] = body
        since_full[a] = 0; emis_idx[a] += 1
        ctx_idx[a] = None
        prev_tok_on_axis[a] = None
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            provctx.append((ctx_idx[0], ctx_idx[1], ctx_idx[2]))
        ph = (a + 1) % 3; continue
    payload = body
    if len(payload) == 0: continue
    a = ph
    Rbefore = bytes(regs[a])
    vb = r2_value(Rbefore, payload, T, a)
    if vb is not None: regs[a][:] = vb
    since_full[a] += 1; emis_idx[a] += 1
    c = dict(tok_i=ti, vtx=len(pts), axis=a, T=T, b=b, nb=len(payload),
             payload=bytes(payload), Rbefore=Rbefore,
             emitted=bytes(regs[a]), fpos=fpos, raw_pre=bytes(d[max(0, fpos - 10):fpos]),
             e0=e0b, e0c=e0c, since_full=since_full[a], emis=emis_idx[a],
             prev_ax=prev_tok_on_axis[a], Tpos=Tpos)
    CTX.append(c); ctx_idx[a] = len(CTX) - 1
    prev_tok_on_axis[a] = len(CTX) - 1
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        provctx.append((ctx_idx[0], ctx_idx[1], ctx_idx[2]))
    ph = (ph + 1) % 3
P = np.array(pts)

# ---- GT: LABELING + SCORING ONLY ----
gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu); dist, idx = kd.query(P)
kdA = [cKDTree(Gu[:, [a]]) for a in range(3)]
print(f'decoded {len(P)}  correct<1m {int((dist < 1).sum())}  '
      f'[first500 {int((dist[:500] < 1).sum())}]  (GT scoring only)')

def pin_true(dec, wrong_axis, tol=0.5):
    others = [x for x in range(3) if x != wrong_axis]
    m = np.ones(len(Gu), bool)
    for a in others:
        m &= np.abs(Gu[:, a] - dec[a]) < tol
    hit = np.where(m)[0]
    if len(hit) == 1: return Gu[hit[0], wrong_axis]
    return None

CLS = lambda c: (c['T'] is not None and 0x21 <= c['T'][0] <= 0x3F and c['nb'] == 5)

rows = []   # (label, ctxindex, true_value)
n_pin = 0; other_wins = Counter(); nowin = 0
for i in range(1, len(P)):
    if dist[i] < 1.0:
        # correct vertex: every axis whose ctx is a class-token with primary
        # splice == emitted AND axis exact -> CARRY-0 exemplar
        g = Gu[idx[i]]
        for a in range(3):
            ci = provctx[i][a]
            if ci is None: continue
            c = CTX[ci]
            if not CLS(c): continue
            if abs(P[i][a] - g[a]) > 1e-6: continue
            vb0 = spl(c['Rbefore'], c['payload'], 2, 0)
            if vb0 is None or bytes(vb0) != c['emitted']: continue
            rows.append(('ZERO', ci, g[a]))
        continue
    # broken: single-axis + pinned?
    dec = P[i]
    gaps = [float(kdA[a].query([[dec[a]]])[0][0]) for a in range(3)]
    wrong = int(np.argmax(gaps))
    if sorted(gaps)[0] > 0.5 or sorted(gaps)[1] > 0.5: continue
    tv = pin_true(dec, wrong)
    if tv is None: continue
    ci = provctx[i][wrong]
    if ci is None: continue
    c = CTX[ci]
    if not CLS(c): continue
    n_pin += 1
    vbm2 = spl(c['Rbefore'], c['payload'], 2, -2)
    if vbm2 is not None and abs(be(vbm2) - tv) < 1e-6:
        rows.append(('NEED', ci, tv)); continue
    # exact win with something else?
    found = None
    for k0 in range(0, 4):
        for cc in (0, -1, 1, -2, 2, -3, 3, -4, 4):
            vb = spl(c['Rbefore'], c['payload'], k0, cc)
            if vb is not None and abs(be(vb) - tv) < 1e-6:
                found = (k0, cc); break
        if found: break
    if found: other_wins[found] += 1
    else: nowin += 1

nA = sum(1 for r in rows if r[0] == 'NEED'); nB = sum(1 for r in rows if r[0] == 'ZERO')
print(f'\nclass 21-3F nb=5:  NEED(-2)={nA}  ZERO={nB}  '
      f'(pinned class tokens={n_pin}, other exact wins={dict(other_wins)}, no exact win={nowin})')

# ---- feature extraction (ALL GT-free) ----
def feats(c, true_v):
    p = c['payload']; R = c['Rbefore']; T = c['T']
    f = {}
    f['T1'] = T[0]; f['T2'] = T[1]
    f['b'] = c['b']; f['b_hi'] = c['b'] >> 3
    f['p0'] = p[0]; f['p0_hi'] = p[0] >> 4; f['p0_par'] = p[0] & 1; f['p0_msb'] = p[0] >> 7
    f['p1'] = p[1]; f['p4'] = p[4]; f['p4_par'] = p[4] & 1
    f['r1'] = R[1]; f['r1_par'] = R[1] & 1; f['r1_lo2'] = R[1] & 3; f['r1_lonib'] = R[1] & 0xF
    f['r2'] = R[2]
    f['cmp_p0_r2'] = (p[0] > R[2]) - (p[0] < R[2])       # arithmetic borrow probe
    f['diff_p0_r2'] = (p[0] - R[2]) & 0xFF
    # low-6-byte unsigned compare: new low bytes (p + kept r7) vs old low bytes
    newlow = bytes(p) + R[7:8]; oldlow = R[2:8]
    f['cmp_low6'] = (newlow > oldlow) - (newlow < oldlow)
    f['e0_lo'] = (c['e0'][0] & 0x1F) if c['e0'] else -1
    f['e0_b1'] = c['e0'][1] if c['e0'] else -1
    f['e0_b2'] = c['e0'][2] if c['e0'] else -1
    f['since_full'] = c['since_full']; f['since_full_par'] = c['since_full'] & 1
    f['emis_par'] = c['emis'] & 1
    f['vtx_par'] = c['vtx'] & 1
    f['axis'] = c['axis']
    rp = c['raw_pre']
    f['pre1'] = rp[-1] if len(rp) >= 1 else -1   # == T2
    f['pre3'] = rp[-3] if len(rp) >= 3 else -1   # byte before the T-pair
    f['pre4'] = rp[-4] if len(rp) >= 4 else -1
    # previous same-axis token features
    pa = c['prev_ax']
    if pa is not None:
        pc = CTX[pa]
        f['pT1'] = pc['T'][0] if pc['T'] else -1
        f['pnb'] = pc['nb']
    else:
        f['pT1'] = -1; f['pnb'] = -1
    # value-side diagnostics (GT-derived; for understanding only, flagged DIAG)
    f['DIAG_dsign'] = int(np.sign(true_v - be(R)))
    return f

table = []
for lab, ci, tv in rows:
    table.append((lab, ci, feats(CTX[ci], tv)))

# ---- separation scan ----
print('\n--- per-feature separation (feature: value -> NEED/ZERO counts; best purity) ---')
featnames = sorted(table[0][2].keys())
report = []
for fn in featnames:
    cnt = defaultdict(lambda: [0, 0])
    for lab, ci, f in table:
        cnt[f[fn]][0 if lab == 'NEED' else 1] += 1
    # best achievable accuracy predicting label from this feature alone
    acc = sum(max(v) for v in cnt.values()) / len(table)
    report.append((acc, fn, dict(cnt)))
report.sort(reverse=True)
base = max(nA, nB) / len(table) if table else 0
print(f'baseline (majority class): {base:.3f}   n={len(table)}')
for acc, fn, cnt in report:
    tag = ' ***' if acc > base + 0.08 else ''
    small = {k: tuple(v) for k, v in sorted(cnt.items())[:14]}
    print(f'{fn:16s} acc={acc:.3f}{tag}  {small if len(cnt) <= 14 else f"({len(cnt)} values)"}')

# ---- detail dump for hand inspection ----
print('\n--- NEED tokens (full context) ---')
for lab, ci, f in table:
    if lab != 'NEED': continue
    c = CTX[ci]
    print(f"vtx{c['vtx']:5d} ax{c['axis']} T={c['T'][0]:02x},{c['T'][1]:02x} b={c['b']:02x} "
          f"pay={c['payload'].hex()} R={c['Rbefore'].hex()} pre={c['raw_pre'].hex()} "
          f"e0={c['e0'].hex() if c['e0'] else '--'} sf={c['since_full']} em={c['emis']} ds={f['DIAG_dsign']}")
print('\n--- ZERO tokens (first 40) ---')
z = 0
for lab, ci, f in table:
    if lab != 'ZERO': continue
    z += 1
    if z > 40: break
    c = CTX[ci]
    print(f"vtx{c['vtx']:5d} ax{c['axis']} T={c['T'][0]:02x},{c['T'][1]:02x} b={c['b']:02x} "
          f"pay={c['payload'].hex()} R={c['Rbefore'].hex()} pre={c['raw_pre'].hex()} "
          f"e0={c['e0'].hex() if c['e0'] else '--'} sf={c['since_full']} em={c['emis']} ds={f['DIAG_dsign']}")

np.save('selector_table.npy', np.array([(lab, ci) for lab, ci, _ in table], dtype=object), allow_pickle=True)
import pickle
with open('selector_ctx.pkl', 'wb') as fh:
    pickle.dump({'rows': rows, 'CTX': CTX}, fh)
print('\nsaved selector_ctx.pkl')
