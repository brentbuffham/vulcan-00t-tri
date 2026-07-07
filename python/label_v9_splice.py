#!/usr/bin/env python3
"""LABELING on v8b output, WHOLE FILE (intercepts + SYLVANIA).

Method (ruleextract_first500, upgraded):
 - decode with decode_v8_frame variant-b machinery, capturing per-axis write
   context (register-before, payload, T, token kind) at emission time
 - GT = full-precision DXF verts (NO rounding) -- used ONLY to label + score
 - for each broken vertex (>=1m): per-axis gaps via 1D KD trees; if exactly
   the two other axes are exact (<1e-6 ... use 0.5m fallback classing), pin
   the true 3rd value via 2D match on the two exact axes (unique within tol)
 - teacher-force: which (k0, carry) splice of the corrupting token hits the
   pinned true value BIT-EXACT (<1e-6 abs, DXF is 17 sig digits = exact)
 - cross-tab winners vs current k0_rule by (T1-class, nb, axis)

GT never fed to the decoder. Usage: python label_v9_splice.py <case>
"""
import struct, sys
import numpy as np
from collections import Counter, defaultdict
from scipy.spatial import cKDTree

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

# ---- container location (identical to decode_v8_frame) ----
geo_end = struct.unpack('<15i', d[0:60])[11]
def coordlike(v): return np.isfinite(v) and 1 < abs(v) < 1e7
seed_off = None
for off in range(8240, 8400):
    vs = [be(d[off + 8 * k:off + 8 * k + 8]) for k in range(3) if off + 8 * k + 8 <= n]
    if len(vs) == 3 and all(coordlike(v) for v in vs):
        seed_off = off; break
assert seed_off is not None
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
        if full_at(pos + 1) is not None:
            toks.append(('Fe', d[pos + 1:pos + 9], lastT, None, pos)); lastT = None
            pos += 9
            if pos < face_start and (d[pos] & 7) == 7: pos += 1
            continue
        if b < 0x20:
            nb = (b & 7) + 1; end = pos + 1 + nb
            if end > face_start: end = face_start
            toks.append(('V', d[pos + 1:end], lastT, b, pos)); lastT = None; pos = end; continue
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
band = make_band(TIGHT); toks = tokenize(make_full_at(band))

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
def r2(R, payload, T, a):
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

# ---- decode with context capture ----
regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
ctx = {0: None, 1: None, 2: None}
provctx = [(None, None, None)]
hist = {0: [be(regs[0])], 1: [be(regs[1])], 2: [be(regs[2])]}  # per-axis value history
for ti, t in enumerate(toks):
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]; ctx[a] = ('FULL', bytes(t[1]), None, None)
        hist[a].append(be(regs[a]))
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            provctx.append((ctx[0], ctx[1], ctx[2]))
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    Rbefore = bytes(regs[a])
    h = hist[a]
    last2 = h[-2] if len(h) >= 2 else h[-1]
    vb = r2(Rbefore, payload, t[2], a)
    if vb is not None: regs[a][:] = vb
    ctx[a] = ('V', Rbefore, bytes(payload), t[2], vb is not None, t[3], ti, last2)
    hist[a].append(be(regs[a]))
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        provctx.append((ctx[0], ctx[1], ctx[2]))
    ph = (ph + 1) % 3
P = np.array(pts)

def cand_pred(pred_v, payload):
    """placement-3 value: low len(payload) bytes = payload, high bytes chosen
    so the value is NEAREST pred_v. GT-free reconstruction."""
    nb = len(payload); hb = 8 - nb
    pb = struct.pack('>d', pred_v)
    hi = int.from_bytes(pb[:hb], 'big')
    best = None
    for dh in (-1, 0, 1):
        h2 = hi + dh
        if not (0 <= h2 < (1 << (8 * hb))): continue
        vb = h2.to_bytes(hb, 'big') + payload
        v = be(vb)
        if not np.isfinite(v): continue
        dv = abs(v - pred_v)
        if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None
print(f'{case} v8b: decoded {len(P)}')

# ---- GT full precision (LABEL + SCORE only) ----
def dxf_verts_full(path):
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
                try:
                    ci = int(code); fv = float(val)
                except Exception:
                    continue
                if abs(fv) < 1e8:
                    for base, ax in ((10, 0), (20, 1), (30, 2)):
                        if base <= ci <= base + 3: cur[(ci - base, ax)] = fv
    return np.array(list(seen))
G = dxf_verts_full(DXF)
kd = cKDTree(G); dist, _ = kd.query(P)
print(f'[SCORING] GT {len(G)}  full <1m {int((dist<1).sum())}/{len(P)} ({100*(dist<1).mean():.1f}%)')

# per-axis gaps, vectorized
kdA = [cKDTree(G[:, [a]]) for a in range(3)]
gaps = np.stack([kdA[a].query(P[:, [a]])[0] for a in range(3)], axis=1)  # (N,3)

broken = np.where(dist >= 1.0)[0]
broken = broken[broken > 0]
EX = 1e-6   # axis considered exact
sg = np.sort(gaps[broken], axis=1)
n_single = int(((sg[:, 0] < EX) & (sg[:, 1] < EX)).sum())
n_single_loose = int((sg[:, 1] < 0.5).sum())
n_multi = len(broken) - n_single_loose
print(f'broken {len(broken)}: single-axis(2 exact<1e-6) {n_single}  single-axis(loose<0.5) {n_single_loose}  multi/cascade {n_multi}')

# pin: for each wrong axis, 2D tree on the other two
pins = {}   # i -> (wrong, true_v)
for w in range(3):
    oth = [x for x in range(3) if x != w]
    tree2 = cKDTree(G[:, oth])
    cand = broken[(gaps[broken][:, oth[0]] < EX) & (gaps[broken][:, oth[1]] < EX) & (gaps[broken][:, w] >= 0.5)]
    if len(cand) == 0: continue
    dd, ii = tree2.query(P[np.ix_(cand, oth)], k=2)
    for j, i in enumerate(cand):
        if dd[j][0] < 1e-6:
            v1 = G[ii[j][0], w]
            if dd[j][1] < 1e-6 and abs(G[ii[j][1], w] - v1) > 1e-6:
                continue  # ambiguous pin
            pins[int(i)] = (w, v1)
print(f'pinned single-axis breaks: {len(pins)}')

# onset restriction: wrong axis was EXACT at vertex i-1 (clean Rbefore)
onset_pins = {}
for i, (w, true_v) in pins.items():
    if i - 1 >= 0 and gaps[i - 1, w] < EX and dist[i - 1] < 1.0:
        onset_pins[i] = (w, true_v)
print(f'onset pins (prev vertex correct AND prev wrong-axis exact): {len(onset_pins)}')

# teacher-force
def t1class(T1):
    if T1 is None: return 'none'
    if 0x21 <= T1 <= 0x3F: return '21-3F'
    if 0x40 <= T1 <= 0x5F: return '40-5F'
    if T1 == 0x20: return '20'
    return f'{T1:02x}'
def sext(payload):
    v = int.from_bytes(payload, 'big')
    if payload[0] & 0x80: v -= 1 << (8 * len(payload))
    return v

def analyze(pinset, tag):
    tab = defaultdict(Counter)
    n_nonV = n_noexact = n_exact = 0
    carry_dist = Counter(); k0_dist = Counter()
    dumps = []
    for i, (w, true_v) in sorted(pinset.items()):
        c = provctx[i][w]
        if c is None or c[0] != 'V':
            n_nonV += 1
            tab[('FULL', 0, 'XYZ'[w])]['nonV'] += 1
            continue
        _, Rbefore, payload, T, wrote, cb, ti, last2 = c
        nb = len(payload)
        rk = k0_rule(T, nb)
        if rk + nb > 8: rk = 8 - nb
        tb = struct.pack('>d', true_v)
        # free-form diagnostics
        placements = [k0 for k0 in range(0, 9 - nb) if tb[k0:k0 + nb] == payload]
        reg_int = int.from_bytes(Rbefore, 'big'); true_int = int.from_bytes(tb, 'big')
        adds = []
        for s in range(0, 9 - nb):
            shift = 8 * (8 - nb - s)
            if reg_int + (sext(payload) << shift) == true_int: adds.append(('+', s))
            if reg_int - (sext(payload) << shift) == true_int: adds.append(('-', s))
        exact_wins = []
        for k0 in range(0, 9 - nb):
            for cc in (0, -1, 1, -2, 2, -3, 3, -4, 4):
                vb = spl(Rbefore, payload, k0, cc)
                if vb is not None and abs(be(vb) - true_v) < 1e-6:
                    exact_wins.append((k0, cc))
        key = (f'b={cb:02x}', t1class(T[0]) if T else 'none', nb, 'XYZ'[w])
        if exact_wins:
            n_exact += 1
            wk0, wc = exact_wins[0]
            tab[key][(rk,) + tuple(exact_wins[0])] += 1
            carry_dist[wc] += 1; k0_dist[wk0 - rk] += 1
        else:
            n_noexact += 1
            tab[key]['NOEXACT'] += 1
        if len(dumps) < 60:
            # byte-2 (k0-1) delta needed, and full missing-byte diagnostics
            need = {}
            if 3 in placements:
                for bpos in range(0, 3 if nb == 5 else 8 - nb + 3):
                    pass
            d2 = (tb[2] - Rbefore[2]) if nb == 5 else None
            b7 = tb[7] if nb == 4 else None
            dumps.append((i, key, rk, exact_wins, placements, adds,
                          Rbefore.hex(), payload.hex(), tb.hex(),
                          T, d2, b7))
    print(f'\n=== {tag}: {len(pinset)} pins ===')
    print(f'teacher-force: exact {n_exact}  no-exact-win {n_noexact}  nonV(FULL ctx) {n_nonV}')
    print(f'winning carry dist: {dict(carry_dist)}')
    print(f'winning k0-rule_k0 delta dist: {dict(k0_dist)}')
    print('cross-tab (T1class, nb, axis): {(rule_k0, win_k0, win_c) | NOEXACT: n}')
    for key in sorted(tab, key=str):
        print(f'  {key}: {dict(tab[key])}')
    print('sample dumps:')
    for row in dumps:
        i, key, rk, ew, pl, ad, rh, ph_, th, T, d2, b7 = row
        Ts = f'{T[0]:02x},{T[1]:02x}' if T else 'None'
        extra = f' byte2: R={rh[4:6]} true={th[4:6]} d2={d2}' if d2 is not None else (f' true[7]={b7:02x}' if b7 is not None else '')
        print(f'  v{i} {key} T=({Ts}) rk={rk} wins={ew} plc={pl}{extra}\n      R={rh} pay={ph_} true={th}')
    return tab

analyze(onset_pins, 'ONSET pins (clean Rbefore)')
analyze({i: p for i, p in pins.items() if i not in onset_pins}, 'NON-onset pins (inherited suspects)')

# ---- placement census on CORRECT axis writes (labeled by GT, decode untouched) ----
# For every emitted vertex whose axis value is exact vs GT (gap<1e-6) and whose
# last write was a V token: where does the payload sit in the WRITTEN bytes?
# And what is the byte-2 delta (written[2]-Rbefore[2]) vs the T bytes?
print('\n=== placement census on CORRECT axis writes ===')
plc_tab = defaultdict(Counter)
d2_byT = defaultdict(Counter)
for i in range(1, len(P)):
    if dist[i] >= 1e-6: continue
    for a in range(3):
        c = provctx[i][a]
        if c is None or c[0] != 'V': continue
        _, Rbefore, payload, T, wrote, cb, ti, last2 = c
        if not wrote: continue
        nb = len(payload)
        wb = struct.pack('>d', P[i, a])
        placements = tuple(k0 for k0 in range(0, 9 - nb) if wb[k0:k0 + nb] == payload)
        key = (f'b={cb:02x}', t1class(T[0]) if T else 'none', nb, 'XYZ'[a])
        plc_tab[key][placements] += 1
        if nb == 5 and placements == (3,):
            d2 = wb[2] - Rbefore[2]
            d2_byT[(t1class(T[0]) if T else 'none')][(T[0] if T else None, T[1] if T else None, d2)] += 1
print('(T1class, nb, axis) -> {payload placements in written bytes: n}')
for key in sorted(plc_tab, key=str):
    print(f'  {key}: {dict(plc_tab[key].most_common(6))}')
print('\nnb=5 placement-3 correct writes: (T1, T2, byte2 delta) counts by class')
for cl in sorted(d2_byT):
    print(f'  {cl}: {dict(sorted(d2_byT[cl].items())[:40])}')

# ---- SEPARATION SCAN: placement-2 vs placement-3 within nb=5 cells ----
# pop A (label 0) = correct-axis writes, payload at bytes 2..6 of written value
# pop B (label 1) = correct-axis writes at 3..7  +  onset pins with plc=[3]
print('\n=== separation scan: nb=5 placement 2 vs 3 ===')
samples = []   # (label, feats dict)
rawsamples = []  # (label, ctx, axis, true_bytes)
def feats_of(c, a, i):
    _, Rbefore, payload, T, wrote, cb, ti, last2 = c
    f = {}
    f['T1'] = T[0] if T else -1
    f['T2'] = T[1] if T else -1
    f['T1lo5'] = (T[0] & 0x1f) if T else -1
    f['T2hi5'] = (T[1] >> 3) if T else -1
    f['T2hi'] = (T[1] >> 4) if T else -1
    f['T2bit3'] = ((T[1] >> 3) & 1) if T else -1
    f['cb'] = cb
    f['cbhi'] = cb >> 3
    f['axis'] = a
    f['p0hi'] = payload[0] >> 4
    f['p0'] = payload[0]
    f['R2'] = Rbefore[2]
    f['R7'] = Rbefore[7]
    f['p0_vs_R2'] = min(abs(payload[0] - Rbefore[2]), 256 - abs(payload[0] - Rbefore[2]))
    f['p0_vs_R3'] = min(abs(payload[0] - Rbefore[3]), 256 - abs(payload[0] - Rbefore[3]))
    # stream context
    tp = toks[ti - 1] if ti > 0 else None
    tn = toks[ti + 1] if ti + 1 < len(toks) else None
    f['prev_kind'] = {'F': 0, 'Fe': 1, 'V': 2, None: -1}.get(tp[0] if tp else None, 3)
    f['next_kind'] = {'F': 0, 'Fe': 1, 'V': 2, None: -1}.get(tn[0] if tn else None, 3)
    f['prev_nb'] = len(tp[1]) if tp and tp[0] == 'V' else -1
    f['next_nb'] = len(tn[1]) if tn and tn[0] == 'V' else -1
    f['prevV_cb'] = tp[3] if tp and tp[0] == 'V' else -1
    return f
for i in range(1, len(P)):
    if dist[i] >= 1e-6: continue
    for a in range(3):
        c = provctx[i][a]
        if c is None or c[0] != 'V' or not c[4]: continue
        payload = c[2]; nb = len(payload)
        if nb != 5: continue
        wb = struct.pack('>d', P[i, a])
        if wb[2:7] == payload:
            samples.append((0, feats_of(c, a, i))); rawsamples.append((0, c, a, wb))
        elif wb[3:8] == payload:
            samples.append((1, feats_of(c, a, i))); rawsamples.append((1, c, a, wb))
for i, (w, true_v) in onset_pins.items():
    c = provctx[i][w]
    if c is None or c[0] != 'V': continue
    payload = c[2]
    if len(payload) != 5: continue
    tb = struct.pack('>d', true_v)
    if tb[3:8] == payload:
        samples.append((1, feats_of(c, w, i))); rawsamples.append((1, c, w, tb))
    else:
        rawsamples.append((-1, c, w, tb))  # onset, placement unknown (large jump?)
n0 = sum(1 for l, _ in samples if l == 0); n1 = len(samples) - n0
print(f'pop A (plc2) {n0}   pop B (plc3) {n1}')
fkeys = samples[0][1].keys()
for fk in fkeys:
    # best single-threshold / value-set separation
    vals0 = Counter(f[fk] for l, f in samples if l == 0)
    vals1 = Counter(f[fk] for l, f in samples if l == 1)
    # value-set purity: assign each value to majority class, count agreement
    agree = 0
    for v in set(vals0) | set(vals1):
        agree += max(vals0.get(v, 0), vals1.get(v, 0))
    sep = agree / len(samples)
    flag = '  <<<<' if sep > 0.97 else ''
    print(f'  {fk:10s} sep {100*sep:5.1f}%{flag}')
# detail for the top features
for fk in fkeys:
    vals0 = Counter(f[fk] for l, f in samples if l == 0)
    vals1 = Counter(f[fk] for l, f in samples if l == 1)
    agree = sum(max(vals0.get(v, 0), vals1.get(v, 0)) for v in set(vals0) | set(vals1))
    if agree / len(samples) > 0.97:
        print(f'\n  DETAIL {fk}: plc2 {dict(sorted(vals0.items())[:24])}')
        print(f'           plc3 {dict(sorted(vals1.items())[:24])}')

# conditional scans within T1 groups
def t1grp(t1):
    if t1 == 0x20: return '20'
    if 0x21 <= t1 <= 0x3F: return '21-3F'
    if 0x40 <= t1 <= 0x5F: return '40-5F'
    return 'none'
for grp in ('20', '21-3F', '40-5F', 'none'):
    sub = [(l, f) for l, f in samples if t1grp(f['T1']) == grp]
    if not sub: continue
    m0 = sum(1 for l, _ in sub if l == 0); m1 = len(sub) - m0
    print(f'\n--- T1 group {grp}: plc2 {m0}  plc3 {m1} ---')
    if m0 == 0 or m1 == 0: continue
    best = []
    for fk in fkeys:
        vals0 = Counter(f[fk] for l, f in sub if l == 0)
        vals1 = Counter(f[fk] for l, f in sub if l == 1)
        agree = sum(max(vals0.get(v, 0), vals1.get(v, 0)) for v in set(vals0) | set(vals1))
        best.append((agree / len(sub), fk))
    best.sort(reverse=True)
    for sep, fk in best[:5]:
        print(f'  {fk:10s} sep {100*sep:5.1f}%')
    for sep, fk in best[:3]:
        vals0 = Counter(f[fk] for l, f in sub if l == 0)
        vals1 = Counter(f[fk] for l, f in sub if l == 1)
        print(f'  DETAIL {fk}: plc2 {dict(sorted(vals0.items()))}')
        print(f'            plc3 {dict(sorted(vals1.items()))}')

# ---- PRED-NEAREST CHOOSER evaluation (GT-free rule candidate) ----
# cand2 = splice at k0=2 (keep R[0:2] and R[7])   [current 21-3F behavior]
# cand3 = placement-3 with high bytes nearest pred, pred = 2*last - last2
# chooser: pick the candidate closest to pred. Score vs labels.
print('\n=== pred-nearest chooser on labeled nb=5 samples ===')
conf = Counter(); exact_hit = Counter(); pred_gap = defaultdict(list)
for label, c, a, tb in rawsamples:
    _, Rbefore, payload, T, wrote, cb, ti, last2 = c
    last = be(Rbefore)
    pred = 2 * last - last2
    c2 = spl(Rbefore, payload, 2)
    c3 = cand_pred(pred, payload)
    d2v = abs(be(c2) - pred) if c2 is not None else np.inf
    d3v = abs(be(c3) - pred) if c3 is not None else np.inf
    pick = 0 if d2v < d3v else 1
    picked = c2 if pick == 0 else c3
    conf[(label, pick)] += 1
    ok = picked == tb or abs(be(picked) - be(tb)) < 1e-6
    exact_hit[(label, pick, ok)] += 1
    if label >= 0: pred_gap[label].append((d2v, d3v))
print('confusion (true_label, picked):', dict(conf))
print('picked-value bit-exact vs truth (label, pick, exact):', dict(exact_hit))
# how decisive is the margin?
for l in (0, 1):
    g = np.array(pred_gap[l])
    if len(g):
        margin = np.log10(np.maximum(g[:, 1 - l], 1e-12) / np.maximum(g[:, l], 1e-12))
        print(f'label {l}: n={len(g)} margin(log10 other/own) min={margin.min():.2f} p5={np.percentile(margin,5):.2f} med={np.median(margin):.2f}')

# ---- raw byte neighborhoods of exception populations ----
print('\n=== raw neighborhoods (24 bytes before V lead .. record end) ===')
def show(c, lbl):
    _, Rbefore, payload, T, wrote, cb, ti, last2 = c
    pos = toks[ti][4]
    pre = d[max(0, pos - 24):pos].hex()
    rec = d[pos:pos + 1 + len(payload)].hex()
    print(f'  {lbl} tok{ti} pos{pos} pre={pre} | lead+pay={rec}')
def grp_of(c):
    T = c[3]
    if T is None: return 'none'
    return t1grp(T[0])
shown = Counter()
for label, c, a, tb in rawsamples:
    if label < 0: continue
    g = grp_of(c)
    kind = None
    if label == 1 and g == '21-3F' and shown['3in21'] < 10: kind = '3in21'
    elif label == 0 and g == '20' and shown['2in20'] < 10: kind = '2in20'
    elif label == 0 and g == '21-3F' and shown['2norm'] < 6: kind = '2norm'
    elif label == 1 and g == '20' and shown['3norm'] < 6: kind = '3norm'
    if kind:
        shown[kind] += 1
        show(c, f'{kind} ax={"XYZ"[a]}')
