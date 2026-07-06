#!/usr/bin/env python3
"""RULE EXTRACTION on the first 500 vertices (decode_v6_clean, GT-free ranges).

For each broken vertex whose OTHER two axes are exact, the two exact axes pin the
true GT vertex -> we know the true value the wrong axis SHOULD have (no guessing).
Teacher-force: which (k0, carry) splice of the corrupting token produces that true
value? Cross-tab winners vs the current k0 rule by (T1-class, nb) to find the rule.
GT used ONLY as the teacher-forced target (labeled); never fed to the decoder.
"""
import struct
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

# ---- decode, capturing per-axis "write context" = (R_before, payload, T, nb, ttype) ----
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0
pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
ctx = {0: None, 1: None, 2: None}
provctx = [(None, None, None)]
for t in toks:
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]; ctx[a] = ('FULL', bytes(t[1]), t[2], None)
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            provctx.append((ctx[0], ctx[1], ctx[2]))
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    Rbefore = bytes(regs[a])
    vb = r2_value(Rbefore, payload, t[2], a)
    if vb is not None: regs[a][:] = vb
    ctx[a] = ('V', Rbefore, bytes(payload), t[2])
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        provctx.append((ctx[0], ctx[1], ctx[2]))
    ph = (ph + 1) % 3
P = np.array(pts)

# ---- score / pin (GT for TEACHER-FORCING target + scoring, labeled) ----
gt = np.loadtxt('intercepts_gt.csv', delimiter=','); Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu); dist, idx = kd.query(P)
N = min(500, len(P))

def pin_true(dec, wrong_axis, tol=0.5):
    """Pin the GT vertex by the two NON-wrong axes; return its coord on wrong_axis."""
    others = [x for x in range(3) if x != wrong_axis]
    m = np.ones(len(Gu), bool)
    for a in others:
        m &= np.abs(Gu[:, a] - dec[a]) < tol
    hit = np.where(m)[0]
    if len(hit) == 1:
        return Gu[hit[0], wrong_axis]
    return None

def t1class(T1):
    if T1 is None: return 'none'
    if 0x21 <= T1 <= 0x3F: return '21-3F'
    if 0x40 <= T1 <= 0x5F: return '40-5F'
    if T1 == 0x20: return '20'
    return f'{T1:02x}'
kdA = [cKDTree(Gu[:, [a]]) for a in range(3)]
EXACT_COUNTER = []; EXACT_DETAIL = defaultdict(Counter)
rows = []          # teacher-forced results
n_broken = n_pinned = n_explained = 0
for i in range(1, N):
    if dist[i] < 1.0: continue
    n_broken += 1
    dec = P[i]
    gaps = [float(kdA[a].query([[dec[a]]])[0][0]) for a in range(3)]
    wrong = int(np.argmax(gaps))
    # require the other two axes essentially exact (single-register drift)
    if sorted(gaps)[0] > 0.5 or sorted(gaps)[1] > 0.5:
        continue
    true_v = pin_true(dec, wrong)
    if true_v is None:
        continue
    n_pinned += 1
    c = provctx[i][wrong]
    if c is None or c[0] != 'V':
        rows.append((i, wrong, 'nonV', None, None, None)); continue
    _, Rbefore, payload, T = c
    nb = len(payload)
    rule_k0 = k0_rule(T, nb)
    # teacher-force: which (k0,c) hits true_v? Track EXACT (bit) vs approx(<1m).
    wins = []; exact_wins = []
    for k0 in range(0, 8 - nb + 1):
        for cc in (0, -1, 1, -2, 2, -3, 3, -4, 4):
            vb = spl(Rbefore, payload, k0, cc)
            if vb is not None:
                err = abs(be(vb) - true_v)
                if err < 1.0: wins.append((k0, cc, err))
                if err < 1e-6: exact_wins.append((k0, cc))
    EXACT_COUNTER.append(len(exact_wins))
    if exact_wins: EXACT_DETAIL[(t1class(T[0]) if T else 'none', nb)][exact_wins[0]] += 1
    if wins:
        n_explained += 1
        wins.sort(key=lambda x: x[2])
        wk0, wc, _ = wins[0]
        T1 = T[0] if T else None; T2 = T[1] if T else None
        rows.append((i, wrong, 'V', (T1, T2, nb), rule_k0, (wk0, wc)))
    else:
        T1 = T[0] if T else None; T2 = T[1] if T else None
        rows.append((i, wrong, 'V', (T1, T2, nb), rule_k0, None))

print(f'first {N}: correct {int((dist[:N]<1).sum())}  broken {n_broken}  '
      f'single-axis-pinned {n_pinned}  teacher-forced-explained {n_explained}')
print(f'  ({n_explained}/{n_pinned} of pinned single-axis breaks have a (k0,c) that hits the true value)\n')

# EXACT-hit verdict: is any of this a real (bit-exact) rule or search overfitting?
nexact = sum(1 for e in EXACT_COUNTER if e > 0)
print(f'EXACT (bit-for-bit) hits: {nexact}/{len(EXACT_COUNTER)} pinned single-axis breaks')
print(f'  exact-win detail (T1class,nb):(k0,carry)->count: {dict(EXACT_DETAIL)}\n')

# cross-tab: (T1-class, nb) -> rule_k0 vs winning k0
tab = defaultdict(Counter)
axcnt = Counter(); nbcnt = Counter()
for i, wrong, kind, feat, rk, win in rows:
    if kind != 'V' or win is None: continue
    T1, T2, nb = feat
    axcnt['XYZ'[wrong]] += 1; nbcnt[nb] += 1
    tab[(t1class(T1), nb)][(rk, win[0], win[1])] += 1
print('wrong-axis distribution:', dict(axcnt), '  nb distribution:', dict(nbcnt))
print('\ncross-tab  (T1class, nb) : {(rule_k0 -> win_k0, win_carry): count}')
for key in sorted(tab):
    print(f'  {key}: {dict(tab[key])}')

# carry check: are wins carry-free (real k0 rule) or carry-scattered (overfit)?
allwin = [win for *_, win in rows if win]
if allwin:
    ck = Counter(w[1] for w in allwin)
    print('\nwinning carry distribution (0 = pure k0, no carry):', dict(ck))
    kk = Counter(w[0] for w in allwin)
    print('winning k0 distribution:', dict(kk))
