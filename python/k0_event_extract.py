#!/usr/bin/env python3
"""k0 event-site extractor (TEACHER-FORCED analysis; GT used for scoring/target only).

Re-runs the instrumented v5-P2 decode (drift_band_map machinery), finds bad bands
(err>10m, consecutive), and for EACH band-onset emitted point:
  - recomputes which axis has the largest |dec - gtNN| error (dominant-error axis)
  - finds the token that LAST wrote that axis register before emission (V or FULL)
  - TEACHER-FORCED: sweeps k0 in 0..8-nb and carry c in {0,+-1,+-2,+-3,+-4},
    splices payload into the PRE-token register value, and tests whether the
    result lands the emitted point <1m from a GT point AND/OR the spliced double
    equals the GT coordinate on that axis to 1e-9.
Then cross-tabs winning (k0,c) vs the decoder's actual choice, grouped by
feature signature (T1,T2,nb,payload[0],len,axis).  Prints a confusion table.

NOTHING here feeds the decoder; GT is target/label only.
"""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict

OOT = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
GTCSV = 'intercepts_gt.csv'

d = open(OOT, 'rb').read()
geo_end = struct.unpack('<15i', d[0:60])[11]
occ = [i for i in range(8326, len(d) - 2) if d[i] == 0xE0 and d[i + 1] == 0x03]
face_start = len(d)
for k in range(len(occ) - 3):
    if occ[k + 3] - occ[k] < 90: face_start = occ[k]; break


def be(b): return struct.unpack('>d', bytes(b))[0]
def sane(v):
    a = abs(v); return (500 < a < 1000) or (50000 < a < 60000) or (160000 < a < 166000)
def band(v):
    x = abs(v)
    if 500 < x < 1000: return 2
    if 50000 < x < 60000: return 0
    if 160000 < x < 166000: return 1
    return -1
def full_at(pos):
    if pos + 8 <= face_start and d[pos] in (0x40, 0x41, 0xC0, 0xC1):
        v = be(d[pos:pos + 8])
        if sane(v): return v
    return None


# --- tokenize (verbatim from drift_band_map, byte pos recorded) ---
toks = []; pos = 8350; lastT = None
while pos < face_start:
    b = d[pos]
    if b == 0 and pos + 6 <= face_start and d[pos:pos + 6] == b'\x00' * 6:
        while pos < face_start and d[pos] == 0: pos += 1
        continue
    if full_at(pos) is not None:
        toks.append(('F', d[pos:pos + 8], lastT, None, pos)); lastT = None; pos += 8; continue
    if b >= 0x20 and full_at(pos + 1) is not None:
        toks.append(('Fe', d[pos + 1:pos + 9], lastT, None, pos)); lastT = None; pos += 10; continue
    if b < 0x20:
        nb = (b & 7) + 1; end = pos + 1 + nb
        for j in range(pos + 1, min(end, face_start)):
            if full_at(j) is not None: end = j; break
        if end > face_start: end = face_start
        toks.append(('V', d[pos + 1:end], lastT, b, pos)); lastT = None; pos = end; continue
    if 0xe0 <= b <= 0xff and pos + 3 <= face_start: lastT = None; pos += 3; continue
    if pos + 2 <= face_start: lastT = (d[pos], d[pos + 1]); pos += 2; continue
    pos += 1


def k0_rule(T, nb):
    if T is not None:
        T1, T2 = T
        if 0x21 <= T1 <= 0x3F: return 2
        if 0x40 <= T1 <= 0x5F: return 3
        if T1 == 0x20: return 3 if T2 < 0x60 else 2
    return {4: 3, 5: 3, 6: 2}.get(nb, max(0, 8 - nb))
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
def r2_value_dbg(R, payload, T, a):
    """returns (vb, k0_used, c_used, path) reproducing r2_value's actual choice."""
    nb = len(payload)
    if nb == 0 or nb > 8: return None, None, None, 'nb'
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    vb = spl(R, payload, k0r)
    if vb is not None and band(be(vb)) == a: return vb, k0r, 0, 'rule'
    for c in (-1, 1, -2, 2, -3, 3, -4, 4):
        vb = spl(R, payload, k0r, c)
        if vb is not None and band(be(vb)) == a: return vb, k0r, c, 'rule+carry'
    pv = be(R); best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - pv)
            if best is None or dv < best[0]: best = (dv, vb, k0)
    if best: return best[1], best[2], 0, 'bruteband'
    return None, None, None, 'fail'


# --- run decode, tracking per-axis last-write source, snapshot at each emission ---
regs = [bytearray(d[8326:8334]), bytearray(d[8334:8342]), bytearray(d[8342:8350])]
ph = 0
pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
reg_src = [{'kind': 'init', 'ti': -1} for _ in range(3)]
snap = [[dict(s) for s in reg_src]]  # per emitted point: copy of reg_src for 3 axes
emit_ti = [-1]
for ti, t in enumerate(toks):
    if t[0] in ('F', 'Fe'):
        v = be(t[1]); a = band(v)
        if a < 0: continue
        regs[a][:] = t[1]
        reg_src[a] = {'kind': 'F', 'ti': ti, 'bytepos': t[4]}
        if a == 2 and ph == 2:
            pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
            snap.append([dict(s) for s in reg_src]); emit_ti.append(ti)
        ph = (a + 1) % 3; continue
    payload = t[1]
    if len(payload) == 0: continue
    a = ph
    pre_R = bytes(regs[a])
    vb, k0u, cu, path = r2_value_dbg(pre_R, payload, t[2], a)
    if vb is not None: regs[a][:] = vb
    reg_src[a] = {'kind': 'V', 'ti': ti, 'bytepos': t[4], 'pre_R': pre_R,
                  'payload': bytes(payload), 'T': t[2], 'nb': len(payload),
                  'k0': k0u, 'c': cu, 'path': path, 'lead': t[3]}
    if a == 2:
        pts.append((be(regs[0]), be(regs[1]), be(regs[2])))
        snap.append([dict(s) for s in reg_src]); emit_ti.append(ti)
    ph = (ph + 1) % 3
P = np.array(pts)

# --- score vs GT (scoring/target only) ---
gt = np.loadtxt(GTCSV, delimiter=',')
Gu = np.unique(gt, axis=0)
kd = cKDTree(Gu)
err, nn_idx = kd.query(P)
bad = err > 10.0
bands = []; i = 0
while i < len(P):
    if bad[i]:
        j = i
        while j + 1 < len(P) and bad[j + 1]: j += 1
        bands.append((i, j)); i = j + 1
    else:
        i += 1
onsets = [a for (a, b) in bands]

CARRIES = [0, -1, 1, -2, 2, -3, 3, -4, 4]

def teacher_force(pre_R, payload, a, target_axis_val, base_point):
    """sweep (k0,c); return best by |v-target| and 3D-land info."""
    nb = len(payload)
    best = None  # (errax, k0, c, v, dist3d, exact)
    for k0 in range(0, 8 - nb + 1):
        for c in CARRIES:
            vb = spl(pre_R, payload, k0, c)
            if vb is None: continue
            v = be(vb)
            if band(v) != a:  # must stay in correct axis band
                continue
            errax = abs(v - target_axis_val)
            cp = base_point.copy(); cp[a] = v
            dist3d = float(kd.query(cp)[0])
            exact = errax < 1e-9
            cand = (errax, k0, c, v, dist3d, exact)
            if best is None or errax < best[0]: best = cand
    return best

# --- per-site teacher-forced extraction ---
sites = []
n_full_written = 0
for oi in onsets:
    if oi == 0: continue
    p = P[oi]; g = Gu[nn_idx[oi]]
    diffs = np.abs(p - g)
    a = int(np.argmax(diffs))               # dominant-error axis
    src = snap[oi][a]
    if src['kind'] != 'V':
        n_full_written += 1
        sites.append({'oi': oi, 'axis': a, 'kind': src['kind'], 'explained': False,
                      'full_written': True})
        continue
    tf = teacher_force(src['pre_R'], src['payload'], a, g[a], p)
    T = src['T']
    T1 = T[0] if T else None
    T2 = T[1] if T else None
    explained = tf is not None and (tf[5] or tf[4] < 1.0 or tf[0] < 1.0)
    sites.append({
        'oi': oi, 'axis': a, 'kind': 'V',
        'nb': src['nb'], 'T1': T1, 'T2': T2, 'lead': src['lead'],
        'pay0': src['payload'][0], 'paylen': len(src['payload']),
        'dec_k0': src['k0'], 'dec_c': src['c'], 'dec_path': src['path'],
        'win_errax': None if tf is None else tf[0],
        'win_k0': None if tf is None else tf[1],
        'win_c': None if tf is None else tf[2],
        'win_dist3d': None if tf is None else tf[4],
        'win_exact': None if tf is None else tf[5],
        'explained': explained,
        'gap_ti': emit_ti[oi] - src['ti'],
        'full_written': False,
    })

n_sites = len(sites)
n_expl = sum(1 for s in sites if s['explained'])
n_v = sum(1 for s in sites if not s.get('full_written'))
print(f'total points {len(P)}  good(<1m) {(err<1).sum()}  bad(>10m) {bad.sum()}  bands {len(bands)}')
print(f'band-onset sites analyzed: {n_sites}')
print(f'  dominant-axis written by FULL/init (no k0 fix possible): {n_full_written}')
print(f'  dominant-axis written by a V token: {n_v}')
print(f'  V-sites EXPLAINED by some (k0,c) (<1m 3D or axis-exact): {n_expl}/{n_v}  ({100*n_expl/max(1,n_v):.1f}%)')
print(f'  V-sites explained of ALL onsets: {n_expl}/{n_sites}  ({100*n_expl/max(1,n_sites):.1f}%)')

# axis breakdown
axcnt = Counter(s['axis'] for s in sites)
axexp = Counter(s['axis'] for s in sites if s['explained'])
print(f'  by dominant axis (0=X,1=Y,2=Z): total {dict(axcnt)}  explained {dict(axexp)}')

# path breakdown of decoder's actual choice on V-sites
pathcnt = Counter(s['dec_path'] for s in sites if s['kind'] == 'V')
print(f'  decoder path on V-sites: {dict(pathcnt)}')

# gap_ti: was the corrupting write in THIS vertex cycle or earlier?
gaps = [s['gap_ti'] for s in sites if s['kind'] == 'V']
print(f'  write-to-emit token gap: median {np.median(gaps):.0f}  <=2: {sum(1 for x in gaps if x<=2)}/{len(gaps)}')

# =============== CONFUSION: decoder (k0,c) -> teacher-forced winner (k0,c) ==========
print('\n=== CONFUSION  decoder(k0,c) -> winner(k0,c)  [explained V-sites only] ===')
conf = Counter()
for s in sites:
    if s['kind'] != 'V' or not s['explained']: continue
    conf[((s['dec_k0'], s['dec_c']), (s['win_k0'], s['win_c']))] += 1
for (dc, wc), n in sorted(conf.items(), key=lambda x: -x[1]):
    flag = '' if dc == wc else '   <-- MISMATCH'
    print(f'  dec k0={dc[0]} c={dc[1]:+d}  ->  win k0={wc[0]} c={wc[1]:+d}   n={n}{flag}')

n_agree = sum(n for (dc, wc), n in conf.items() if dc == wc)
n_dis = sum(n for (dc, wc), n in conf.items() if dc != wc)
print(f'  agree {n_agree}  mismatch {n_dis}')

# =============== CROSS-TAB by feature signature (mismatches) =====================
# feature sig grouping for mismatches: does a deterministic rule fall out?
print('\n=== MISMATCH cross-tab by feature signature (T-class, nb, axis) ===')
def tclass(T1):
    if T1 is None: return 'noT'
    if 0x21 <= T1 <= 0x3F: return 'T1_21_3F'
    if 0x40 <= T1 <= 0x5F: return 'T1_40_5F'
    if T1 == 0x20: return 'T1_20'
    return f'T1_{T1:02x}'
sig = defaultdict(lambda: Counter())
for s in sites:
    if s['kind'] != 'V' or not s['explained']: continue
    if (s['dec_k0'], s['dec_c']) == (s['win_k0'], s['win_c']): continue
    key = (tclass(s['T1']), s['nb'], s['axis'])
    sig[key][((s['dec_k0'], s['dec_c']), (s['win_k0'], s['win_c']))] += 1
for key in sorted(sig, key=lambda k: -sum(sig[k].values())):
    tot = sum(sig[key].values())
    print(f'  {key}: n={tot}')
    for (dc, wc), n in sorted(sig[key].items(), key=lambda x: -x[1]):
        print(f'      dec(k0={dc[0]},c={dc[1]:+d}) -> win(k0={wc[0]},c={wc[1]:+d})  n={n}')

# =============== win distribution over ALL explained (agree+mismatch) ============
print('\n=== winner (k0,c) distribution over explained V-sites, by (T-class,nb) ===')
wd = defaultdict(lambda: Counter())
for s in sites:
    if s['kind'] != 'V' or not s['explained']: continue
    wd[(tclass(s['T1']), s['nb'])][(s['win_k0'], s['win_c'])] += 1
for key in sorted(wd, key=lambda k: -sum(wd[k].values())):
    tot = sum(wd[key].values())
    winners = sorted(wd[key].items(), key=lambda x: -x[1])
    dom = winners[0]
    print(f'  {key}: n={tot}  dominant win={dom[0]}({dom[1]})  all={dict(wd[key])}')

# how much would carry-only vs k0-only fixes explain?
k0_diff = sum(1 for s in sites if s['kind']=='V' and s['explained'] and s['win_k0']!=s['dec_k0'])
c_diff = sum(1 for s in sites if s['kind']=='V' and s['explained'] and s['win_c']!=s['dec_c'] and s['win_k0']==s['dec_k0'])
print(f'\nmismatch needing different k0: {k0_diff}   needing only different carry (same k0): {c_diff}')

# save sites for the rule-builder step
import pickle
pickle.dump(sites, open('k0_sites.pkl', 'wb'))
print('\nsaved k0_sites.pkl')
