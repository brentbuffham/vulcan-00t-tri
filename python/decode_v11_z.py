#!/usr/bin/env python3
"""decode_v11_z -- v10 + SURFACE-PREDICTION reference for Z (GT-free).

Z_RECONSTRUCTION_HUNT finding: the yellow class (X/Y exact, Z off by k*0.125m
windows) is a WRONG-REFERENCE defect. GT-oracle: a plane through the 3
XY-nearest vertices predicts trueZ with median err 0.029m (463/548 yellow and
1052/1317 clean within the 0.0625m half-window); no stream byte carries k
(all correlations weak); last-Z / last-FULL / parallelogram-in-emission all
fail. The encoder references the SURFACE: at Z-decode time this vertex's X,Y
are already decoded, so the decoder can do the same from its OWN earlier
output (no GT): ref = plane fit through the 3 XY-nearest previously decoded
vertices (incremental grid index), fallback last-Z when degenerate/absent.
The hi bytes are then built FROM THE REF (not from R +-span), which also
recovers the far-dh onsets (|dh| up to 77 observed).

Usage: python decode_v11_z.py <case> [ZTH=0.5] [NPASS=3] [ZGATE=16]
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
ZTH = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
ZGATE = float(sys.argv[4]) if len(sys.argv) > 4 else 16.0
OOT, DXF = CASES[case]
d = open(OOT, 'rb').read(); n = len(d)
def be(b): return struct.unpack('>d', bytes(b))[0]

# ---- container location (identical to decode_v10_ref) ----
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
print(f'{case} (v11): seed_off {seed_off} coord_start {coord_start} face_start {face_start}  seeds {[round(s,1) for s in SEED]}')

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

# ---- value reconstruction (v10 core) ----
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
def unit3(R):
    """one byte-2 window at this register's exponent"""
    h = int.from_bytes(R[:3], 'big')
    if h + 1 >= (1 << 24): return 0.0
    R2 = (h + 1).to_bytes(3, 'big') + bytes(R[3:])
    return abs(be(R2) - be(R))
def ref_cands(R, payload, k0, a, ref_v):
    """hi bytes taken from REF (not R): candidates hi(ref)+dh, dh in -1..1,
    tail from R; in-band candidate nearest ref."""
    nb = len(payload); hb = k0
    if hb < 0 or k0 + nb > 8: return None
    tail = R[k0 + nb:]
    rb = struct.pack('>d', ref_v)
    hi = int.from_bytes(rb[:hb], 'big') if hb else 0
    best = None
    for dh in (-1, 0, 1):
        h2 = hi + dh
        if hb and not (0 <= h2 < (1 << (8 * hb))): continue
        if not hb and dh != 0: continue
        vb = (h2.to_bytes(hb, 'big') if hb else b'') + payload + tail
        v = be(vb)
        if not np.isfinite(v) or band(v) != a: continue
        dv = (abs(v - ref_v), abs(dh))
        if best is None or dv < best[0]: best = (dv, vb)
    return best if best else None
def r2_v11(R, payload, T, a, pred_v, prev_nb=None, zref=None, zconf=None):
    nb = len(payload)
    if nb == 0 or nb > 8: return None
    k0r = k0_rule(T, nb)
    if k0r + nb > 8: k0r = 8 - nb
    if nb == 5 and k0r == 2 and prev_nb == 6:   # Rule A (fold signature)
        k0r = 3
    last = be(R)
    if a == 2 and zref is not None:
        # v11 HYBRID: keep v10's nearest-to-last candidate UNLESS it disagrees
        # with the surface prediction by > ZTH window units at its EFFECTIVE
        # placement (plc2 windows are ~32 m, so plc2 records are automatically
        # protected -- distance-to-ref must never arbitrate PLACEMENT, cf.
        # REFERENCE_COLUMN_HUNT section 3). On disagreement rebuild hi FROM
        # the prediction at the same placement.
        cl = hi_cands(R, payload, k0r, a, last)
        k0e = k0r if cl is not None else (8 - nb)
        if cl is None and k0e != k0r:
            cl = hi_cands(R, payload, k0e, a, last)
        if cl is not None:
            vlb = bytearray(cl[1]); hb = k0e
            h = int.from_bytes(vlb[:hb], 'big') if hb else 0
            unit = 0.0
            if hb and h + 1 < (1 << (8 * hb)):
                v2 = bytearray(vlb); v2[:hb] = (h + 1).to_bytes(hb, 'big')
                unit = abs(be(bytes(v2)) - be(bytes(vlb)))
            # PLACEMENT FLIP (confidence-gated): an nb=5 record parsed at plc2
            # whose value sits far from a CONFIDENT surface, while the plc3
            # rebuild lands within one window of it, is a mis-placed fold
            # record (the plc3-truth class) -> flip.
            u3v = unit3(R)
            if (nb == 5 and k0e == 2 and u3v > 0 and zconf is not None
                    and zconf <= 1.0 * u3v
                    and abs(be(bytes(vlb)) - zref) > 4.0 * u3v):
                cf = ref_cands(R, payload, 3, a, zref)
                if cf is not None and abs(be(cf[1]) - zref) <= 1.0 * u3v:
                    return cf[1]
            if unit <= 0 or abs(be(bytes(vlb)) - zref) <= ZTH * unit:
                return cl[1]
            # CONFIDENCE GATE: only a self-consistent surface (IQR of the
            # plane ensemble <= 2 windows) may override the register-based
            # candidate. A corrupted/meaningless neighbourhood (wide IQR)
            # leaves v10 behaviour untouched.
            if zconf is None or (u3v > 0 and zconf > ZGATE * u3v):
                return cl[1]
        c1 = ref_cands(R, payload, k0r, a, zref)
        if c1 is not None: return c1[1]
        k0l = 8 - nb
        c2 = ref_cands(R, payload, k0l, a, zref) if k0l != k0r else None
        if c2 is not None: return c2[1]
        if cl is not None: return cl[1]
        # fall through to v10 chain if ref-construction leaves the band
    c1 = hi_cands(R, payload, k0r, a, last)
    k0l = 8 - nb
    c2 = hi_cands(R, payload, k0l, a, last) if k0l != k0r else None
    if c1 is not None: return c1[1]
    if c2 is not None: return c2[1]
    best = None
    for k0 in range(0, 8 - nb + 1):
        vb = spl(R, payload, k0)
        if vb is not None and band(be(vb)) == a:
            dv = abs(be(vb) - last)
            if best is None or dv < best[0]: best = (dv, vb)
    return best[1] if best else None

# ---- incremental XY grid for surface prediction (GT-free: own output only) ----
class Grid:
    def __init__(self):
        self.cell = None; self.g = {}; self.buf = []
    def _key(self, x, y): return (int(x // self.cell), int(y // self.cell))
    def set_cell(self, c):
        self.cell = max(c, 1e-3)
        for p in self.buf: self._ins(p)
        self.buf = []
    def _ins(self, p):
        self.g.setdefault(self._key(p[0], p[1]), []).append(p)
    def add(self, x, y, z, vi=-1, tr=0):
        if self.cell is None: self.buf.append((x, y, z, vi, tr))
        else: self._ins((x, y, z, vi, tr))
    def near(self, x, y, kmax=8):
        if self.cell is None: return []
        cx, cy = self._key(x, y)
        out = []
        for ring in range(0, 4):
            for i in range(cx - ring, cx + ring + 1):
                for j in range(cy - ring, cy + ring + 1):
                    if max(abs(i - cx), abs(j - cy)) != ring: continue
                    out.extend(self.g.get((i, j), ()))
            if len(out) >= kmax and ring >= 1: break
        if not out: return []
        arr = np.asarray(out)
        dd = np.hypot(arr[:, 0] - x, arr[:, 1] - y)
        o = np.argsort(dd)[:kmax]
        return [(dd[i], arr[i]) for i in o]

from itertools import combinations
_COMBOS = np.array(list(combinations(range(8), 3)))
def plane_ref(grid, x, y, exclude=None):
    """robust surface prediction from earlier decoded vertices: median of the
    plane-interpolations over all 3-subsets of the 8 XY-nearest (a minority of
    corrupted priors cannot move the median). Prefers ANCHOR vertices (Z from
    FULL / nb>=6 records -- byte 2 transmitted, essentially never broken).
    exclude = own vertex index (multi-pass grids contain the vertex itself)."""
    nb_ = grid.near(x, y, kmax=40)
    if exclude is not None:
        nb_ = [(dd, p) for (dd, p) in nb_ if int(p[3]) != exclude]
    if not nb_: return None
    anchors = [(dd, p) for (dd, p) in nb_ if p[4] > 0]
    nb_ = anchors[:8] if len(anchors) >= 4 else nb_[:8]
    d0, p0 = nb_[0]
    if d0 < 1e-6:
        return p0[2], 0.0                 # revisit of an existing XY: use its Z
    if len(nb_) < 3: return None
    pts = np.array([p for (dd, p) in nb_])[:, :3]
    k = len(pts)
    combos = _COMBOS[np.all(_COMBOS < k, axis=1)] if k < 8 else _COMBOS
    A, B, C = pts[combos[:, 0]], pts[combos[:, 1]], pts[combos[:, 2]]
    nrm = np.cross(B - A, C - A)          # plane normals
    dscale = max(nb_[min(2, k - 1)][0], 1e-6)
    span = np.maximum(np.linalg.norm(B[:, :2] - A[:, :2], axis=1),
                      np.linalg.norm(C[:, :2] - A[:, :2], axis=1))
    okm = np.abs(nrm[:, 2]) > 0.05 * dscale * span   # reject near-degenerate
    if not okm.any(): return None
    nrm, A2 = nrm[okm], A[okm]
    z = A2[:, 2] - (nrm[:, 0] * (x - A2[:, 0]) + nrm[:, 1] * (y - A2[:, 1])) / nrm[:, 2]
    z = z[np.isfinite(z)]
    if len(z) == 0: return None
    med = float(np.median(z))
    iqr = float(np.percentile(z, 75) - np.percentile(z, 25)) if len(z) >= 4 else 1e9
    return med, iqr

# ---- decode (multi-pass; pass>=2 uses previous pass's full surface,
#       still GT-free: it is the decoder's OWN output) ----
def decode(static_grid=None):
    regs = [bytearray(d[seed_off:seed_off + 8]), bytearray(d[seed_off + 8:seed_off + 16]), bytearray(d[seed_off + 16:seed_off + 24])]
    hist = [[be(regs[0])], [be(regs[1])], [be(regs[2])]]
    ph = 0; pts = [(be(regs[0]), be(regs[1]), be(regs[2]))]
    prev_nb = None
    grid = Grid(); steps = []; anch = [1]
    def commit_vertex(tr):
        x, y, z = be(regs[0]), be(regs[1]), be(regs[2])
        pts.append((x, y, z)); anch.append(tr)
        if len(pts) >= 2:
            px, py, _ = pts[-2]
            st = np.hypot(x - px, y - py)
            if np.isfinite(st) and st > 1e-9: steps.append(st)
        if grid.cell is None and len(steps) >= 50:
            grid.set_cell(2.0 * float(np.median(steps)))
        grid.add(x, y, z, len(pts) - 1, tr)
    grid.add(pts[0][0], pts[0][1], pts[0][2], 0, 1)
    for t in toks:
        if t[0] in ('F', 'Fe'):
            v = be(t[1]); a = band(v)
            if a < 0: continue
            regs[a][:] = t[1]; hist[a].append(be(regs[a]))
            if a == 2 and ph == 2: commit_vertex(1)
            ph = (a + 1) % 3; prev_nb = 8; continue
        payload = t[1]
        if len(payload) == 0: continue
        a = ph
        h = hist[a]
        pred = 2 * h[-1] - h[-2] if len(h) >= 2 else h[-1]
        if band(pred) != a: pred = h[-1]
        zref = None; zconf = None
        if a == 2:
            vi_next = len(pts)   # index this vertex will get
            zr = None
            if static_grid is not None:
                zr = plane_ref(static_grid, be(regs[0]), be(regs[1]), exclude=vi_next)
            if zr is None:
                zr = plane_ref(grid, be(regs[0]), be(regs[1]))
            if zr is not None and band(zr[0]) == 2:
                zref, zconf = zr
        vb = r2_v11(bytes(regs[a]), payload, t[2], a, pred, prev_nb, zref, zconf)
        if vb is not None: regs[a][:] = vb
        hist[a].append(be(regs[a]))
        if a == 2:
            nbz = len(payload)
            k0z = k0_rule(t[2], nbz)
            if k0z + nbz > 8: k0z = 8 - nbz
            if nbz == 5 and k0z == 2 and prev_nb == 6: k0z = 3
            commit_vertex(1 if (nbz >= 6 or (nbz == 5 and k0z == 2)) else 0)
        ph = (ph + 1) % 3; prev_nb = len(payload)
    return np.array(pts), np.array(anch), grid.cell

# (DXF parsed early for per-pass SCORING ONLY -- never feeds the decode)
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

P, ANCH, cell = decode()
print(f'pass1: decoded {len(P)} vertices  (grid cell {cell})  anchors {int(ANCH.sum())}')
NPASS = int(sys.argv[3]) if len(sys.argv) > 3 else 3
_scorers = [cKDTree(G)]
def _passscore(P):
    if not _scorers: return ''
    Gt = _scorers[0]
    dist, _ = Gt.query(P)
    return f'<0.25m {int((dist<0.25).sum())}/{len(P)} ({100*(dist<0.25).mean():.1f}%)'
for pn in range(2, NPASS + 1):
    sg = Grid(); sg.set_cell(cell if cell else 8.0)
    for vi in range(len(P)):
        sg.add(P[vi, 0], P[vi, 1], P[vi, 2], vi, int(ANCH[vi]))
    P, ANCH, _ = decode(static_grid=sg)
    print(f'pass{pn}: decoded {len(P)} vertices  {_passscore(P)}')
np.save(f'P_v11_{case}.npy', P)

# ---- score vs DXF (SCORING ONLY) ----
dist, _ = cKDTree(G).query(P)
dxy, _ = cKDTree(G[:, :2]).query(P[:, :2])
N = min(500, len(P))
m25 = dist < 0.25
yel = (~m25) & (dxy < 0.25)
print(f'[SCORING ONLY] GT verts {len(G)}  first{N} <0.25m {int((dist[:N]<0.25).sum())}/{N}')
print(f'[SCORING ONLY] <0.25m {int(m25.sum())}/{len(P)} ({100*m25.mean():.1f}%)   <1m {int((dist<1).sum())}/{len(P)} ({100*(dist<1).mean():.1f}%)   yellow(XYok,Zoff) {int(yel.sum())}')
