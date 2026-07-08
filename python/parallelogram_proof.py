#!/usr/bin/env python3
"""PROOF: is the .00t coordinate predictor the EdgeBreaker gate parallelogram?

GT (DXF faces) used for VERIFICATION ONLY -- never fed to a decoder. We test a
MECHANISM hypothesis: the encoder predicts each vertex from a neighbor triangle
across a shared edge as pred = A + B - C (parallelogram), storing low bits and
reconstructing the high byte from that prediction.

Test at the v11 DRIFT sites (yellow class: X/Y bit-exact, Z off by k*0.125m):
  - true Z is pinned (XY-nearest GT vertex, unique because XY exact)
  - compare, on Z, the error of:
      (a) our v11 DECODED Z            (known wrong here)
      (b) the PLANE oracle             (v11's surface stand-in: 3 XY-nearest GT)
      (c) the GATE PARALLELOGRAM       (A+B-C over the true mesh faces)
Z half-window = 0.0625 m: a predictor "wins" a site if |predZ-trueZ| < 0.0625
(then nearest-congruent snap recovers the exact value).

If (c) beats (b) -- especially on the ~85 sites the plane MISSES -- the encoder's
predictor is the gate parallelogram and cracking the faces closes the drift.
"""
import numpy as np
from scipy.spatial import cKDTree

DXF = r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'
DEC = r'C:/Users/brent/desktop/git/vulcan-00t-tri/python/P_v11_intercepts.npy'
HALF = 0.0625  # Z half-window (0.125 m byte-2 unit)

# ---- parse DXF: unique vertices + triangle index list (verification only) ----
lines = open(DXF, 'r', errors='ignore').read().split('\n')
i = 0; n = len(lines); tris = []; cur = {}; in3d = False
def fn(s):
    try: return float(s)
    except: return None
while i < n - 1:
    code = lines[i].strip(); val = lines[i + 1].strip() if i + 1 < n else ''
    if code == '0':
        if in3d and len(cur) >= 9: tris.append(cur.copy())
        in3d = (val.upper() == '3DFACE'); cur = {}
    elif in3d:
        c = fn(code); f = fn(val)
        if c is not None and f is not None and abs(f) < 1e8:
            ci = int(c)
            for k in range(4):
                if ci == 10 + k: cur[(k, 0)] = f
                elif ci == 20 + k: cur[(k, 1)] = f
                elif ci == 30 + k: cur[(k, 2)] = f
    i += 2
if in3d and len(cur) >= 9: tris.append(cur.copy())

verts = []; vindex = {}; faces = []
def vid(p):
    k = (round(p[0], 4), round(p[1], 4), round(p[2], 4))
    if k not in vindex: vindex[k] = len(verts); verts.append(k)
    return vindex[k]
for t in tris:
    cs = []
    for k in range(4):
        if (k, 0) in t and (k, 1) in t and (k, 2) in t:
            cs.append((t[(k, 0)], t[(k, 1)], t[(k, 2)]))
    uq = []
    for c in cs:
        if c not in uq: uq.append(c)
    if len(uq) >= 3: faces.append([vid(c) for c in uq[:3]])
G = np.array(verts)            # GT vertices
F = np.array(faces)            # GT triangle vertex-index triples
print(f'DXF: {len(G)} verts, {len(F)} triangles  (expected t=2v-4 -> {2*len(G)-4})')

# ---- edge -> tips (corner-table adjacency across shared edges) ----
from collections import defaultdict
edge_tips = defaultdict(list)   # (min,max vertex idx) -> [tip vertex idx, ...]
vert_faces = defaultdict(list)  # vertex idx -> [face idx, ...]
for fi, (a, b, c) in enumerate(F):
    edge_tips[(min(a, b), max(a, b))].append(c)
    edge_tips[(min(b, c), max(b, c))].append(a)
    edge_tips[(min(a, c), max(a, c))].append(b)
    for x in (a, b, c): vert_faces[x].append(fi)

def parallelogram_preds(d):
    """all gate-parallelogram predictions of vertex d from neighbor triangles
    across the edge opposite d in each incident face: pred = A + B - C."""
    preds = []
    for fi in vert_faces[d]:
        tri = F[fi]
        others = [x for x in tri if x != d]
        if len(others) != 2: continue
        a, b = others
        for c in edge_tips[(min(a, b), max(a, b))]:
            if c == d: continue                      # the neighbor tip, not d itself
            preds.append(G[a] + G[b] - G[c])
    return preds

# ---- global sanity: does parallelogram predict ALL vertices well? ----
best3d = []
for d in range(len(G)):
    ps = parallelogram_preds(d)
    if not ps: best3d.append(np.nan); continue
    e = np.linalg.norm(np.array(ps) - G[d], axis=1)
    best3d.append(e.min())
best3d = np.array(best3d)
ok = np.isfinite(best3d)
print(f'\n[ALL VERTS] best-gate parallelogram 3D residual: '
      f'median {np.nanmedian(best3d):.4f} m  '
      f'<half-window {np.mean(best3d[ok] < HALF)*100:.1f}%  '
      f'(interior verts {ok.sum()}/{len(G)})')

# ---- locate the v11 DRIFT (yellow) sites ----
P = np.load(DEC)
treeG = cKDTree(G); d3, _ = treeG.query(P)
treeXY = cKDTree(G[:, :2]); dxy, gi = treeXY.query(P[:, :2])
match = d3 < 0.25
yellow = (~match) & (dxy < 0.25)            # X/Y exact, Z wrong
yi = np.where(yellow)[0]
print(f'\n[DRIFT SITES] v11 yellow (X/Y-ok, Z-off): {len(yi)}')

# plane oracle (v11 stand-in): 3 XY-nearest GT verts, interpolate Z at (x,y)
def plane_oracle_Z(x, y):
    dd, idx = treeXY.query([[x, y]], k=3)
    idx = idx[0]
    p = G[idx]
    A, B, C = p[0], p[1], p[2]
    nrm = np.cross(B - A, C - A)
    if abs(nrm[2]) < 1e-9: return np.nan
    return A[2] - (nrm[0]*(x - A[0]) + nrm[1]*(y - A[1])) / nrm[2]

win_dec = win_plane = win_para = 0
para_e = []; plane_e = []; dec_e = []
plane_miss_para_win = 0; plane_miss = 0
for k in yi:
    gv = gi[k]                       # unique GT vertex (XY exact)
    trueZ = G[gv, 2]
    decZ = P[k, 2]
    # (c) gate parallelogram: best over incident neighbor triangles
    ps = parallelogram_preds(gv)
    pz = min((abs(p[2] - trueZ) for p in ps), default=np.inf)
    # (b) plane oracle
    ez = plane_oracle_Z(P[k, 0], P[k, 1])
    plz = abs(ez - trueZ) if np.isfinite(ez) else np.inf
    # (a) decoded
    dz = abs(decZ - trueZ)
    para_e.append(pz); plane_e.append(plz); dec_e.append(dz)
    win_dec += dz < HALF; win_plane += plz < HALF; win_para += pz < HALF
    if plz >= HALF:                  # plane MISSED this site
        plane_miss += 1
        if pz < HALF: plane_miss_para_win += 1
para_e = np.array(para_e); plane_e = np.array(plane_e); dec_e = np.array(dec_e)

print(f'\n  Z-error at drift sites (median m, and % within half-window {HALF} m):')
print(f'    (a) v11 DECODED       median {np.median(dec_e):.4f}   within {100*win_dec/len(yi):.1f}%')
print(f'    (b) PLANE oracle      median {np.median(plane_e[np.isfinite(plane_e)]):.4f}   within {100*win_plane/len(yi):.1f}%')
print(f'    (c) GATE PARALLELOGRAM median {np.median(para_e[np.isfinite(para_e)]):.4f}   within {100*win_para/len(yi):.1f}%')
print(f'\n  THE DECISIVE CHECK -- sites the PLANE misses ({plane_miss}):')
print(f'    gate parallelogram recovers {plane_miss_para_win}/{plane_miss} '
      f'({100*plane_miss_para_win/max(plane_miss,1):.1f}%) of them')
print(f'\n  Verdict: gate parallelogram {"BEATS" if win_para>win_plane else "does NOT beat"} '
      f'the plane stand-in on the drift class '
      f'({win_para} vs {win_plane} of {len(yi)} within half-window).')
