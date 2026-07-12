"""Oracle: does using FACES topology (our decoded triangles) for the Z-surface
neighbours beat XY-nearest, on the yellow (XY-ok, Z-wrong) vertices?
This is the coord<->faces joint bootstrap the doc (Z_RECON §6) flagged as the
real path. GT positions used as MECHANISM oracle (stated) -- to decide if
wiring true topology into the Z predictor is worth it.
"""
import json, pickle
import numpy as np
from collections import defaultdict
from scipy.spatial import cKDTree

P = np.load('P_v11_intercepts.npy')          # v11 decoded (52%)
G = np.load('GT_intercepts.npy')             # GT verts (scoring/oracle)
map11, _ = pickle.load(open('map11.pkl', 'rb'))
df = json.load(open('decoded_faces_ext.json'))
tris = df['tris']; good = df['good']

# yellow = XY within 0.25 of a GT vert but Z off (in v11)
tree = cKDTree(G); dd, gi = tree.query(P)
treeXY = cKDTree(G[:, :2]); dxy, gixy = treeXY.query(P[:, :2])
yellow = (dd >= 0.25) & (dxy < 0.25)
print('v11 yellow verts:', int(yellow.sum()))

# face adjacency in SLOT space (only CORRECT-topology faces, GT-free topology)
adj = defaultdict(set)
for t, g in zip(tris, good):
    if not g:      # use only correct-topology faces as the trusted graph
        continue
    for a in t:
        for b in t:
            if a != b:
                adj[a].add(b)

# GT positions per slot (via map11)
def gpos(slot):
    v = map11.get(slot)
    return G[v] if v is not None else None

def plane_pred(nbrs, x, y):
    pts = np.array([p for p in nbrs if p is not None])
    if len(pts) < 3: return None
    best = []
    for i in range(len(pts)):
        for j in range(i+1, len(pts)):
            for k in range(j+1, len(pts)):
                A, B, C = pts[i], pts[j], pts[k]
                n = np.cross(B-A, C-A)
                if abs(n[2]) < 1e-6: continue
                z = A[2] - (n[0]*(x-A[0]) + n[1]*(y-A[1]))/n[2]
                best.append(z)
    return float(np.median(best)) if best else None

# XY-nearest GT neighbours (the current stand-in, oracle form)
gtXY = cKDTree(G[:, :2])
face_err = []; xy_err = []; both = 0
for s in range(len(P)):
    if not yellow[s]:
        continue
    v = map11.get(s)
    if v is None or s not in adj:
        continue
    gx, gy, gz = G[v]
    # face-neighbour plane (GT positions of topological neighbours)
    fn = [gpos(b) for b in adj[s]]
    fp = plane_pred(fn, gx, gy)
    # XY-nearest plane (8 nearest GT verts excluding self)
    dq, iq = gtXY.query([gx, gy], k=9)
    xn = [G[i] for i in iq if i != v][:8]
    xp = plane_pred(xn, gx, gy)
    if fp is not None and xp is not None:
        both += 1
        face_err.append(abs(fp - gz)); xy_err.append(abs(xp - gz))
face_err = np.array(face_err); xy_err = np.array(xy_err)
print('yellow verts with BOTH predictors (in a correct face):', both)
if both:
    hw = 0.0625
    print('median |err|: face-topology %.3f m  vs  XY-nearest %.3f m'
          % (np.median(face_err), np.median(xy_err)))
    print('within half-window (0.0625m): face %d/%d = %.0f%%   XY %d/%d = %.0f%%'
          % ((face_err<hw).sum(), both, 100*(face_err<hw).mean(),
             (xy_err<hw).sum(), both, 100*(xy_err<hw).mean()))
    print('within 0.25m: face %.0f%%   XY %.0f%%'
          % (100*(face_err<0.25).mean(), 100*(xy_err<0.25).mean()))
    print('face STRICTLY better than XY on: %d/%d' % ((face_err<xy_err).sum(), both))
