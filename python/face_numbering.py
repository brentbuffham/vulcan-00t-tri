#!/usr/bin/env python3
"""Pin the .00t vertex numbering. Candidates: spatial sorts of GT verts (col-major
by X, row-major by Y, asc/desc). Score: fraction of consecutive extracted face-record
index pairs that form a GT edge under the candidate numbering, and fraction of
value-triples that form GT triangles."""
import sys
import numpy as np

oot = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
dxf = r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'

# ---- GT ----
lines = open(dxf, 'r', errors='ignore').read().split('\n')
i = 0; n = len(lines); tris_xyz = []; cur = {}; in3d = False
def fnum(s):
    try: return float(s)
    except: return None
while i < n - 1:
    code = lines[i].strip(); val = lines[i+1].strip() if i+1 < n else ''
    if code == '0':
        if in3d and len(cur) >= 9: tris_xyz.append(cur.copy())
        in3d = (val.upper() == '3DFACE'); cur = {}
    elif in3d:
        c = fnum(code); f = fnum(val)
        if c is not None and f is not None and abs(f) < 1e8:
            ci = int(c)
            for k in range(4):
                if ci == 10+k: cur[(k,0)] = f
                elif ci == 20+k: cur[(k,1)] = f
                elif ci == 30+k: cur[(k,2)] = f
    i += 2
vid = {}; verts = []; gt_tris = []
for t in tris_xyz:
    tri = []
    for k in range(3):
        p = (round(t[(k,0)],3), round(t[(k,1)],3), round(t[(k,2)],3))
        if p not in vid: vid[p] = len(verts); verts.append(p)
        tri.append(vid[p])
    gt_tris.append(tuple(tri))
V = np.array(verts); NV = len(verts)
# GT edges and tris as POSITION-id sets (ids = DXF first-appearance)
edges = set()
triset = set()
for a,b,c in gt_tris:
    edges.update({frozenset((a,b)), frozenset((b,c)), frozenset((a,c))})
    triset.add(frozenset((a,b,c)))
print(f'GT: {NV} v, {len(gt_tris)} t, {len(edges)} edges')

# ---- extracted values (clean: skip record-leading 00) ----
d = open(oot, 'rb').read()
occ = [i for i in range(8326, len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs = [d[occ[k]:occ[k+1]] for k in range(1, len(occ)-1)]
vals = []
for ri, r in enumerate(recs):
    pl = r[2:]; j = 1 if pl[:1] == b'\x00' else 0
    while j < len(pl):
        b = pl[j]
        if b == 0x00 and j+1 < len(pl): vals.append((ri, pl[j+1])); j += 2
        elif b == 0x01 and j+2 < len(pl): vals.append((ri, (pl[j+1]<<8)|pl[j+2])); j += 3
        else: j += 1
seq = [v for _,v in vals if v < NV]
print(f'clean values: {len(vals)} ({len(seq)} in range)')

# ---- candidate numberings: perm[k] = DXF-id of .00t vertex k ----
X, Y = V[:,0], V[:,1]
cands = {
 'dxf-order': np.arange(NV),
 'dxf-rev': np.arange(NV)[::-1],
 'X asc,Y asc': np.lexsort((Y, X)),
 'X asc,Y desc': np.lexsort((-Y, X)),
 'X desc,Y asc': np.lexsort((Y, -X)),
 'X desc,Y desc': np.lexsort((-Y, -X)),
 'Y asc,X asc': np.lexsort((X, Y)),
 'Y asc,X desc': np.lexsort((-X, Y)),
 'Y desc,X asc': np.lexsort((X, -Y)),
 'Y desc,X desc': np.lexsort((-X, -Y)),
}
print(f"\n{'candidate':16s} {'edge%':>6s} {'tri%':>6s}   (consecutive-pair edge rate; sliding triple tri rate)")
for name, perm in cands.items():
    m = perm  # ootIdx -> dxfId
    pe = sum(1 for a,b in zip(seq, seq[1:]) if frozenset((m[a], m[b])) in edges)
    pt = sum(1 for a,b,c in zip(seq, seq[1:], seq[2:]) if frozenset((m[a],m[b],m[c])) in triset)
    print(f'{name:16s} {pe/(len(seq)-1)*100:6.1f} {pt/(len(seq)-2)*100:6.1f}')
