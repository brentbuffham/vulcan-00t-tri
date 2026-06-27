#!/usr/bin/env python3
"""Extract a point cloud from FULL-encoded .00t files. Inline FULL doubles carry TRUE
magnitude, so axis = magnitude band (no splice ambiguity). Auto-detect 3 bands, scan
geometry for band doubles, assemble vertices (one per axis, in stream order), write
XYZ + report bbox/count. Works for full-based files (intercepts/OB34); partial for
delta files. NO ground truth needed; bbox + shape = the verification."""
import sys, struct
import numpy as np
oot=sys.argv[1]; outxyz=sys.argv[2] if len(sys.argv)>2 else None
d=open(oot,'rb').read()
h=struct.unpack('<15i',d[0:60]); geo_end=h[11] if 8352<h[11]<=len(d) else len(d)
def be(o):
    try: return struct.unpack('>d',d[o:o+8])[0]
    except: return float('nan')
# pass1: collect all plausible coordinate doubles
raw=[]; o=8300
while o<geo_end-8:
    if d[o] in (0x40,0x41,0xc0,0xc1):
        v=be(o)
        if 1.0<abs(v)<1e7 and v==v:
            raw.append((o,v)); o+=8; continue
    o+=1
vals=np.array([v for _,v in raw])
print(f'{oot}\n plausible doubles={len(vals):,}')
if len(vals)<6: print(' too few'); sys.exit()
# pass2: cluster magnitudes into up to 3 bands by sorting gaps
av=np.sort(np.abs(vals))
# find 2 largest relative gaps to split into 3 bands
logs=np.log10(av+1); gaps=np.diff(logs); cut=np.argsort(gaps)[-2:]
edges=sorted([ (av[c]+av[c+1])/2 for c in cut ])
def band(v):
    a=abs(v)
    if len(edges)==2:
        if a<edges[0]: return 0
        if a<edges[1]: return 1
        return 2
    return 0
bands={0:[],1:[],2:[]}
for _,v in raw: bands[band(v)].append(v)
for b in range(3):
    arr=np.array(bands[b]) if bands[b] else np.array([0])
    print(f' band{b}: n={len(bands[b]):,} range[{arr.min():.2f},{arr.max():.2f}]')
# pass3: assemble vertices in stream order (flush when an axis repeats)
verts=[]; cur={}
for _,v in raw:
    b=band(v)
    if b in cur: verts.append(cur); cur={}
    cur[b]=v
if len(cur)==3: verts.append(cur)
full=[ (vv[0],vv[1],vv[2]) for vv in verts if len(vv)==3]
P=np.array(full)
print(f' assembled vertices(3-axis)={len(P):,}')
if len(P):
    print(f' bbox  band0[{P[:,0].min():.2f},{P[:,0].max():.2f}]  band1[{P[:,1].min():.2f},{P[:,1].max():.2f}]  band2[{P[:,2].min():.2f},{P[:,2].max():.2f}]')
    if outxyz:
        np.savetxt(outxyz, P, fmt='%.4f', delimiter=',')
        print(f' wrote {outxyz}')
