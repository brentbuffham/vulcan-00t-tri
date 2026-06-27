#!/usr/bin/env python3
"""Parse the intercepts DXF (ground truth). Extract 3DFACE triangles -> unique
vertices + faces. Report count, bbox, and TRUE nearest-neighbour spacing (answers the
~5 / ~8.5 m drill-pattern question directly). Save vertices for splice calibration."""
import sys
import numpy as np
from scipy.spatial import cKDTree
dxf=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'
out=sys.argv[2] if len(sys.argv)>2 else None
lines=open(dxf,'r',errors='ignore').read().split('\n')
i=0; n=len(lines); tris=[]; cur={}; in3d=False
def fnum(s):
    try: return float(s)
    except: return None
while i<n-1:
    code=lines[i].strip(); val=lines[i+1].strip() if i+1<n else ''
    if code=='0':
        if in3d and len(cur)>=9:
            # corners 0,1,2 (3 = dup of 2 for triangles)
            tris.append(cur.copy())
        in3d = (val.upper()=='3DFACE'); cur={}
    elif in3d:
        c=fnum(code); f=fnum(val)
        if c is not None and f is not None and abs(f)<1e8:
            ci=int(c)
            for k in range(4):
                if ci==10+k: cur[(k,0)]=f
                elif ci==20+k: cur[(k,1)]=f
                elif ci==30+k: cur[(k,2)]=f
    i+=2
if in3d and len(cur)>=9: tris.append(cur.copy())
# build vertex + face lists
verts=[]; faces=[]; vindex={}
def vid(p):
    k=(round(p[0],3),round(p[1],3),round(p[2],3))
    if k not in vindex: vindex[k]=len(verts); verts.append(k)
    return vindex[k]
for t in tris:
    corners=[]
    for k in range(4):
        if (k,0) in t and (k,1) in t and (k,2) in t:
            corners.append((t[(k,0)],t[(k,1)],t[(k,2)]))
    uniq=[]
    for c in corners:
        if c not in uniq: uniq.append(c)
    if len(uniq)>=3: faces.append(tuple(vid(c) for c in uniq[:3]))
V=np.array(verts)
print(f'3DFACE entities={len(tris):,}  triangles={len(faces):,}  unique vertices={len(V):,}')
print(f'bbox X[{V[:,0].min():.2f},{V[:,0].max():.2f}] Y[{V[:,1].min():.2f},{V[:,1].max():.2f}] Z[{V[:,2].min():.2f},{V[:,2].max():.2f}]')
print(f'extent: {np.ptp(V[:,0]):.1f} x {np.ptp(V[:,1]):.1f} x {np.ptp(V[:,2]):.1f} m')
t=cKDTree(V[:,:2]); dd,_=t.query(V[:,:2],k=2); nn=dd[:,1]; nn=nn[np.isfinite(nn)]
print(f'TRUE plan NN spacing: median={np.median(nn):.2f}m mean={nn.mean():.2f}m  %in[4,6]={np.mean((nn>=4)&(nn<=6))*100:.0f} %in[7,9]={np.mean((nn>=7)&(nn<=9))*100:.0f}')
h,e=np.histogram(nn[nn<15],bins=np.arange(0,15,0.5)); top=np.argsort(h)[-6:][::-1]
print(' top NN bins:', ', '.join(f'{e[i]:.1f}-{e[i]+0.5:.1f}:{h[i]}' for i in top))
print(' first 5 verts:', [tuple(round(x,3) for x in v) for v in V[:5]])
if out: np.savetxt(out,V,fmt='%.4f',delimiter=','); print(' wrote',out)
