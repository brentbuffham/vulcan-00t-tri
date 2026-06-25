#!/usr/bin/env python3
"""For each decoded vertex, look up its (X,Y) column in GT and report:
 - does the (X,Y) column exist at all?
 - how many Z values does GT have in that column?
 - is my decoded Z among them (within 0.02)?
 - if my Z is NOT there, what is the nearest GT Z in that column?
This separates 'wrong column (X/Y)' from 'wrong Z pairing'."""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]; N=int(sys.argv[3]) if len(sys.argv)>3 else 40
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
# build column index: (xkey,ykey) -> sorted list of zkeys
from collections import defaultdict
col=defaultdict(list)
for (xk,yk,zk) in GT: col[(xk,yk)].append(zk)
for k in col: col[k].sort()
print(f'GT columns (x,y): {len(col):,}')
TOL={0:0.30,1:0.30,2:0.02}
def snap(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v); cands=[]
    if i<len(a): cands.append(a[i])
    if i>0: cands.append(a[i-1])
    best=min(cands,key=lambda c:abs(c-v))
    return best if abs(best-v)<=TOL[ax] else None
def near(v,ax,tol=0.006):
    a=gt[ax]; i=np.searchsorted(a,v)
    if i<=0: return abs(a[0]-v)<tol
    if i>=len(a): return abs(a[-1]-v)<tol
    return min(abs(a[i]-v),abs(a[i-1]-v))<tol
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
pos=8328+24; n=0
while pos<geo_end and n<N:
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); pos+=1+nb
        if len(payload)!=nb or (payload and payload[0] in FULL_IND): continue
        cx=be(prev[0][:8-nb]+payload); cy=be(prev[1][:8-nb]+payload); cz=be(prev[2][:8-nb]+payload)
        if near(cx,0): ax,val=0,cx
        elif near(cy,1): ax,val=1,cy
        elif 511<=cz<=543: ax,val=2,cz
        else: continue
        prev[ax]=(prev[ax][:8-nb]+payload+b'\x00'*8)[:8]; cur[ax]=val
        if ax==2:
            sx=snap(cur[0],0); sy=snap(cur[1],1); sz=snap(cur[2],2)
            if sx is None or sy is None or sz is None:
                print(f'V{n:3d}  unsnappable'); n+=1; continue
            xk,yk,zk=round(sx*100),round(sy*100),round(sz*100)
            zs=col.get((xk,yk))
            if zs is None:
                # try neighbor X columns
                xi=np.searchsorted(gt[0],sx)
                alt=[]
                for dxi in (-1,1):
                    j=xi+dxi
                    if 0<=j<len(gt[0]):
                        ak=round(gt[0][j]*100)
                        if (ak,yk) in col: alt.append((gt[0][j],len(col[(ak,yk)])))
                print(f'V{n:3d}  X={sx} Y={sy} Z={sz}  COLUMN MISSING. neighborXcols={alt}')
            else:
                zarr=np.array(zs)
                nearest=zarr[np.argmin(np.abs(zarr-zk))]
                zok = min(abs(zarr-zk))<=2  # within 0.02
                print(f'V{n:3d}  X={sx} Y={sy} Z={sz}  col has {len(zs)} Zs  myZok={zok}  '
                      f'nearestGTz={nearest/100:.3f} (d={(nearest-zk)/100:+.3f})')
            n+=1
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
