#!/usr/bin/env python3
"""No column assumption. Parse groups (= records up to & incl a 0x60 refine) from
the coord start. For each group's two primaries A,B and the refine, splice onto
EACH axis running-prev and print all candidates, with the nearest GT vertex by 3D
search. Goal: identify which axis A and B encode and the refine's role."""
import sys, struct, pickle
import numpy as np
from collections import defaultdict
oot=sys.argv[1]; SP=sys.argv[2]
NG=int(sys.argv[3]) if len(sys.argv)>3 else 18
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
GT=pickle.load(open(f'{SP}/gt_keys.pkl','rb'))
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def splice(prevd,payload):
    keep=8-len(payload); raw=bytes(prevd[:keep])+bytes(payload)
    return struct.unpack('>d',raw[:8])[0]
def tobytes(v):
    return struct.pack('>d',v)
d=open(oot,'rb').read()
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
# running prev seeded from v0
prev=[bytearray(d[8328:8336]),bytearray(d[8336:8344]),bytearray(d[8344:8352])]
# parse tokens from 8352
toks=[]; pos=8328+24
while len(toks)<NG*8+20:
    b=d[pos]
    if b<=0x06: nb=b+1; toks.append(('C',nb,d[pos+1:pos+1+nb],pos)); pos+=1+nb
    elif is_sep(b): toks.append(('S',b,None,pos)); pos+=1
    elif (b&0xE0) in TAG_CLASSES: toks.append(('T',b,None,pos)); pos+=1
    else: toks.append(('?',b,None,pos)); pos+=1
# groups end at 0x60 coord
groups=[]; cur=[]; lasttag=0x20
for k,v,pl,p in toks:
    if k=='T': lasttag=v
    elif k=='C':
        cur.append((lasttag,pl,p))
        if (lasttag&0xE0)==0x60: groups.append(cur); cur=[]
    if len(groups)>=NG: break
def nearestGT(x,y,z):
    # search GT key set with tolerance via rounding to grid
    for tol in (0,1,2):
        k=(round(x*100),round(y*100),round(z*100))
        if k in GT: return k
    return None
for g in groups[:NG]:
    prim=[(t,pl,p) for (t,pl,p) in g if (t&0xE0)!=0x60]
    ref=[(t,pl,p) for (t,pl,p) in g if (t&0xE0)==0x60]
    line=f'@{g[0][2]}:'
    for nm,(t,pl,p) in zip('AB',prim[:2]):
        sx=splice(prev[0],pl); sy=splice(prev[1],pl); sz=splice(prev[2],pl)
        line+=f'  {nm}[{t:02x} {pl.hex()}] X={sx:.3f} Y={sy:.3f} Z={sz:.3f}'
    print(line)
