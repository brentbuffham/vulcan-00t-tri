#!/usr/bin/env python3
"""Take ONE GT row (fixed Y) and compare to my decoded stream for that row.
 - Print GT (X sorted -> Z) pairs for the row.
 - Print my decoded X-values and Z-values (as ordered lists) while Y is on that row.
Separates: do the VALUE SETS match (value model right) vs is only the PAIRING off?"""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
YKEY=int(sys.argv[3]) if len(sys.argv)>3 else 21468475   # 214684.75
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
row=sorted([(xk,zk) for (xk,yk,zk) in GT if yk==YKEY])
print(f'GT row Y={YKEY/100}: {len(row)} columns')
print('  GT X (sorted):', [f'{xk/100:.3f}' for xk,_ in row][:40])
print('  GT Z (by X)  :', [f'{zk/100:.3f}' for _,zk in row][:40])
gtX=set(xk for xk,_ in row)
# decode stream, collect X and Z values while on this Y row
def near(v,ax,tol=0.006):
    a=gt[ax]; i=np.searchsorted(a,v)
    if i<=0: return abs(a[0]-v)<tol
    if i>=len(a): return abs(a[-1]-v)<tol
    return min(abs(a[i]-v),abs(a[i-1]-v))<tol
def snapx(v):
    a=gt[0]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    return min(c,key=lambda x:abs(x-v))
def be(raw): return struct.unpack('>d',(raw+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0); FULL_IND=(0x40,0x41,0xC0,0xC1)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytes(d[8328:8336]),1:bytes(d[8336:8344]),2:bytes(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
pos=8328+24
myX=[]; myZ=[]; curYkey=round(cur[1]*100); seq=[]
BOUND=26_000_000
while pos<min(geo_end,BOUND):
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
        if ax==1: curYkey=round(val*100)
        if curYkey==YKEY:
            if ax==0: myX.append(val); seq.append(('X',val))
            elif ax==2: myZ.append(val); seq.append(('Z',val))
        elif curYkey<YKEY-1:  # passed the row (Y decreasing? unknown) -- stop after we collected some
            if myX or myZ: break
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
print(f'\nMy decoded on row: {len(myX)} X-updates, {len(myZ)} Z-updates')
print('  my X:', [f'{v:.3f}' for v in myX][:40])
print('  my Z:', [f'{v:.3f}' for v in myZ][:40])
# multiset comparison of snapped X
mySX=set(round(snapx(v)*100) for v in myX)
print(f'\n  my distinct snapped X: {len(mySX)}   GT row X: {len(gtX)}   overlap: {len(mySX&gtX)}')
print('  GT X not in mine:', sorted([x/100 for x in (gtX-mySX)])[:15])
print('  mine not in GT  :', sorted([x/100 for x in (mySX-gtX)])[:15])
print('\n  interleave seq (first 50):', [(t,f'{v:.3f}') for t,v in seq][:50])
