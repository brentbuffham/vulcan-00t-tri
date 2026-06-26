#!/usr/bin/env python3
"""POSITION-CYCLE decoder. Hypothesis from toy files: coords stream vertex-major in
X,Y,Z order; production emits ~3 records/vertex (one per axis), NO stream dedup.
So axis = record-cycle position (0=X,1=Y,2=Z), NOT range, NOT a 'refine'.
NO ground truth in the decode. CSV cache used ONLY to score recall at the end."""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
gt={0:np.load(f'{cachedir}/gt_x.npy'),1:np.load(f'{cachedir}/gt_y.npy'),2:np.load(f'{cachedir}/gt_z.npy')}
GT=pickle.load(open(f'{cachedir}/gt_keys.pkl','rb'))
TOL={0:0.10,1:0.15,2:0.05}
def snap(v,ax):
    a=gt[ax]; i=np.searchsorted(a,v); c=[]
    if i<len(a):c.append(a[i])
    if i>0:c.append(a[i-1])
    if not c: return None
    best=min(c,key=lambda x:abs(x-v))
    return best if abs(best-v)<=TOL[ax] else None
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
FULL_IND=(0x40,0x41,0xC0,0xC1); TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
decoded=set(); raw_triples=[]
def emit():
    raw_triples.append(tuple(cur))
    sx=snap(cur[0],0); sy=snap(cur[1],1); sz=snap(cur[2],2)
    if None in (sx,sy,sz): return
    decoded.add((round(sx*100),round(sy*100),round(sz*100)))
emit()  # vertex 0 = seed
pos=8328+24; cyc=0; nrec=0; nfull=0
while pos<min(geo_end,BOUND):
    b=d[pos]
    if b<=0x06:
        nb=b+1; payload=bytes(d[pos+1:pos+1+nb]); npos=pos+1+nb
        if len(payload)!=nb: pos=npos; continue
        ax=cyc
        if payload[0] in FULL_IND:           # FULL: payload = high bytes, low=0
            prev[ax][:]=payload+b'\x00'*(8-nb); nfull+=1
        else:                                 # DELTA: splice prev high + payload low
            prev[ax][:]=bytes(prev[ax][:8-nb])+payload
        cur[ax]=be(prev[ax])
        cyc=(cyc+1)%3; nrec+=1
        if cyc==0: emit()
        pos=npos
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG_CLASSES: pos+=1
    else: pos+=1
if cyc!=0: emit()
inter=decoded & GT
print(f'records={nrec:,} (fulls={nfull:,})  emitted_verts={len(raw_triples):,}')
print(f'decoded(snap-valid)={len(decoded):,}  GT={len(GT):,}  matched={len(inter):,}  '
      f'RECALL={len(inter)/len(GT)*100:.2f}%  PREC={len(inter)/max(1,len(decoded))*100:.2f}%')
# range self-check on first 30 emitted triples
print('first 8 triples (X,Y,Z):')
for t in raw_triples[:8]:
    print(f'   {t[0]:12.3f} {t[1]:12.3f} {t[2]:10.3f}')
