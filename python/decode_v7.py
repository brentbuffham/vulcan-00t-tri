#!/usr/bin/env python3
"""decode_v7: CLEAN SEQUENTIAL framing [tag][sep][count][count+1 payload].
The v6 'b<=6' gate misframed every long record (count>6) and desynced the cycle.
Model from raw hex: vertex = [0x20:X][0x20:Y][0x60:Z]; 0x60 (short 3-byte) = Z and
marks vertex end. Carry unchanged axes. NO ground truth in decode; CSV scores only.
argv4 lone20=  'X' or 'Y'  (which axis a solitary 0x20 before a 0x60 fills)."""
import sys, struct, pickle
import numpy as np
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 26_222_853
LONE=sys.argv[4] if len(sys.argv)>4 else 'X'
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
FULL_IND=(0x40,0x41,0xC0,0xC1)
prev={0:bytearray(d[8328:8336]),1:bytearray(d[8336:8344]),2:bytearray(d[8344:8352])}
cur=[be(prev[0]),be(prev[1]),be(prev[2])]
decoded=set(); nverts=0
def apply(ax,payload,nb):
    if payload and payload[0] in FULL_IND:
        prev[ax][:]=payload[:8]+b'\x00'*max(0,8-nb)
        if nb>=8: prev[ax][:]=payload[:8]
        else: prev[ax][:]=payload+b'\x00'*(8-nb)
    else:
        prev[ax][:]=bytes(prev[ax][:8-nb])+payload if nb<=8 else payload[-8:]
    cur[ax]=be(prev[ax])
def emit():
    global nverts; nverts+=1
    sx=snap(cur[0],0); sy=snap(cur[1],1); sz=snap(cur[2],2)
    if None in (sx,sy,sz): return
    decoded.add((round(sx*100),round(sy*100),round(sz*100)))
emit()  # vertex 0 (seed)
pos=8352; group=[]  # list of (tag,payload,nb) for 0x20 records before a 0x60
def flush_group_and_z(zpay=None, znb=0):
    """assign accumulated 0x20 records to X then Y, optional Z, emit."""
    twenties=group
    if len(twenties)>=1: apply(0, twenties[0][1], twenties[0][2])  # X
    if len(twenties)>=2: apply(1, twenties[1][1], twenties[1][2])  # Y
    # extra 0x20s beyond 2: alternate (rare) -> apply to X,Y cyclically
    for k in range(2,len(twenties)):
        apply(k%2, twenties[k][1], twenties[k][2])
    if len(twenties)==1 and LONE=='Y':
        apply(1, twenties[0][1], twenties[0][2]); # redo as Y instead
    if zpay is not None: apply(2, zpay, znb)
    emit()
n20=n60=nother=0
while pos+3<=min(geo_end,BOUND):
    tag=d[pos]; sep=d[pos+1]; count=d[pos+2]; nb=count+1
    payload=bytes(d[pos+3:pos+3+nb]); pos=pos+3+nb
    if len(payload)!=nb: break
    cls=tag&0xE0
    if cls==0x60:           # Z + vertex end
        flush_group_and_z(payload, nb); group=[]; n60+=1
    elif cls==0x20:         # X or Y (by position)
        group.append((tag,payload,nb)); n20+=1
    else:                    # 0x40/0x80/0xC0/escape: treat as a 0x20-class fill for now
        group.append((tag,payload,nb)); nother+=1
if group: flush_group_and_z(None,0)
inter=decoded & GT
print(f'framing: 20-recs={n20:,} 60-recs(verts)={n60:,} other={nother:,}  emitted_verts={nverts:,}')
print(f'decoded(snap-valid)={len(decoded):,}  GT={len(GT):,}  matched={len(inter):,}  '
      f'RECALL={len(inter)/len(GT)*100:.2f}%  PREC={len(inter)/max(1,len(decoded))*100:.2f}%  [LONE={LONE}]')
