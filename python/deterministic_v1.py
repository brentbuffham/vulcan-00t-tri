#!/usr/bin/env python3
"""FIRST FULLY DETERMINISTIC DECODER (no GT in the loop):
- tokens: FULL=8-byte BE double (lead 40/41/C0/C1 + sane); V: prefix p<0x20 ->
  nb=(p&7)+1 payload bytes, depth=(p>>3); T (2B) and E (3B) tokens skipped.
- axis: strict X->Y->Z cycle; each V or FULL fills one slot. FULL of band b
  resyncs the cycle to b.
- splice: value = reg[:8-nb-depth] + payload + reg[8-depth:]; register update.
GT used ONLY for final scoring."""
import struct
import numpy as np
from scipy.spatial import cKDTree
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
out=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\det_v1.xyz'
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
slot=3
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        v=be(d[pos:pos+8]); fb=band(v)
        regs[fb][:]=d[pos:pos+8]
        slot=slot-(slot%3)+fb  # resync cycle to full's axis
        slot+=1
        if fb==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1; dep=b>>3
        payload=d[pos+1:pos+1+nb]
        a=slot%3
        if nb+dep<=8:
            regs[a][:8]=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
        slot+=1
        if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    pos+=1
P=np.array(pts)
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print(f'decoded vertices: {len(P)} (GT {len(Gu)})')
for tol in (0.002,0.01,0.1,1.0):
    print(f'  within {tol}m of GT: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,0.01,0.1,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(out,'w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote',out)
