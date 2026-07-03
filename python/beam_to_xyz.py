#!/usr/bin/env python3
"""Replay beam2 path -> decoded scalar stream -> naive point assembly for the
compare viewer: keep running X/Y/Z, emit a point on every Z update (cycle heuristic).
This is the HONEST current state: exact values where beam decoded them, wrong
grouping wherever the cycle heuristic is off."""
import struct
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\beam2_path.npy'
out=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\beam2_decoded.xyz'
path=np.load(sp,allow_pickle=True)
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
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8])); pos+=8; continue
    if b<=0x06 and pos+1+b+1<=face_start:
        toks.append(('V',d[pos+1:pos+1+b+1])); pos+=1+b+1; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3])); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2])); pos+=2; continue
    toks.append(('S',bytes([b]))); pos+=1
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
cur=[be(regs[0]),be(regs[1]),be(regs[2])]
pts=[tuple(cur)]
vi=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]; cur[a]=v
        if a==2: pts.append(tuple(cur))
        continue
    if t[0]!='V': continue
    a,mode,ok=path[vi]; vi+=1
    nb=len(t[1])
    if mode==0: vb=bytes(regs[a][:8-nb])+t[1]
    else: vb=bytes(regs[a][:8-nb-1])+t[1]+bytes(regs[a][7:])
    regs[a][:]=vb; cur[a]=be(vb)
    if a==2: pts.append(tuple(cur))
with open(out,'w') as f:
    for x,y,z in pts:
        f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print(f'wrote {len(pts)} points -> {out}')
