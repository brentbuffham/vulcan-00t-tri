#!/usr/bin/env python3
"""Cycle-model test on beam2 path: condition axis TRANSITION (stay/fwd/back)
on preceding T-token byte1 class (hi-3 bits) and on mode. Only hit-verified
labels used. If 0x60-class => STAY and 0x20-class => advance, cycle model holds."""
import struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\beam2_path.npy'
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
vi=0;prev_axis=2;prev_ok=True
lastT=None
table=defaultdict(Counter)
table2=defaultdict(Counter)
for t in toks:
    if t[0]=='F':
        prev_axis=band(be(t[1])); prev_ok=True; lastT=None; continue
    if t[0]=='V':
        a,mode,ok=path[vi]
        if ok and prev_ok:
            trans=(a-prev_axis)%3  # 0 stay,1 fwd,2 back
            cls=(lastT[1][0]>>4) if lastT and lastT[0]=='T' else (-1 if lastT is None else -2)
            table[cls][trans]+=1
            table2[(cls,mode)][trans]+=1
        prev_axis=a; prev_ok=ok; vi+=1; lastT=None; continue
    if t[0] in ('T','E','S'): lastT=t if t[0]=='T' else lastT
print('T byte1 hi-nibble class -> axis transition (0=stay,1=fwd,2=back):')
for cls in sorted(table):
    c=table[cls];n=sum(c.values())
    nm={-1:'noT',-2:'E/S'}.get(cls,f'0x{cls:x}0')
    print(f'  {nm:5s}: n={n:5d}  stay={c[0]/n*100:4.0f}%  fwd={c[1]/n*100:4.0f}%  back={c[2]/n*100:4.0f}%')
print('\n(class,mode) -> transition:')
for key in sorted(table2,key=lambda k:-sum(table2[k].values()))[:12]:
    c=table2[key];n=sum(c.values())
    print(f'  {key}: n={n:5d}  stay={c[0]/n*100:4.0f}%  fwd={c[1]/n*100:4.0f}%  back={c[2]/n*100:4.0f}%')
