#!/usr/bin/env python3
"""Test: 2-byte face-record values = (vertexIndex<<k)|flags. Find k maximizing
consistency: (a) max(val>>k) ~ NV-1, (b) value-stream smoothness (|dv| small),
(c) 1-byte and 2-byte values share range."""
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
NV=2975
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
v1=[];v2=[]  # (ri, val)
for ri,r in enumerate(recs):
    pl=r[2:]; j=1 if pl[:1]==b'\x00' else 0
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl): v1.append((ri,pl[j+1])); j+=2
        elif b==0x01 and j+2<len(pl): v2.append((ri,(pl[j+1]<<8)|pl[j+2])); j+=3
        else: j+=1
a1=np.array([v for _,v in v1]); a2=np.array([v for _,v in v2])
print(f'1-byte values: {len(a1)}  range {a1.min()}..{a1.max()}')
print(f'2-byte values: {len(a2)}  range {a2.min()}..{a2.max()}')
for k in range(0,5):
    s=a2>>k
    inr=(s<NV).mean()*100
    print(f' shift {k}: 2B>>k max={s.max():6d}  p99={np.percentile(s,99):7.0f}  <NV: {inr:5.1f}%')
# low-3-bit distribution of 2-byte values
from collections import Counter
print('\n2-byte val & 7 histogram:', dict(sorted(Counter((a2&7).tolist()).items())))
print('2-byte val & 15 histogram:', dict(sorted(Counter((a2&15).tolist()).items())))
print('1-byte val & 7 histogram:', dict(sorted(Counter((a1&7).tolist()).items())))
# merged stream smoothness for shift k on 2B, raw 1B
merged={}
for k in (0,1,2,3):
    stream=[]
    i1=i2=0
    allv=sorted([(ri,0,val) for ri,val in v1]+[(ri,1,val) for ri,val in v2])
    for ri,typ,val in allv:
        stream.append(val if typ==0 else (val>>k))
    s=np.array(stream)
    dv=np.abs(np.diff(s))
    print(f'k={k}: merged |dv| median={np.median(dv):.0f}  p75={np.percentile(dv,75):.0f}  frac|dv|<=8: {(dv<=8).mean()*100:.0f}%')
