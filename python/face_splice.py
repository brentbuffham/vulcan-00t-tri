#!/usr/bin/env python3
"""V tokens as SPLICED vertex refs (like coord deltas): V2 sets 16-bit register,
V1 splices low byte. Test smoothness, range, coverage of resulting id stream."""
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
NV=2975
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
seq=[]  # (ri, kind, raw, spliced)
reg=0
for ri,r in enumerate(recs):
    pl=r[2:]; j=1 if pl[:1]==b'\x00' else 0
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl):
            reg=(reg&0xFF00)|pl[j+1]; seq.append((ri,'V1',pl[j+1],reg)); j+=2
        elif b==0x01 and j+2<len(pl):
            reg=(pl[j+1]<<8)|pl[j+2]; seq.append((ri,'V2',reg,reg)); j+=3
        elif b==0x15: j+=1
        elif 0xe0<=b<=0xff and j+2<len(pl): j+=3
        elif b>=0x20 and j+1<len(pl): j+=2
        else: j+=1
s=np.array([x[3] for x in seq])
print(f'spliced refs: {len(s)}  range {s.min()}..{s.max()}  <NV: {(s<NV).mean()*100:.1f}%')
dv=np.diff(s)
print(f'|dv| median={np.median(np.abs(dv)):.0f}  frac|dv|<=2: {(np.abs(dv)<=2).mean()*100:.0f}%  <=8: {(np.abs(dv)<=8).mean()*100:.0f}%  <=64: {(np.abs(dv)<=64).mean()*100:.0f}%')
print('top diffs:',Counter(dv.tolist()).most_common(15))
cov=len(set(s.tolist()))
print(f'distinct ids: {cov} of NV={NV}')
occ_per=Counter(Counter(s.tolist()).values())
print('occurrences-per-id histogram:',dict(sorted(occ_per.items())[:8]))
print('first 50 spliced:',s[:50].tolist())
