#!/usr/bin/env python3
"""Characterize face records: (a) histogram of consecutive value diffs (row strides),
(b) record templates = hex skeleton with index values masked out, (c) values per record."""
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
NV=2975
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]

tmpl=Counter(); vals=[]; nvals_per_rec=Counter()
rec_vals=[]
for ri,r in enumerate(recs):
    pl=r[2:]; j=1 if pl[:1]==b'\x00' else 0
    skel=['00.' if pl[:1]==b'\x00' else '']
    rv=[]
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl):
            rv.append(pl[j+1]); skel.append('V1'); j+=2
        elif b==0x01 and j+2<len(pl):
            rv.append((pl[j+1]<<8)|pl[j+2]); skel.append('V2'); j+=3
        else:
            skel.append(f'{b:02x}'); j+=1
    tmpl[' '.join(skel)]+=1
    nvals_per_rec[len(rv)]+=1
    rec_vals.append(rv); vals.extend(rv)

print('values per record:', dict(sorted(nvals_per_rec.items())))
a=np.array([v for v in vals if v<NV])
dv=np.diff(a)
c=Counter(dv.tolist())
print('\ntop 25 consecutive-value diffs:', c.most_common(25))
print('\ntop 30 record templates:')
for t,n in tmpl.most_common(30):
    print(f'  {n:5d}  {t}')
