#!/usr/bin/env python3
"""Map undecoded token ranges from closing_order.npy; locate them in the file,
check proximity to the e0 03 14 marker and anchor density inside."""
import struct
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
order=np.load(sp+r'\closing_order.npy',allow_pickle=True)
labels=np.load(sp+r'\fp2_labels.npy',allow_pickle=True)
N=len(labels)
covered=np.zeros(N,bool)
for vi,ti in order:
    covered[ti:ti+3]=True
runs=[];s=None
for i in range(N):
    if not covered[i] and s is None: s=i
    if covered[i] and s is not None: runs.append((s,i-1)); s=None
if s is not None: runs.append((s,N-1))
runs.sort(key=lambda r:r[0]-r[1])
tot=sum(b-a+1 for a,b in runs)
print(f'undecoded tokens: {tot}/{N} ({tot/N*100:.0f}%)  runs: {len(runs)}')
print('biggest 15 runs (tokStart,tokEnd,len,anchorsInside):')
for a,b in runs[:15]:
    na=sum(1 for i in range(a,b+1) if labels[i][0] in ('U','F'))
    print(f'  {a:5d}..{b:5d} len={b-a+1:4d} anchors={na}')
# token index near marker? count tokens before/after byte 70664: need token positions
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
print('marker byte 70664 tokens: (approximate token count to there)')
