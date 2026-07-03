#!/usr/bin/env python3
"""Global phase-consistency test: for consecutive certain anchors (fingerprint
uniques + fulls), does (token-index delta) mod 3 == (axis delta) mod 3?
If ~100%: every token advances the cycle exactly once -> no splits/refines,
phase known EVERYWHERE by counting."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
labels=np.load(sp+r'\fp2_labels.npy',allow_pickle=True)
anch=[(i,l[1]) for i,l in enumerate(labels) if l[0] in ('U','F')]
print(f'anchors: {len(anch)}')
ok=0;bad=0;badlist=[]
for (i1,a1),(i2,a2) in zip(anch,anch[1:]):
    if (i2-i1)%3==(a2-a1)%3: ok+=1
    else:
        bad+=1
        if len(badlist)<15: badlist.append((i1,a1,i2,a2,(i2-i1)%3,(a2-a1)%3))
print(f'phase-consistent pairs: {ok}/{ok+bad} = {ok/(ok+bad)*100:.2f}%')
print('first inconsistent:',badlist)
# distribution of gap sizes for bad pairs
gaps=[i2-i1 for (i1,a1),(i2,a2) in zip(anch,anch[1:]) if (i2-i1)%3!=(a2-a1)%3]
print('bad-pair gap histogram:',Counter(gaps).most_common(10))
