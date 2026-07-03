#!/usr/bin/env python3
"""GT distinct-value counts per axis + Y-row structure (intercepts)."""
import sys
import numpy as np
from collections import Counter
gtcsv=sys.argv[1] if len(sys.argv)>1 else r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
print('verts:',len(Gu))
for a,nm in enumerate('XYZ'):
    u=np.unique(np.round(Gu[:,a],3))
    print(nm,'distinct:',len(u))
ys=np.sort(np.unique(np.round(Gu[:,1],2)))
dy=np.diff(ys)
print('Y gaps>1m:',int((dy>1).sum()),' Y gaps>0.5m:',int((dy>0.5).sum()))
c=Counter(np.round(Gu[:,1],3).tolist())
sizes=sorted(c.values(),reverse=True)
print('largest same-Y groups:',sizes[:10],' total groups:',len(c))
cx=Counter(np.round(Gu[:,0],3).tolist())
sx=sorted(cx.values(),reverse=True)
print('largest same-X groups:',sx[:10],' total groups:',len(cx))
