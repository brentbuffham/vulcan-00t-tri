#!/usr/bin/env python3
"""Extract 3DFACE triples from the intercepts DXF, map corners to GT vertex
indices (exact within tolerance), save faces_gt.npy (order = DXF entity order)."""
import re, numpy as np

dxf=r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'
gt=np.loadtxt(r'C:/Users/brent/AppData/Local/Temp/claude/C--Users-brent-desktop-git-vulcan-00t-tri/6045a728-103e-40d9-818d-ffe48c95ac26/scratchpad/intercepts_gt.csv',delimiter=',')
print('GT verts:',gt.shape)

txt=open(dxf,errors='ignore').read()
# split entities
faces=[]
for m in re.finditer(r'\n\s*0\r?\n3DFACE\r?\n(.*?)(?=\n\s*0\r?\n)',txt,re.S):
    body=m.group(1)
    pts={}
    for gm in re.finditer(r'\n\s*(1[0-3])\r?\n([-\d.eE+]+)\r?\n\s*(2\1[0-9]?)?',body):
        pass
    # simpler: pull group codes 10..13,20..23,30..33
    codes={}
    lines=[l.strip() for l in body.splitlines() if l.strip()]
    for i in range(0,len(lines)-1,1):
        if lines[i] in ('10','11','12','13','20','21','22','23','30','31','32','33'):
            try: codes.setdefault(lines[i],float(lines[i+1]))
            except ValueError: pass
    quad=[]
    for k in range(4):
        try:
            quad.append((codes[f'1{k}'],codes[f'2{k}'],codes[f'3{k}']))
        except KeyError:
            break
    faces.append(quad)
print('3DFACE entities:',len(faces))
# triangles: corner3 == corner2 typically
tri=[f[:3] if (len(f)<4 or f[3]==f[2]) else f for f in faces]
nquad=sum(1 for f in tri if len(f)==4)
print('true quads:',nquad)

# map to GT indices via rounding key
key={}
for i,(x,y,z) in enumerate(gt):
    key[(round(x,3),round(y,3),round(z,3))]=i
missing=0
fidx=[]
for f in tri:
    ids=[]
    for (x,y,z) in f[:3]:
        k=(round(x,3),round(y,3),round(z,3))
        if k in key: ids.append(key[k])
        else:
            # nearest fallback
            dd=np.sum((gt-np.array([x,y,z]))**2,axis=1)
            j=int(dd.argmin())
            if dd[j]<1e-4: ids.append(j)
            else: ids.append(-1); missing+=1
    fidx.append(ids)
fidx=np.array(fidx)
print('faces:',fidx.shape,'unmatched corners:',missing)
print('unique verts referenced:',len(np.unique(fidx[fidx>=0])))
np.save('faces_gt.npy',fidx)
print('first 20 faces:'); print(fidx[:20])
print('last 5 faces:'); print(fidx[-5:])
