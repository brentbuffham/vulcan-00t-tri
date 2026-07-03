#!/usr/bin/env python3
"""Pi-free record<->triangle alignment: GT newness sequence (how many first-appearance
verts per tri, in DXF order) vs record features. If .00t face order == DXF order,
record structure should predict newness. Check counts first, then 1:1 prefix
correlation, then DP alignment allowing multi-tri records."""
import numpy as np
from collections import Counter

oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
dxf=r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'

lines=open(dxf,'r',errors='ignore').read().split('\n')
i=0;n=len(lines);tris_xyz=[];cur={};in3d=False
def fnum(s):
    try: return float(s)
    except: return None
while i<n-1:
    code=lines[i].strip(); val=lines[i+1].strip() if i+1<n else ''
    if code=='0':
        if in3d and len(cur)>=9: tris_xyz.append(cur.copy())
        in3d=(val.upper()=='3DFACE'); cur={}
    elif in3d:
        c=fnum(code); f=fnum(val)
        if c is not None and f is not None and abs(f)<1e8:
            ci=int(c)
            for k in range(4):
                if ci==10+k: cur[(k,0)]=f
                elif ci==20+k: cur[(k,1)]=f
                elif ci==30+k: cur[(k,2)]=f
    i+=2
vid={};gt_tris=[];newness=[]
for t in tris_xyz:
    tri=[];nn=0
    for k in range(3):
        p=(round(t[(k,0)],3),round(t[(k,1)],3),round(t[(k,2)],3))
        if p not in vid: vid[p]=len(vid);nn+=1
        tri.append(vid[p])
    gt_tris.append(tuple(tri));newness.append(nn)
newness=np.array(newness)
print('GT newness histogram:',dict(sorted(Counter(newness.tolist()).items())))
print('GT newness first 40:',newness[:40].tolist())

d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
feats=[]
for r in recs:
    pl=r[2:]; j=1 if pl[:1]==b'\x00' else 0
    nv=0
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl): nv+=1;j+=2
        elif b==0x01 and j+2<len(pl): nv+=1;j+=3
        else: j+=1
    start=pl[0] if pl else -1
    tag1=pl[1] if len(pl)>1 else -1
    feats.append((start,tag1,nv,len(r)))
print(f'\nrecords: {len(recs)}  GT tris: {len(gt_tris)}')
print('record start-byte histogram:',Counter(f[0] for f in feats).most_common(8))
print('first-tag (after 00 start) histogram:',Counter(f[1] for f in feats if f[0]==0).most_common(10))
# newness counts vs record-class counts
print('\ncounts to reconcile:')
print('  tris with nn=1:',int((newness==1).sum()),' nn=0:',int((newness==0).sum()),' nn>=2:',int((newness>=2).sum()))
print('  total new verts:',int(newness.sum()))
c1=Counter(f[1] for f in feats if f[0]==0)
print('  records tag1=0x60:',c1.get(0x60,0),' tag1=0x40:',c1.get(0x40,0),' tag1=0x42/43:',c1.get(0x42,0)+c1.get(0x43,0))
print('  records start=0x15:',sum(1 for f in feats if f[0]==0x15))
# 1:1 prefix test: does tag class predict newness at same index?
tagc=np.array([f[1] if f[0]==0 else 256+f[0] for f in feats])
L=min(len(tagc),len(newness))
for cls in [0x60,0x40,0x42,0x43,0x22,0x23,256+0x15]:
    m=tagc[:L]==cls
    if m.sum()>20:
        mean_nn=newness[:L][m].mean()
        print(f'  tag {cls if cls<256 else hex(cls-256)+"(start)"}: n={m.sum()} mean newness@same idx={mean_nn:.2f} (base {newness[:L].mean():.2f})')
