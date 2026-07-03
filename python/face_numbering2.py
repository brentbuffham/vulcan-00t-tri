#!/usr/bin/env python3
"""Numbering v2: gap-clustered columns, serpentine variants, PCA frames.
Score = median 3D distance between consecutive extracted face-record values
(correct numbering => a few metres; chance ~ 100+ m), plus edge%/tri%."""
import numpy as np

oot = r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
dxf = r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'

lines = open(dxf, 'r', errors='ignore').read().split('\n')
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
vid={};verts=[];gt_tris=[]
for t in tris_xyz:
    tri=[]
    for k in range(3):
        p=(round(t[(k,0)],3),round(t[(k,1)],3),round(t[(k,2)],3))
        if p not in vid: vid[p]=len(verts);verts.append(p)
        tri.append(vid[p])
    gt_tris.append(tuple(tri))
V=np.array(verts); NV=len(verts)
edges=set();triset=set()
for a,b,c in gt_tris:
    edges.update({frozenset((a,b)),frozenset((b,c)),frozenset((a,c))})
    triset.add(frozenset((a,b,c)))

d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
vals=[]
for ri,r in enumerate(recs):
    pl=r[2:]; j=1 if pl[:1]==b'\x00' else 0
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl): vals.append((ri,pl[j+1])); j+=2
        elif b==0x01 and j+2<len(pl): vals.append((ri,(pl[j+1]<<8)|pl[j+2])); j+=3
        else: j+=1
seq=[v for _,v in vals if v<NV]
print(f'{NV} v, {len(gt_tris)} t; values used: {len(seq)}')

def serpentine(order_axis_vals, along_vals, gap_thresh):
    """cluster columns on order_axis by sorted-gap > thresh; within col sort by along;
    returns list of perms: [normal, serpentine, serp-alt-phase]"""
    idx=np.argsort(order_axis_vals)
    sv=order_axis_vals[idx]
    brk=np.where(np.diff(sv)>gap_thresh)[0]
    cols=np.split(idx,brk+1)
    perms=[]
    for mode in ('plain','serp0','serp1'):
        out=[]
        for ci,col in enumerate(cols):
            c=col[np.argsort(along_vals[col])]
            if mode=='serp0' and ci%2==1: c=c[::-1]
            if mode=='serp1' and ci%2==0: c=c[::-1]
            out.append(c)
        perms.append((mode,len(cols),np.concatenate(out)))
    return perms

X,Y=V[:,0],V[:,1]
# PCA frame
C=V[:,:2]-V[:,:2].mean(0)
w,U=np.linalg.eigh(C.T@C)
P1=C@U[:,1]; P0=C@U[:,0]   # P1 = major axis

cands=[]
for axname,(oa,al) in {'X/Y':(X,Y),'Y/X':(Y,X),'P1/P0':(P1,P0),'P0/P1':(P0,P1)}.items():
    for g in (0.5,1.0,2.0):
        for mode,ncol,perm in serpentine(oa,al,g):
            cands.append((f'{axname} gap{g} {mode} ({ncol}c)',perm))
        for mode,ncol,perm in serpentine(-oa,al,g):
            cands.append((f'-{axname} gap{g} {mode} ({ncol}c)',perm))

print(f"\n{'candidate':34s} {'medD':>7s} {'edge%':>6s} {'tri%':>6s}")
best=[]
for name,perm in cands:
    if len(perm)!=NV: continue
    m=perm
    pos=V[m]
    a=np.array(seq[:-1]); b=np.array(seq[1:])
    dd=np.linalg.norm(pos[a]-pos[b],axis=1)
    medD=np.median(dd)
    pe=sum(1 for x,y in zip(seq,seq[1:]) if frozenset((m[x],m[y])) in edges)/(len(seq)-1)*100
    pt=sum(1 for x,y,z in zip(seq,seq[1:],seq[2:]) if frozenset((m[x],m[y],m[z])) in triset)/(len(seq)-2)*100
    best.append((medD,name,pe,pt))
best.sort()
for medD,name,pe,pt in best[:14]:
    print(f'{name:34s} {medD:7.1f} {pe:6.1f} {pt:6.1f}')
