#!/usr/bin/env python3
"""Voting v2: V2 tokens only (absolute refs?), tested at tri offsets -3..+3.
Also test V1 as relative backref: does (recent-vertex - V1) hit tri verts?"""
import numpy as np
from collections import Counter, defaultdict
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
vid={};verts=[];gt=[];nn=[]
for t in tris_xyz:
    tri=[];new=0
    for k in range(3):
        p=(round(t[(k,0)],3),round(t[(k,1)],3),round(t[(k,2)],3))
        if p not in vid: vid[p]=len(vid);verts.append(p);new+=1
        tri.append(vid[p])
    gt.append(tuple(tri));nn.append(new)
nn=np.array(nn);NT=len(gt);V=np.array(verts);NV=len(verts)
isNew=(nn>=1).astype(np.int8)
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
def tokenize(pl):
    toks=[];j=0
    if pl[:1]==b'\x00': j=1
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl): toks.append(('V1',pl[j+1]));j+=2
        elif b==0x01 and j+2<len(pl): toks.append(('V2',(pl[j+1]<<8)|pl[j+2]));j+=3
        elif b==0x15: toks.append(('X15',0,0));j+=1
        elif 0xe0<=b<=0xff and j+2<len(pl): toks.append(('E',b,pl[j+1],pl[j+2]));j+=3
        elif b>=0x20 and j+1<len(pl): toks.append((f'T{b>>5}',b,pl[j+1]));j+=2
        else: toks.append(('?',b,0));j+=1
    return toks
recparts=[]
for r in recs:
    toks=tokenize(r[2:])
    parts=[];curt=[]
    for t in toks:
        if t[0]=='E': parts.append(curt);curt=[t]
        else: curt.append(t)
    parts.append(curt)
    recparts.append(parts)
partV=[[1 if any(t[0] in ('V1','V2') for t in p) else 0 for p in parts] for parts in recparts]
R=len(recparts)
INF=np.int32(1<<28)
dp=np.full((R+1,NT+1),INF,dtype=np.int32)
bk=np.zeros((R+1,NT+1),dtype=np.int8)
dp[0,0]=0
for r in range(R):
    pv=partV[r];nparts=len(pv)
    row=dp[r];nrow=dp[r+1]
    for k in (1,2,3):
        ts=np.arange(0,NT-k+1)
        cost=np.zeros(len(ts),dtype=np.int32)
        for i2 in range(k):
            if i2<nparts: cost+=(pv[i2]!=isNew[ts+i2]).astype(np.int32)
            else: cost+=1
        cost+=max(0,nparts-k)
        cand=row[ts]+cost
        upd=cand<nrow[ts+k]
        nrow[ts+k]=np.where(upd,cand,nrow[ts+k])
        bk[r+1,ts[upd]+k]=k
r,t=R,NT;assign=[]
while r>0:
    k=int(bk[r,t]);assign.append((r-1,t-k,k));t-=k;r-=1
assign=assign[::-1]

# collect V2 occurrences with their aligned tri index
occs=[]  # (value, tri_index, kind)
for ri,t0,k in assign:
    parts=recparts[ri]
    if len(parts)!=k: continue
    for i2 in range(k):
        for tok in parts[i2]:
            if tok[0] in ('V1','V2'):
                occs.append((tok[0],tok[1],t0+i2))
print(f'clean V occurrences: {len(occs)} (V2: {sum(1 for k_,v,t_ in occs if k_=="V2")})')
for kind in ('V2','V1'):
    print(f'\n-- {kind} as ABSOLUTE id, purity by tri offset:')
    for dlt in range(-3,4):
        hit=tot=0
        for kk,v,ti in occs:
            if kk!=kind: continue
            tj=ti+dlt
            if 0<=tj<NT and v<NV:
                tot+=1
                if v in gt[tj]: hit+=1
        print(f'  d={dlt:+d}: {hit}/{tot} = {hit/max(tot,1)*100:.1f}%')
# V1 as relative: v vertices before the newest vertex so far
print('\n-- V1 as RELATIVE (newestVert - v), purity by tri offset:')
# newest vertex before tri t = count of verts introduced in tris[0..t-1]
intro=np.cumsum(nn)  # after tri t, intro[t] verts exist
for dlt in (-1,0,1):
    hit=tot=0
    for kk,v,ti in occs:
        if kk!='V1': continue
        tj=ti+dlt
        if 0<=tj<NT:
            ref=intro[tj-1]-1-v if tj>0 else -1
            tot+=1
            if ref>=0 and ref in gt[tj]: hit+=1
    print(f'  d={dlt:+d}: {hit}/{tot} = {hit/max(tot,1)*100:.1f}%')
