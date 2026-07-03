#!/usr/bin/env python3
"""Recover pi (.00t vertex id -> GT vertex id) by voting: DP-align parts to tris,
then each V-token value v in a part aligned to tri (a,b,c) votes pi[v] in {a,b,c}.
Report consistency, coverage, and the spatial structure of pi."""
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
        maxt=NT-k
        ts=np.arange(0,maxt+1)
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

votes=defaultdict(Counter)
nvt=0
for ri,t0,k in assign:
    parts=recparts[ri]
    if len(parts)!=k: continue  # clean records only
    for i2 in range(k):
        tri=gt[t0+i2]
        for tok in parts[i2]:
            if tok[0] in ('V1','V2'):
                votes[tok[1]][None]  # ensure key
                for g in tri: votes[tok[1]][g]+=1
                nvt+=1
print(f'V tokens voted: {nvt}, distinct v values: {len(votes)}')
pi={};amb=0;weak=0
for v,c in votes.items():
    del c[None]
    if not c: continue
    (g1,c1),*rest=c.most_common(2)
    if rest and rest[0][1]==c1: amb+=1;continue
    if c1<1: weak+=1;continue
    pi[v]=g1
print(f'pi resolved: {len(pi)} (ambiguous {amb})')
# consistency check: how often does each occurrence agree with pi?
agree=tot=0
for v,c in votes.items():
    if v in pi:
        s=sum(c.values());agree+=c[pi[v]];tot+=s
print(f'vote purity: {agree/tot*100:.1f}% (each v-occurrence containing pi[v])')
# injectivity
gcount=Counter(pi.values())
dups=sum(1 for g,c in gcount.items() if c>1)
print(f'pi injective? duplicate targets: {dups}/{len(pi)}')
# structure: pi sorted by v -> GT coordinates
vs=sorted(pi)
P=V[[pi[v] for v in vs]]
dstep=np.linalg.norm(np.diff(P,axis=0),axis=1)
print(f'spatial step |pos[pi[v_i+1]]-pos[pi[v_i]]|: median={np.median(dstep):.2f}m p90={np.percentile(dstep,90):.1f}m')
print('first 20 (v, GTid, x, y, z):')
for v in vs[:20]:
    g=pi[v];print(f'  v={v:4d} -> g={g:4d}  {V[g][0]:.2f} {V[g][1]:.2f} {V[g][2]:.2f}')
np.save('scratch_pi.npy',np.array([[v,pi[v]] for v in vs]))
