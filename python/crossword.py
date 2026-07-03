#!/usr/bin/env python3
"""Crossword solver: per-token fingerprint candidate sets (axis,value,k) + Viterbi.
State = (rounded last value per axis, phase). Transition = pick candidate c=(a,w,k):
- prefix-compat: prev value on axis a must share bytes [0..k) with w (stable bytes only, cap 6)
- cycle prior: a == expected phase gets bonus; else penalty
- fulls: literal, reset axis value + phase
Score maximization via beam. Output: full (axis,value) sequence, vertex assembly,
GT triple score, and rule tables on the solved path."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
BEAM=200
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
vals=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
u64=[vals[a].copy().view(np.uint64) for a in range(3)]
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
# candidate sets (cached)
import os,pickle
CACHE=sp+r'\cands_cache.pkl'
if os.path.exists(CACHE):
    cands=pickle.load(open(CACHE,'rb'))
    print('loaded candidate cache')
else:
    cands=[]
    for t in toks:
        if t[0]=='F':
            v=be(t[1]); a=band(v)
            cands.append([('F',a,round(v,3),None)]); continue
        payload=t[1]; nb=len(payload); pI=int.from_bytes(payload,'big')
        cc=[]
        seen=set()
        for a in range(3):
            base=u64[a]
            for k in range(max(0,8-nb-3),8-nb+1):
                sh=8*(8-k-nb)
                mask=((1<<(8*nb))-1)<<sh
                cand=(base & ~np.uint64(mask)) | np.uint64(pI<<sh)
                vv=cand.view(np.float64)
                arr=vals[a]
                idx=np.searchsorted(arr,vv)
                for jj in (idx-1,idx):
                    jj2=np.clip(jj,0,len(arr)-1)
                    ok=np.abs(arr[jj2]-vv)<=0.0006
                    for tgt in np.unique(jj2[ok]):
                        key=(a,round(arr[tgt],3),k)
                        if key not in seen:
                            seen.add(key); cc.append(('V',a,round(arr[tgt],3),k))
        cands.append(cc)
    pickle.dump(cands,open(CACHE,'wb'))
    print('candidate cache saved')
sizes=[len(c) for c in cands]
print(f'candidate sets: median={int(np.median(sizes))} p90={int(np.percentile(sizes,90))} max={max(sizes)} empty={sum(1 for s in sizes if s==0)}')
def dbytes(v): return struct.pack('>d',v)
# beam
# state: (score, vx, vy, vz, phase)  values rounded floats (or None)
init=(0.0, round(be(d[8326:8334]),3), round(be(d[8334:8342]),3), round(be(d[8342:8350]),3), 0)
beam={(init[1],init[2],init[3],init[4]):(0.0,())}
for ti,(t,cc) in enumerate(zip(toks,cands)):
    nxt={}
    for (vx,vy,vz,ph),(sc,path) in beam.items():
        cur=[vx,vy,vz]
        if t[0]=='F':
            a=band(be(t[1])); w=round(be(t[1]),3)
            cur2=list(cur); cur2[a]=w
            key=(cur2[0],cur2[1],cur2[2],(a+1)%3)
            s2=sc+3.0
            if key not in nxt or nxt[key][0]<s2: nxt[key]=(s2,path+((a,w,'F'),))
            continue
        if not cc:
            key=(vx,vy,vz,(ph+1)%3)
            s2=sc-2.0
            if key not in nxt or nxt[key][0]<s2: nxt[key]=(s2,path+((None,None,'miss'),))
            continue
        for kind,a,w,k in cc:
            # prefix compat with current value on axis a
            compat=True
            if cur[a] is not None and k>0:
                pb=dbytes(cur[a]); wb=dbytes(w)
                kk=min(k,6)
                compat=pb[:kk]==wb[:kk]
            s2=sc+(3.0 if compat else -6.0)
            s2+= (1.5 if a==ph else -2.5)
            cur2=list(cur); cur2[a]=w
            ph2=(a+1)%3
            key=(cur2[0],cur2[1],cur2[2],ph2)
            if key not in nxt or nxt[key][0]<s2: nxt[key]=(s2,path+((a,w,k),))
        # miss option
        key=(vx,vy,vz,(ph+1)%3)
        s2=sc-2.0
        if key not in nxt or nxt[key][0]<s2: nxt[key]=(s2,path+((None,None,'miss'),))
    beam=dict(sorted(nxt.items(),key=lambda kv:-kv[1][0])[:BEAM])
    if (ti+1)%2000==0:
        bs=max(v[0] for v in beam.values()); print(f'  tok {ti+1}/{len(toks)} best={bs:.0f}')
bkey,bval=max(beam.items(),key=lambda kv:kv[1][0])
path=bval[1]
print(f'final score {bval[0]:.0f}')
# assemble vertices: emit on Z assignment
cur=[None,None,None]; pts=[]
axc=Counter(); missn=0
for a,w,k in path:
    if a is None: missn+=1; continue
    cur[a]=w; axc[a]+=1
    if a==2 and cur[0] is not None and cur[1] is not None:
        pts.append(tuple(cur))
print(f'axis counts: {dict(axc)}  miss: {missn}')
P=np.array(pts)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print(f'assembled {len(P)} vertices')
for tol in (0.002,0.01,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu) if len(P) else (None,None)
print(f'  GT recall <2mm: {(d2<0.002).sum()}/{len(Gu)} ({(d2<0.002).mean()*100:.1f}%)')
with open(sp+r'\crossword.xyz','w') as f:
    for x,y,z in pts: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
np.save(sp+r'\crossword_path.npy',np.array(path,dtype=object),allow_pickle=True)
print('saved')
