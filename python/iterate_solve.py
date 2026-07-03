#!/usr/bin/env python3
"""Iterative constraint propagation solve.
State per token: committed (axis,value) or open. Start: fingerprint uniques + fulls.
Sweep L->R and R->L: for open tokens next to committed neighbors, filter candidates:
 - phase: neighbor axis +-1 (cycle)
 - locality: |w - nearest committed same-axis value within 6 tokens| < 60m
 - prefix-compat: bytes[0..k) of w match register estimate (rounded ok, cap 5)
Commit when exactly 1 candidate survives. Iterate. Then final segment decode for
the remainder + assembly + score."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
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
        toks.append(('F',d[pos:pos+8])); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb])); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
labels=np.load(sp+r'\fp2_labels.npy',allow_pickle=True)
axis=np.full(N,-1,dtype=int); value=np.full(N,np.nan)
for i,(t,l) in enumerate(zip(toks,labels)):
    if t[0]=='F':
        v=be(t[1]); axis[i]=band(v); value[i]=round(v,3)
    elif l[0]=='U':
        axis[i]=l[1]; value[i]=l[2]
print(f'initial committed: {(axis>=0).sum()}/{N}')

def candidates(i,phase_req=None,loc=None,LOC=60.0):
    t=toks[i]
    payload=t[1]; nb=len(payload); pI=int.from_bytes(payload,'big')
    cc=[]
    axes=range(3) if phase_req is None else [phase_req]
    for a in axes:
        base=u64[a]
        got=set()
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
                if loc is not None and loc[a] is not None:
                    ok &= np.abs(arr[jj2]-loc[a])<LOC
                for tgt in np.unique(jj2[ok]):
                    w=round(arr[tgt],3)
                    if w not in got:
                        got.add(w); cc.append((a,w,k))
    return cc

changed=True; it=0
while changed and it<12:
    it+=1; changed=False; ncommit=0
    for direction in (1,-1):
        rng=range(N) if direction==1 else range(N-1,-1,-1)
        # rolling last committed value per axis (within window)
        last=[None,None,None]; lastidx=[-99]*3
        for i in rng:
            if axis[i]>=0:
                last[axis[i]]=value[i]; lastidx[axis[i]]=i
                continue
            # phase requirement from nearest committed neighbor at distance delta
            ph=None
            j=i-direction
            if 0<=j<N and axis[j]>=0:
                ph=(axis[j]+direction)%3
            if ph is None: continue
            loc=[last[a] if abs(i-lastidx[a])<=9 else None for a in range(3)]
            cc=candidates(i,phase_req=ph,loc=loc)
            if len(cc)==1:
                a,w,k=cc[0]
                axis[i]=a; value[i]=w; ncommit+=1; changed=True
                last[a]=w; lastidx[a]=i
    print(f'iter {it}: committed {ncommit} (total {(axis>=0).sum()}/{N})')
# fill remaining by phase interpolation + best candidate
nfill=0
for i in range(N):
    if axis[i]>=0: continue
    ph=None
    if i>0 and axis[i-1]>=0: ph=(axis[i-1]+1)%3
    elif i+1<N and axis[i+1]>=0: ph=(axis[i+1]-1)%3
    cc=candidates(i,phase_req=ph) if ph is not None else candidates(i)
    if cc:
        # nearest to a local reference
        ref=None
        for j in range(i-1,max(-1,i-12),-1):
            if axis[j]>=0 and (ph is None or axis[j]==ph): ref=value[j]; break
        if ref is not None:
            cc.sort(key=lambda c:abs(c[1]-ref))
        a,w,k=cc[0]; axis[i]=a; value[i]=w; nfill+=1
print(f'filled {nfill}; final committed {(axis>=0).sum()}/{N}')
# assemble
cur=[None,None,None]; pts=[]
for i in range(N):
    if axis[i]<0: continue
    cur[axis[i]]=value[i]
    if axis[i]==2 and None not in cur: pts.append(tuple(cur))
P=np.array(pts)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print(f'assembled {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
print(f'  GT recall <2mm: {(d2<0.002).sum()}/{len(Gu)} ({(d2<0.002).mean()*100:.1f}%)')
with open(sp+r'\iterate_decoded.xyz','w') as f:
    for x,y,z in pts: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
np.save(sp+r'\iterate_axis.npy',axis); np.save(sp+r'\iterate_value.npy',value)
print('saved')
