#!/usr/bin/env python3
"""Answer-key stream alignment: oracle-decode scalar stream (axis,value,streamIdx);
for each GT vertex find the stream positions of its exact X, Y, Z values.
Reveals the interleave: distributions of (posY-posX), (posZ-posX); vertex order
by posX = the traversal order (pi)."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
gA=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
    if not np.isfinite(v): return False
    arr=gA[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return True
    return False
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
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8])); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb])); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    pos+=1
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
scal=[(0,be(regs[0])),(1,be(regs[1])),(2,be(regs[2]))]  # seeds
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]; scal.append((a,v)); continue
    payload=t[1]; nb=len(payload)
    done=False
    for a in range(3):
        for dep in range(0,4):
            if nb+dep>8: continue
            vb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
            if gt_hit(be(vb),a):
                regs[a][:]=vb; scal.append((a,be(vb))); done=True; break
        if done: break
    if done: continue
    for k2 in range(1,nb):
        h,tl=payload[:k2],payload[k2:]; f2=None
        for a in range(3):
            va=bytes(regs[a][:8-k2])+h
            if not gt_hit(be(va),a): continue
            for b2 in range(3):
                if b2==a: continue
                vb2=bytes(regs[b2][:8-(nb-k2)])+tl
                if gt_hit(be(vb2),b2): f2=(a,va,b2,vb2); break
            if f2: break
        if f2:
            a,va,b2,vb2=f2; regs[a][:]=va; regs[b2][:]=vb2
            scal.append((a,be(va))); scal.append((b2,be(vb2))); break
print(f'scalar stream: {len(scal)}')
# index by axis: value -> positions
from collections import defaultdict
posmap=[defaultdict(list) for _ in range(3)]
for i,(a,v) in enumerate(scal):
    posmap[a][round(v,3)].append(i)
# per GT vertex: unique positions?
dpos=[];amb=0;missing=0
for g in Gu:
    ps=[]
    ok=True
    for a in range(3):
        cand=posmap[a].get(round(g[a],3),[])
        if len(cand)==1: ps.append(cand[0])
        elif len(cand)==0: ok=False;missing+=1;break
        else: ok=False;amb+=1;break
    if ok: dpos.append((ps[0],ps[1],ps[2]))
print(f'GT verts uniquely located: {len(dpos)}  ambiguous: {amb}  missing-scalar: {missing}')
dp=np.array(dpos)
dyx=dp[:,1]-dp[:,0]; dzx=dp[:,2]-dp[:,0]; dzy=dp[:,2]-dp[:,1]
print('posY-posX top:',Counter(dyx.tolist()).most_common(8))
print('posZ-posX top:',Counter(dzx.tolist()).most_common(8))
print('posZ-posY top:',Counter(dzy.tolist()).most_common(8))
# traversal order: sort by posX; step distance between consecutive vertices
order=np.argsort(dp[:,0])
P=Gu[order]
step=np.linalg.norm(np.diff(P,axis=0),axis=1)
print(f'traversal step: median={np.median(step):.2f}m  p90={np.percentile(step,90):.2f}m  (NN~4m => smooth walk if ~4)')
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\vertex_streampos.npy',dp)
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\vertex_gt.npy',Gu)
