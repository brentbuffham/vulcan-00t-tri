#!/usr/bin/env python3
"""Full assembly with the 99.9% oracle decode (single-axis any-depth + split
payloads): emit a vertex snapshot on every Z update; KDTree-match vs GT.
Writes decoded xyz for the viewer."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
out=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\oracle_decoded.xyz'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G.reshape(-1,3) if G.ndim==2 else G,axis=0)
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
pts=[]
def cur(): return (be(regs[0]),be(regs[1]),be(regs[2]))
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]
        if a==2: pts.append(cur())
        continue
    payload=t[1]; nb=len(payload)
    done=False; zup=False
    for a in range(3):
        for dep in range(0,4):
            if nb+dep>8: continue
            vb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
            if gt_hit(be(vb),a):
                regs[a][:]=vb; done=True; zup=(a==2); break
        if done: break
    if not done:
        for k2 in range(1,nb):
            h,tl=payload[:k2],payload[k2:]
            f2=None
            for a in range(3):
                va=bytes(regs[a][:8-k2])+h
                if not gt_hit(be(va),a): continue
                for b2 in range(3):
                    if b2==a: continue
                    nb2=nb-k2
                    vb2=bytes(regs[b2][:8-nb2])+tl
                    if gt_hit(be(vb2),b2): f2=(a,va,b2,vb2); break
                if f2: break
            if f2:
                a,va,b2,vb2=f2
                regs[a][:]=va; regs[b2][:]=vb2; done=True; zup=(a==2 or b2==2); break
    if zup: pts.append(cur())
P=np.array(pts)
print(f'assembled points: {len(P)} (GT verts {len(Gu)})')
tree=cKDTree(Gu)
dist,_=tree.query(P)
for tol in (0.01,0.1,1.0):
    print(f'  matched <{tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
# GT recall: how many GT verts have a decoded point within tol
tree2=cKDTree(P)
d2,_=tree2.query(Gu)
for tol in (0.01,0.1,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(out,'w') as f:
    for x,y,z in pts: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote',out)
