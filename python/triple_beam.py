#!/usr/bin/env python3
"""Vertex-triple beam: tokens (V and FULL) come exactly 3 per vertex = X,Y,Z.
Branch over splice depth (0..3) per V-token; FULLs are literal. Score: exact GT
TRIPLE match (+12), else per-axis grid hits (+1 X,+1 Y,+0.3 Z). Registers always
carry the spliced bytes (no GT snapping). Beam keeps survivors across bad patches."""
import sys, struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
out=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\triple_decoded.xyz'
BEAM=int(sys.argv[1]) if len(sys.argv)>1 else 120
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
tree=cKDTree(Gu)
gA=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
    if not np.isfinite(v): return False
    arr=gA[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return True
    return False
def triple_ok(x,y,z,tol=0.002):
    if not (np.isfinite(x) and np.isfinite(y) and np.isfinite(z)): return False
    dd,_=tree.query((x,y,z))
    return dd<tol
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8])); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb],b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    pos+=1
print(f'tokens: {len(toks)} = {len(toks)/3:.1f} vertices worth (GT {len(Gu)})')
# group into vertex token-triples
vts=[toks[i:i+3] for i in range(0,len(toks)-2,3)]
def apply_tok(reg,t,dep):
    if t[0]=='F': return bytes(t[1])
    payload=t[1]; nb=len(payload)
    if nb+dep>8: return None
    return reg[:8-nb-dep]+payload+(reg[8-dep:] if dep else b'')
beam=[(0.0, d[8326:8334], d[8334:8342], d[8342:8350], ())]
for vi,vt in enumerate(vts):
    cand={}
    for sc,rx,ry,rz,ph in beam:
        regs=(rx,ry,rz)
        opts=[]
        for a in range(3):
            t=vt[a]
            if t[0]=='F': opts.append([bytes(t[1])])
            else:
                s=[]
                for dep in range(0,4):
                    nb2=len(t[1])
                    if nb2+dep<=8: s.append(regs[a][:8-nb2-dep]+t[1]+(regs[a][8-dep:] if dep else b''))
                opts.append(s)
        for bx in opts[0]:
            vx=be(bx)
            for by_ in opts[1]:
                vy=be(by_)
                for bz in opts[2]:
                    vz=be(bz)
                    if triple_ok(vx,vy,vz): s2=sc+12.0
                    else:
                        s2=sc+(1.0 if gt_hit(vx,0) else -1.0)+(1.0 if gt_hit(vy,1) else -1.0)+(0.3 if gt_hit(vz,2) else -1.0)
                    key=(bx,by_,bz)
                    if key not in cand or cand[key][0]<s2:
                        cand[key]=(s2,bx,by_,bz,ph+((vx,vy,vz),))
    beam=sorted(cand.values(),key=lambda x:-x[0])[:BEAM]
    if (vi+1)%500==0: print(f'  vertex {vi+1}/{len(vts)} best={beam[0][0]:.0f}')
best=beam[0]
P=np.array(best[4])
print(f'final score {best[0]:.0f}; vertices {len(P)}')
dist,_=tree.query(P)
for tol in (0.002,0.01,0.1,1.0):
    print(f'  decoded within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.002,0.01,0.1,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(out,'w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote',out)
