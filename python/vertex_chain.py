#!/usr/bin/env python3
"""Vertex-chain decode: X value (near-unique per GT vertex) identifies the vertex;
Y and Z tokens must then verify. Greedy chain with local event hypotheses and
anchor resync. GT used as the license-plate database (supervised stage; the rule
tables extracted from the result feed the GT-free decoder)."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
NVG=len(Gu)
# X -> vertex rows
xmap=defaultdict(list)
for vi,(x,y,z) in enumerate(Gu):
    xmap[round(x,3)].append(vi)
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
def tok_values(i,a,regs,tol=0.0006):
    """possible (value, newregbytes) for token i on axis a given register"""
    t=toks[i]
    out=[]
    if t[0]=='F':
        v=be(t[1])
        if band(v)==a: out.append((round(v,3),bytes(t[1])))
        return out
    payload=t[1]; nb=len(payload)
    for end in (8,7,6):
        k0=end-nb
        if k0<0: continue
        vb=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
        out.append((be(vb),vb))
    return out
def match(vlist,target,tol=0.0006):
    for v,vb in vlist:
        if np.isfinite(v) and abs(v-target)<=tol: return vb
    return None
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
i=0
decoded=[]  # (vertexIdx, tokenTriple)
misses=0; hits=0
fails=[]
while i+2<N:
    # propose X
    xs=tok_values(i,0,regs)
    committed=False
    for xv,xb in xs:
        xr=round(xv,3)
        for vi in xmap.get(xr,[]):
            vx,vy,vz=Gu[vi]
            yb=match(tok_values(i+1,1,regs),vy)
            if yb is None: continue
            zb=match(tok_values(i+2,2,regs),vz)
            if zb is None: continue
            regs[0][:]=xb; regs[1][:]=yb; regs[2][:]=zb
            decoded.append((vi,(i,i+1,i+2))); hits+=1
            i+=3; committed=True; break
        if committed: break
    if committed: continue
    # X not identified: try via exact X-grid snap with looser vertex search (KD later)
    # event hypotheses: vertex consumes 2 or 4 tokens
    # (a) split first token: X and Y in token i, Z in i+1
    t=toks[i]
    if t[0]=='V' and len(t[1])>=2:
        payload=t[1]; nb=len(payload)
        done=False
        for k2 in range(1,nb):
            h,tl=payload[:k2],payload[k2:]
            for e1 in (8,7):
                if e1-k2<0: continue
                xb=bytes(regs[0][:e1-k2])+h+bytes(regs[0][e1:])
                xr=round(be(xb),3)
                for vi in xmap.get(xr,[]):
                    vx,vy,vz=Gu[vi]
                    for e2 in (8,7):
                        if e2-(nb-k2)<0: continue
                        yb=bytes(regs[1][:e2-(nb-k2)])+tl+bytes(regs[1][e2:])
                        if abs(be(yb)-vy)<=0.0006:
                            zb=match(tok_values(i+1,2,regs),vz)
                            if zb is not None:
                                regs[0][:]=xb; regs[1][:]=yb; regs[2][:]=zb
                                decoded.append((vi,(i,i,i+1))); hits+=1
                                i+=2; done=True; break
                    if done: break
                if done: break
            if done: break
        if done: continue
    # (b) resync: skip one token
    misses+=1
    if len(fails)<20: fails.append(i)
    i+=1
print(f'vertices decoded: {hits}  token-skips: {misses}')
P=np.array([Gu[vi] for vi,_ in decoded])
tree=cKDTree(Gu)
d2,_=cKDTree(P).query(Gu) if len(P) else (np.array([9e9]),None)
print(f'GT recall (exact, by construction): {len(set(vi for vi,_ in decoded))}/{NVG} distinct vertices ({len(set(vi for vi,_ in decoded))/NVG*100:.1f}%)')
print('first fails at tokens:',fails)
with open(sp+r'\vertex_chain.xyz','w') as f:
    for x,y,z in P: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
np.save(sp+r'\vertex_chain_decoded.npy',np.array(decoded,dtype=object),allow_pickle=True)
print('saved')
