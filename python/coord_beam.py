#!/usr/bin/env python3
"""Beam-search axis decode of the coord section (intercepts).
Tokens via unified grammar. State=(regs X/Y/Z). Branch axis per V-token.
Score: X hit +3.9, Y hit +3.5, Z hit +1.2 (log-lik vs coincidental floor),
miss -3. FULLs re-anchor exactly. Output: best path's scalar sequence + labels."""
import sys, struct
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=sys.argv[1] if len(sys.argv)>1 else r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
BEAM=int(sys.argv[2]) if len(sys.argv)>2 else 160
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gt_hit(v,a,tol=0.0006):
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
# ---- tokenize once ----
toks=[]  # ('F',bytes8) | ('V',payload) | ('T',b1,b2) | ('E',b1,b2,b3) | ('S',b)
pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8])); pos+=8; continue
    if b<=0x06 and pos+1+b+1<=face_start:
        toks.append(('V',d[pos+1:pos+1+b+1])); pos+=1+b+1; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3])); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2])); pos+=2; continue
    toks.append(('S',bytes([b]))); pos+=1
nv=sum(1 for t in toks if t[0]=='V')
print(f'tokens: {len(toks)}  V-tokens: {nv}  fulls: {sum(1 for t in toks if t[0]=="F")}')
HIT=[3.9,3.5,1.2]; MISS=-3.0
# beam state: (score, regsX, regsY, regsZ, path) path=list of axis per V-token (kept as bytes for memory)
init=(0.0, d[8326:8334], d[8334:8342], d[8342:8350], b'')
beam=[init]
vi=0
for ti,t in enumerate(toks):
    if t[0]=='F':
        v=be(t[1]); a=band(v)
        nb2=[]
        for sc,rx,ry,rz,ph in beam:
            r=[rx,ry,rz]; r[a]=bytes(t[1])
            nb2.append((sc,r[0],r[1],r[2],ph))
        beam=nb2; continue
    if t[0]!='V': continue
    payload=t[1]; nb=len(payload)
    cand={}
    for sc,rx,ry,rz,ph in beam:
        regs=(rx,ry,rz)
        for a in range(3):
            vb=regs[a][:8-nb]+payload
            v=be(vb)
            ok=gt_hit(v,a) if band(v)==a else False
            s2=sc+(HIT[a] if ok else MISS)
            r=[rx,ry,rz]; r[a]=vb
            key=(r[0],r[1],r[2])
            ph2=ph+bytes([a])
            if key not in cand or cand[key][0]<s2:
                cand[key]=(s2,r[0],r[1],r[2],ph2)
    beam=sorted(cand.values(),key=lambda x:-x[0])[:BEAM]
    vi+=1
    if vi%2000==0: print(f'  V {vi}/{nv} best={beam[0][0]:.0f}')
best=beam[0]
print(f'final best score: {best[0]:.0f}')
path=best[4]
# replay to get values + hits
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
vi=0; hits=[0,0,0]; tot=[0,0,0]; out=[]
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]; out.append((a,v,True,'F')); continue
    if t[0]!='V': continue
    a=path[vi]; nb=len(t[1])
    vb=bytes(regs[a][:8-nb])+t[1]; regs[a][:]=vb
    v=be(vb); h=gt_hit(v,a); hits[a]+=h; tot[a]+=1
    out.append((a,v,h,'D')); vi+=1
for a,nm in enumerate('XYZ'):
    print(f'{nm}: {hits[a]}/{tot[a]} = {hits[a]/max(tot[a],1)*100:.1f}% hit (floor ~{[2,3,18][a]}%)')
print(f'total scalars: {len(out)} (3*NV={3*2975})')
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\beam_path.npy',
        np.array([(a,v,int(h)) for a,v,h,k in out],dtype=object),allow_pickle=True)
# axis sequence pattern
axseq=''.join('XYZ'[a] for a,v,h,k in out[:120])
print('first 120 axis labels:',axseq)
