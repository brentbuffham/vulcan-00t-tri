#!/usr/bin/env python3
"""Beam v2: branches = axis x {tail, inner1} splice. Bigger beam. After decode,
extract rule table (T-class, SEP-byte, prev_axis) -> (axis, mode) from hit-labeled
tokens and report purity + coverage. GT for scoring only."""
import sys, struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
BEAM=int(sys.argv[1]) if len(sys.argv)>1 else 300
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
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],pos)); pos+=8; continue
    if b<=0x06 and pos+1+b+1<=face_start:
        toks.append(('V',d[pos+1:pos+1+b+1],pos)); pos+=1+b+1; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3],pos)); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2],pos)); pos+=2; continue
    toks.append(('S',bytes([b]),pos)); pos+=1
HIT=[3.9,3.5,1.0]; MISS=-3.5
init=(0.0, d[8326:8334], d[8334:8342], d[8342:8350], ())
beam=[init]; vi=0
nv=sum(1 for t in toks if t[0]=='V')
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v)
        beam=[(sc,)+tuple(bytes(t[1]) if i==a else r for i,r in enumerate((rx,ry,rz)))+(ph,) for sc,rx,ry,rz,ph in beam]
        continue
    if t[0]!='V': continue
    payload=t[1]; nb=len(payload)
    cand={}
    for sc,rx,ry,rz,ph in beam:
        regs=(rx,ry,rz)
        for a in range(3):
            for mode in (0,1):
                if mode==0:
                    vb=regs[a][:8-nb]+payload
                else:
                    if nb+1>8: continue
                    vb=regs[a][:8-nb-1]+payload+regs[a][7:]
                v=be(vb)
                ok=gt_hit(v,a)
                s2=sc+(HIT[a] if ok else MISS)
                r=[rx,ry,rz]; r[a]=vb
                key=(r[0],r[1],r[2])
                lab=(a,mode,ok)
                if key not in cand or cand[key][0]<s2:
                    cand[key]=(s2,r[0],r[1],r[2],ph+(lab,))
    beam=sorted(cand.values(),key=lambda x:-x[0])[:BEAM]
    vi+=1
    if vi%2000==0: print(f'  V {vi}/{nv} best={beam[0][0]:.0f}')
best=beam[0]
print(f'final score {best[0]:.0f}')
path=best[4]
hits=Counter(); tot=Counter()
for a,mode,ok in path:
    tot[a]+=1; hits[a]+=ok
for a,nm in enumerate('XYZ'):
    print(f'{nm}: {hits[a]}/{tot[a]} = {hits[a]/max(tot[a],1)*100:.1f}%')
print('modes used:',Counter((a,mode) for a,mode,ok in path).most_common(8))
# ---- rule extraction ----
# context: preceding T/E/S token bytes
ctx=[];vi=0
lastT=None; prev_axis=2
rows=defaultdict(Counter)
for t in toks:
    if t[0]=='F':
        prev_axis=band(be(t[1])); lastT=None; continue
    if t[0]=='V':
        a,mode,ok=path[vi]
        if ok:
            key=(lastT[1][0]>>5 if lastT and lastT[0]=='T' else (lastT[0] if lastT else '-'),
                 lastT[1][1] if lastT and lastT[0]=='T' else None,
                 prev_axis)
            rows[key][(a,mode)]+=1
        prev_axis=a; vi+=1; lastT=None; continue
    lastT=t
tot2=pure=0
for key,c in rows.items():
    n=sum(c.values()); pure+=c.most_common(1)[0][1]; tot2+=n
print(f'\nrule purity (Tclass,SEP,prev)->(axis,mode): {pure}/{tot2} = {pure/max(tot2,1)*100:.1f}%')
big=sorted(rows.items(),key=lambda kv:-sum(kv[1].values()))[:20]
for key,c in big:
    print(f'  {key}: {dict(c.most_common(4))}')
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\beam2_path.npy',
        np.array(path,dtype=object),allow_pickle=True)
