#!/usr/bin/env python3
"""Triple-locked beam: cycle always advances (X->Y->Z per vertex). Per V-token
branches: SINGLE (placement k in last-4 starts), SPLIT (two consecutive phases),
REFINE (re-update previous phase, no advance). FULL = literal, resyncs phase.
Score: exact GT triple on vertex completion +20; X/Y scalar hit +2, Z +0.5;
miss -4; refine -1. Output: best path -> context->action tables + purity."""
import sys, struct, json
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
BEAM=int(sys.argv[1]) if len(sys.argv)>1 else 160
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
# tokens with T context
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
print(f'tokens: {len(toks)}')
def triple_bonus(rx,ry,rz):
    x,y,z=be(rx),be(ry),be(rz)
    if not (np.isfinite(x) and np.isfinite(y) and np.isfinite(z)): return 0.0
    dd,_=tree.query((x,y,z))
    return 20.0 if dd<0.002 else 0.0
SC=[2.0,2.0,0.5]; MISS=-4.0
# state: (score, rx, ry, rz, phase, path)  path entries: (kind, axis(es), k(s))
beam=[(0.0, d[8326:8334], d[8334:8342], d[8342:8350], 0, ())]
for ti,t in enumerate(toks):
    cand={}
    if t[0]=='F':
        for sc,rx,ry,rz,ph,path in beam:
            v=be(t[1]); a=band(v)
            rr=[rx,ry,rz]; rr[a]=bytes(t[1])
            s2=sc+2.0
            ph2=(a+1)%3
            if a==2: s2+=triple_bonus(rr[0],rr[1],rr[2])
            key=(rr[0],rr[1],rr[2],ph2)
            pe=('F',a,None)
            if key not in cand or cand[key][0]<s2:
                cand[key]=(s2,rr[0],rr[1],rr[2],ph2,path+(pe,))
        beam=sorted(cand.values(),key=lambda x:-x[0])[:BEAM]
        continue
    payload=t[1]; nb=len(payload)
    for sc,rx,ry,rz,ph,path in beam:
        regs=(rx,ry,rz)
        # SINGLE at current phase
        a=ph
        for k in range(max(0,8-nb-3),8-nb+1):
            vb=regs[a][:k]+payload+regs[a][k+nb:]
            v=be(vb)
            s2=sc+(SC[a] if gt_hit(v,a) else MISS)
            rr=[rx,ry,rz]; rr[a]=vb
            if a==2: s2+=triple_bonus(rr[0],rr[1],rr[2])
            key=(rr[0],rr[1],rr[2],(a+1)%3)
            pe=('S',a,k)
            if key not in cand or cand[key][0]<s2:
                cand[key]=(s2,rr[0],rr[1],rr[2],(a+1)%3,path+(pe,))
        # REFINE previous phase (no advance)
        a2=(ph-1)%3
        for k in range(max(0,8-nb-3),8-nb+1):
            vb=regs[a2][:k]+payload+regs[a2][k+nb:]
            v=be(vb)
            s2=sc+(SC[a2] if gt_hit(v,a2) else MISS)-1.0
            rr=[rx,ry,rz]; rr[a2]=vb
            key=(rr[0],rr[1],rr[2],ph)
            pe=('R',a2,k)
            if key not in cand or cand[key][0]<s2:
                cand[key]=(s2,rr[0],rr[1],rr[2],ph,path+(pe,))
        # SPLIT current + next phase
        if nb>=2:
            b2=(ph+1)%3
            for k2 in range(1,nb):
                h,tl=payload[:k2],payload[k2:]
                for e1 in (8,7):
                    ka=e1-k2
                    if ka<0: continue
                    va=regs[ph][:ka]+h+regs[ph][ka+k2:]
                    hv=gt_hit(be(va),ph)
                    for e2 in (8,7):
                        kb=e2-(nb-k2)
                        if kb<0: continue
                        vb2=regs[b2][:kb]+tl+regs[b2][kb+(nb-k2):]
                        hv2=gt_hit(be(vb2),b2)
                        s2=sc+(SC[ph] if hv else MISS)+(SC[b2] if hv2 else MISS)
                        rr=[rx,ry,rz]; rr[ph]=va; rr[b2]=vb2
                        if 2 in (ph,b2): s2+=triple_bonus(rr[0],rr[1],rr[2])
                        key=(rr[0],rr[1],rr[2],(b2+1)%3)
                        pe=('P',(ph,b2),(k2,ka,kb))
                        if key not in cand or cand[key][0]<s2:
                            cand[key]=(s2,rr[0],rr[1],rr[2],(b2+1)%3,path+(pe,))
    beam=sorted(cand.values(),key=lambda x:-x[0])[:BEAM]
    if (ti+1)%2000==0: print(f'  tok {ti+1}/{len(toks)} best={beam[0][0]:.0f}')
best=beam[0]
print(f'final score {best[0]:.0f}')
path=best[5]
# replay for stats + assembly
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
pts=[]
kinds=Counter()
vt=[t for t in toks]
tabPlace=defaultdict(Counter); tabKind=defaultdict(Counter)
for t,pe in zip(vt,path):
    kind=pe[0]
    if t[0]=='F':
        v=be(t[1]); regs[band(v)][:]=t[1]
        if band(v)==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        kinds['F']+=1; continue
    payload=t[1]; nb=len(payload); T=t[2]; p=t[3]
    ctx=(p, T[0] if T else -1, T[1] if T else -1)
    if kind=='S':
        _,a,k=pe
        regs[a][:]=bytes(regs[a][:k])+payload+bytes(regs[a][k+nb:])
        if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        kinds['S']+=1; tabPlace[ctx][('S',k+nb)]+=1
    elif kind=='R':
        _,a,k=pe
        regs[a][:]=bytes(regs[a][:k])+payload+bytes(regs[a][k+nb:])
        kinds['R']+=1; tabPlace[ctx][('R',k+nb)]+=1
    else:
        _,(a,b2),(k2,ka,kb)=pe
        h,tl=payload[:k2],payload[k2:]
        regs[a][:]=bytes(regs[a][:ka])+h+bytes(regs[a][ka+k2:])
        regs[b2][:]=bytes(regs[b2][:kb])+tl+bytes(regs[b2][kb+(nb-k2):])
        if 2 in (a,b2): pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        kinds['P']+=1; tabPlace[ctx][('P',k2)]+=1
print('kinds:',dict(kinds))
P=np.array(pts)
dist,_=tree.query(P)
print(f'assembled {len(P)} vertices')
for tol in (0.002,0.01,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
print(f'  GT recall <2mm: {(d2<0.002).sum()}/{len(Gu)} ({(d2<0.002).mean()*100:.1f}%)')
# table purity
tot=pure=0
for kk,c in tabPlace.items():
    n=sum(c.values()); tot+=n; pure+=c.most_common(1)[0][1]
print(f'(p,T1,T2)->action purity: {pure}/{tot} = {pure/max(tot,1)*100:.1f}% over {len(tabPlace)} contexts')
# save tables + path
outtab={f'{k[0]},{k[1]},{k[2]}':{f'{a[0]},{a[1]}':n for a,n in c.items()} for k,c in tabPlace.items()}
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
json.dump(outtab,open(sp+r'\action_table.json','w'),indent=0)
np.save(sp+r'\triple_lock_path.npy',np.array(path,dtype=object),allow_pickle=True)
with open(sp+r'\triple_lock.xyz','w') as f:
    for x,y,z in pts: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('saved tables/path/xyz')
