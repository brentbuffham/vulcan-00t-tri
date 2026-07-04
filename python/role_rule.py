#!/usr/bin/env python3
"""Learn T-token -> role rule from clean stretches.
Oracle decode (single any-axis any-depth, then split). Assemble scalars into
sliding vertex candidates; a scalar is CLEAN if it belongs to a consecutive
(X,Y,Z) triple that exactly matches a GT vertex (<2mm 3D). For clean V-tokens,
tabulate (preceding T byte1, byte2) -> (axis, depth/split, cycle-transition)."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
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
# tokenize keeping T/E context
toks=[];pos=8350
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],pos)); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb],pos,b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3],pos)); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2],pos)); pos+=2; continue
    pos+=1
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
events=[]  # (axis, value, tokenIdx, kind, Tctx, depth_or_split)
lastT=None
for ti,t in enumerate(toks):
    if t[0]=='T': lastT=t[1]; continue
    if t[0]=='E': continue
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]
        events.append((a,v,ti,'F',bytes(lastT) if lastT else None,None)); lastT=None; continue
    payload=t[1]; nb=len(payload)
    done=False
    for a in range(3):
        for dep in range(0,4):
            if nb+dep>8: continue
            vb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
            if gt_hit(be(vb),a):
                regs[a][:]=vb
                events.append((a,be(vb),ti,'V',bytes(lastT) if lastT else None,dep))
                done=True; break
        if done: break
    if not done:
        for k2 in range(1,nb):
            h,tl=payload[:k2],payload[k2:]; f2=None
            for a in range(3):
                va=bytes(regs[a][:8-k2])+h
                if not gt_hit(be(va),a): continue
                for b2 in range(3):
                    if b2==a: continue
                    vb2=bytes(regs[b2][:8-(nb-k2)])+tl
                    if gt_hit(be(vb2),b2): f2=(a,va,b2,vb2,k2); break
                if f2: break
            if f2:
                a,va,b2,vb2,k2=f2
                regs[a][:]=va; regs[b2][:]=vb2
                events.append((a,be(va),ti,'Vs1',bytes(lastT) if lastT else None,k2))
                events.append((b2,be(vb2),ti,'Vs2',bytes(lastT) if lastT else None,k2))
                done=True; break
    if not done:
        events.append((-1,0.0,ti,'miss',bytes(lastT) if lastT else None,None))
    lastT=None
# find clean triples: consecutive events i,i+1,i+2 with axes X,Y,Z & exact GT vertex
clean=np.zeros(len(events),bool)
nclean=0
for i in range(len(events)-2):
    a0,v0=events[i][0],events[i][1]
    a1,v1=events[i+1][0],events[i+1][1]
    a2,v2=events[i+2][0],events[i+2][1]
    if (a0,a1,a2)==(0,1,2):
        dd,_=tree.query((v0,v1,v2))
        if dd<0.002:
            clean[i]=clean[i+1]=clean[i+2]=True; nclean+=1
print(f'events: {len(events)}  clean XYZ-triples: {nclean}  clean events: {clean.sum()}')
# tabulate rule on clean V events
tab=defaultdict(Counter)
prevax=2
for i,ev in enumerate(events):
    a,v,ti,kind,Tctx,dep=ev
    if clean[i] and kind in ('V','Vs1','Vs2','F'):
        t1=Tctx[0] if Tctx else -1; t2=Tctx[1] if Tctx else -1
        trans=(a-prevax)%3
        tab[(t1>>4 if t1>=0 else -1, t2&0xff if t2>=0 else -1)][ (trans,kind,dep) ]+=1
    if a>=0: prevax=a
# purity
tot=pure=0
for key,c in tab.items():
    n=sum(c.values()); tot+=n; pure+=c.most_common(1)[0][1]
print(f'(T1-hi,T2)->(transition,kind,depth) purity: {pure}/{tot} = {pure/max(tot,1)*100:.1f}%')
rows=sorted(tab.items(),key=lambda kv:-sum(kv[1].values()))[:25]
for key,c in rows:
    n=sum(c.values())
    print(f'  T1hi={key[0]:x} T2=0x{key[1]:02x}: n={n:4d} {dict(c.most_common(3))}')
