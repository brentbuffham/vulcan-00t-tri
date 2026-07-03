#!/usr/bin/env python3
"""Segment-wise decode between fingerprint anchors.
Anchors pin (tokenIdx, axis, value). Between anchors: axis = phase counting;
if the segment is phase-inconsistent, try ONE event (skip:+1 or refine:-1 [or
split: token carries 2 values]) at each position; placement per token: try end
8 then 7 (accept first GT hit; else keep end from table-major=7/8 by prefix).
Score = GT scalar hits. Assemble vertices on Z completion; KDTree score."""
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
def gt_snap(v,a,tol=0.0006):
    if not np.isfinite(v): return None
    arr=vals[a]; i=np.searchsorted(arr,v)
    best=None
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol:
            if best is None or abs(arr[j]-v)<abs(best-v): best=arr[j]
    return best
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
labels=np.load(sp+r'\fp2_labels.npy',allow_pickle=True)
anch=[(i,l[1],l[2]) for i,l in enumerate(labels) if l[0]=='U']
# add fulls as anchors with their value
for i,t in enumerate(toks):
    if t[0]=='F':
        v=be(t[1]); anch.append((i,band(v),round(v,3)))
anch=sorted(set(anch))
# dedupe by index (keep first)
seen=set(); anch=[a for a in anch if not (a[0] in seen or seen.add(a[0]))]
print(f'anchors: {len(anch)}')

def decode_segment(i0,a0,regs,i1,a1,event=None):
    """decode tokens (i0,i1) exclusive-exclusive given regs (bytearrays) at i0 done.
    event=(pos,delta): at token pos phase jumps by extra delta.
    Returns (hits, misses, assignments list[(idx,axis,value,end)], regs_out)."""
    regs=[bytearray(r) for r in regs]
    ph=(a0+1)%3
    hits=0;miss=0;asg=[]
    for i in range(i0+1,i1):
        t=toks[i]
        if t[0]=='F':
            v=be(t[1]); fb=band(v); regs[fb][:]=t[1]
            asg.append((i,fb,round(v,3),None)); ph=(fb+1)%3
            continue
        if event and event[0]==i:
            ph=(ph+event[1])%3
        payload=t[1]; nb=len(payload)
        val=None;endc=None
        for end in (7,8):
            k0=end-nb
            if k0<0: continue
            vb=bytes(regs[ph][:k0])+payload+bytes(regs[ph][end:])
            m=gt_snap(be(vb),ph)
            if m is not None:
                regs[ph][:]=vb; val=m; endc=end; break
        if val is None:
            # keep end-8 splice anyway (cascade), count miss
            k0=8-nb
            vb=bytes(regs[ph][:k0])+payload
            regs[ph][:]=vb; miss+=1
        else: hits+=1
        asg.append((i,ph,val if val is not None else round(be(bytes(regs[ph])),3),endc))
        ph=(ph+1)%3
    consistent=(ph==a1)
    return hits,miss,asg,regs,consistent

# walk anchor pairs
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
allasg={}
stats=Counter()
# initialize register with first anchor values as we go
prev=(-1,2,None)
for (i1,a1,w1) in anch:
    i0,a0,_=prev
    if i1>i0+1:
        h0,m0,asg,regs2,cons=decode_segment(i0,a0,regs,i1,a1)
        best=(h0-(0 if cons else 5),None,asg,regs2)
        if not cons:
            gap=i1-i0
            for j in range(i0+1,i1):
                for delta in (1,2):
                    h,m,asg2,regs3,c2=decode_segment(i0,a0,regs,i1,a1,event=(j,delta))
                    if c2 and h>best[0]:
                        best=(h,(j,delta),asg2,regs3)
            stats['segfix' if best[1] else 'seg_unfixed']+=1
        for a in best[2]: allasg[a[0]]=a
        regs=best[3]
    # apply anchor value
    if w1 is not None:
        wb=struct.pack('>d',w1)
        # merge: keep spliced low bytes if close? use exact GT double as register (approximation)
        t=toks[i1]
        if t[0]=='V':
            nb=len(t[1])
            for end in (7,8):
                k0=end-nb
                if k0<0: continue
                vb=bytes(regs[a1][:k0])+t[1]+bytes(regs[a1][end:])
                if abs(be(vb)-w1)<=0.0006:
                    regs[a1][:]=vb; break
            else:
                regs[a1][:]=wb
        else:
            regs[a1][:]=t[1]
        allasg[i1]=(i1,a1,w1,None)
    prev=(i1,a1,w1)
print('segment stats:',dict(stats))
# assemble
cur=[None,None,None]; pts=[]
nh=0
for i in range(len(toks)):
    if i not in allasg: continue
    _,a,v,_=allasg[i]
    cur[a]=v
    if a==2 and None not in cur: pts.append(tuple(cur))
P=np.array(pts)
tree=cKDTree(Gu)
dist,_=tree.query(P)
print(f'assembled {len(P)} vertices (GT {len(Gu)})')
for tol in (0.002,0.01,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
print(f'  GT recall <2mm: {(d2<0.002).sum()}/{len(Gu)} ({(d2<0.002).mean()*100:.1f}%)')
with open(sp+r'\segment_decoded.xyz','w') as f:
    for x,y,z in pts: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote segment_decoded.xyz')
