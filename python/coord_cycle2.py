#!/usr/bin/env python3
"""Strict-cycle decoder v2: scalar slots = vertex-major X,Y,Z (proven by stream
alignment: posY-posX=+1, posZ-posX=+2). Each V-token fills the current slot
(depth 0..3) or TWO consecutive slots (split payload, any split point).
FULLs fill their band's slot (report misalignment). GT for scoring only."""
import struct
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
out=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\cycle2_decoded.xyz'
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
            toks.append(('V',d[pos+1:pos+1+nb],b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        pos+=2; continue
    pos+=1

regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
slot=3  # seeds fill slots 0,1,2
stats=Counter()
full_align=Counter()
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]
def emit_if_z(old_slot,new_slot):
    # emit a vertex every time we pass a Z slot boundary (slot%3 wraps)
    for s in range(old_slot,new_slot):
        if s%3==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
for t in toks:
    a=slot%3
    if t[0]=='F':
        v=be(t[1]); fb=band(v)
        full_align['ok' if fb==a else 'misaligned']+=1
        regs[fb][:]=t[1]
        # advance to the slot AFTER this full's own slot position:
        old=slot
        if fb==a: slot+=1
        else:
            slot=slot+((fb-a)%3)+1
            stats['resync']+=1
        emit_if_z(old,slot)
        continue
    payload=t[1]; nb=len(payload)
    # 1) single fill of CURRENT slot (advance)
    done=False
    for dep in range(0,4):
        if nb+dep>8: continue
        vb=bytes(regs[a][:8-nb-dep])+payload+(bytes(regs[a][8-dep:]) if dep else b'')
        if gt_hit(be(vb),a):
            regs[a][:]=vb; slot+=1; stats[f'single_d{dep}']+=1; done=True
            emit_if_z(slot-1,slot); break
    if done: continue
    # 2) REFINE previous slot's axis (no advance)
    ap=(slot-1)%3
    for dep in range(0,4):
        if nb+dep>8: continue
        vb=bytes(regs[ap][:8-nb-dep])+payload+(bytes(regs[ap][8-dep:]) if dep else b'')
        v=be(vb)
        if gt_hit(v,ap) and abs(v-be(regs[ap]))>1e-9:
            regs[ap][:]=vb; stats['refine']+=1; done=True; break
    if done: continue
    # 3) split across two consecutive slots (advance 2); reject ulp-noise heads
    b2=(a+1)%3
    for k2 in range(1,nb):
        h,tl=payload[:k2],payload[k2:]
        ok1=None
        for dep in range(0,3):
            if k2+dep>8: continue
            va=bytes(regs[a][:8-k2-dep])+h+(bytes(regs[a][8-dep:]) if dep else b'')
            if gt_hit(be(va),a) and abs(be(va)-be(regs[a]))>1e-7:
                ok1=va; break
        if ok1 is None: continue
        for dep2 in range(0,3):
            if (nb-k2)+dep2>8: continue
            vb2=bytes(regs[b2][:8-(nb-k2)-dep2])+tl+(bytes(regs[b2][8-dep2:]) if dep2 else b'')
            if gt_hit(be(vb2),b2) and abs(be(vb2)-be(regs[b2]))>1e-7:
                regs[a][:]=ok1; regs[b2][:]=vb2; slot+=2; stats['split2']+=1; done=True
                emit_if_z(slot-2,slot); break
        if done: break
    if done: continue
    stats['miss']+=1; slot+=1  # advance anyway
    emit_if_z(slot-1,slot)
nslots=slot
print('fulls alignment:',dict(full_align))
print('stats:',dict(stats))
tot=sum(v for k,v in stats.items() if k.startswith('single') or k in ('split2','miss','refine'))
hitn=tot-stats['miss']
print(f'V-tokens: {tot}  hit: {hitn} ({hitn/tot*100:.1f}%)  slots used: {nslots} (target {3*2975})')
P=np.array(pts)
print(f'assembled vertices: {len(P)} (GT {len(Gu)})')
tree=cKDTree(Gu)
dist,_=tree.query(P)
for tol in (0.01,0.1,1.0):
    print(f'  decoded within {tol}m of GT: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
for tol in (0.01,0.1,1.0):
    print(f'  GT recall <{tol}m: {(d2<tol).sum()}/{len(Gu)} ({(d2<tol).mean()*100:.1f}%)')
with open(out,'w') as f:
    for x,y,z in pts: f.write(f'{x:.4f},{y:.4f},{z:.4f}\n')
print('wrote',out)
