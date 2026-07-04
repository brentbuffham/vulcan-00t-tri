#!/usr/bin/env python3
"""DIAGNOSTIC (not the shipping parser): decode with TRUE axis per token
(answer-key axes only — values still decoded from bytes via k0 formula +
register cascade). Separates phase error from value error:
  high score  -> phase is the only remaining problem
  low score   -> the value cascade itself breaks (k0 errors / events)"""
import struct, json
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
gtcsv=sp+r'\intercepts_gt.csv'
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
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None
# NEW tokenizer with positions
toks=[];pos=8350;lastT=None;esc=False
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],lastT,esc,pos)); lastT=None; esc=False; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        esc=True; lastT=None; pos+=1; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b,pos)); lastT=None; esc=False; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
def tok_old():
    o=[];pos=8350
    while pos<face_start:
        b=d[pos]
        if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
            while pos<face_start and d[pos]==0: pos+=1
            continue
        if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
            o.append(pos); pos+=8; continue
        if b<0x20 and pos+1+(b&7)+1<=face_start:
            o.append(pos); pos+=1+(b&7)+1; continue
        if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
        if b>=0x20 and pos+2<=face_start: pos+=2; continue
        pos+=1
    return o
oldpos=tok_old()
L=json.load(open(sp+r'\commit_labels.json'))
lab_by_pos={oldpos[l['tok']]:l for l in L if l['tok']<len(oldpos)}
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
cur=[be(regs[0]),be(regs[1]),be(regs[2])]
verts={}  # vertex index -> [x,y,z]; use running Z-writes to emit
pts=[]
exact=0;tot=0;oob=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]
        if a==2 and not t[3]: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
        continue
    l=lab_by_pos.get(t[4])
    if l is None: continue   # unlabeled: skip (no axis truth)
    a=l['axis']
    payload=t[1]; nb=len(payload)
    if nb==0: continue
    k0=k0_rule(t[2],nb)
    end=k0+nb
    if end>8: k0=max(0,8-nb); end=k0+nb
    vb=bytes(regs[a][:k0])+payload+bytes(regs[a][end:])
    v=be(vb)
    if not np.isfinite(v) or band(v)!=a:
        oob+=1
        alt=5-k0; e2=alt+nb
        if 0<=alt and e2<=8:
            vb2=bytes(regs[a][:alt])+payload+bytes(regs[a][e2:])
            if np.isfinite(be(vb2)) and band(be(vb2))==a: vb=vb2
    regs[a][:]=vb
    # compare with answer key fb where available
    if l.get('fb'):
        tot+=1; exact+=vb.hex()==l['fb']
    if a==2: pts.append((be(regs[0]),be(regs[1]),be(regs[2])))
print(f'value exact vs answer key (true phase): {exact}/{tot} = {exact/tot*100:.2f}%  oob={oob}')
P=np.array(pts)
from scipy.spatial import cKDTree
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
dist,_=cKDTree(Gu).query(P)
print(f'forced-phase decode: {len(P)} vertices')
for tol in (0.002,1.0):
    print(f'  within {tol}m: {(dist<tol).sum()} ({(dist<tol).mean()*100:.1f}%)')
d2,_=cKDTree(P).query(Gu)
print(f'  GT recall <0.002m: {(d2<0.002).sum()}/{len(Gu)} ({(d2<0.002).mean()*100:.1f}%)')
