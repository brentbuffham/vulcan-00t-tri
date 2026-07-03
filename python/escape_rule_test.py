#!/usr/bin/env python3
"""Test generalized V-token rule: prefix p<0x20 => nb=(p&7)+1 payload bytes,
splice depth=(p>>3) trailing register bytes preserved.
Oracle decode: axis = whichever register's splice (at the PRESCRIBED depth) hits GT.
Report: solo-token count, per-depth hit rates, Y recovery, overall coverage."""
import struct
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
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
# tokenize with generalized prefix
toks=[];pos=8350;solo=0
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],pos)); pos+=8; continue
    if b<0x20:
        nb=(b&7)+1; depth=b>>3
        if pos+1+nb<=face_start:
            toks.append(('V',d[pos+1:pos+1+nb],pos,depth)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        toks.append(('E',d[pos:pos+3],pos)); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        toks.append(('T',d[pos:pos+2],pos)); pos+=2; continue
    solo+=1; pos+=1
nv=sum(1 for t in toks if t[0]=='V')
print(f'tokens: {len(toks)}  V: {nv}  fulls: {sum(1 for t in toks if t[0]=="F")}  solo leftover: {solo}')
vd=Counter((t[3],len(t[1])) for t in toks if t[0]=='V')
print('V (depth,nb) histogram:',sorted(vd.items()))
# oracle with prescribed depth
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
hit_by=Counter(); tot_by=Counter(); axis_c=Counter(); miss=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v); regs[a][:]=t[1]; axis_c[a]+=1; continue
    if t[0]!='V': continue
    payload=t[1]; nb=len(payload); depth=t[3]
    if nb+depth>8: miss+=1; continue
    found=None
    for a in range(3):
        r=regs[a]
        vb=bytes(r[:8-nb-depth])+payload+(bytes(r[8-depth:]) if depth else b'')
        if gt_hit(be(vb),a): found=(a,vb); break
    tot_by[depth]+=1
    if found:
        a,vb=found; regs[a][:]=vb; hit_by[depth]+=1; axis_c[a]+=1
    else: miss+=1
print(f'\noracle (prescribed depth): hits {sum(hit_by.values())}/{nv} = {sum(hit_by.values())/nv*100:.1f}%  miss={miss}')
for dep in sorted(tot_by):
    print(f'  depth {dep}: {hit_by[dep]}/{tot_by[dep]} = {hit_by[dep]/max(tot_by[dep],1)*100:.1f}%')
print('axis totals (incl fulls): X=%d Y=%d Z=%d (target 2975 each)'%(axis_c[0],axis_c[1],axis_c[2]))
