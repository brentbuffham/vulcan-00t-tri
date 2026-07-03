#!/usr/bin/env python3
"""Escape-region anatomy: where do solo bytes (0x07..0x1f) and oracle misses sit,
what bytes surround them, and do W11-13-style escape-prefixed FULL/Y-updates hide there?
Prints hex windows grouped by escape byte value + tests candidate re-framings."""
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
# tokenize, remembering S positions
pos=8350; spos=[]
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        pos+=8; continue
    if b<=0x06 and pos+1+b+1<=face_start: pos+=1+b+1; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if b>=0x20 and pos+2<=face_start: pos+=2; continue
    spos.append(pos); pos+=1
print(f'solo tokens: {len(spos)}')
sc=Counter(d[p] for p in spos)
print('solo byte histogram:',sorted(sc.items()))
# consecutive solos cluster?
sp=np.array(spos); gaps=np.diff(sp)
print(f'solo gap<16 bytes: {(gaps<16).mean()*100:.0f}%  (clusters)')
# hex windows around first 12 solos of the most common byte values
shown=Counter()
for p in spos:
    b=d[p]
    if shown[b]>=4: continue
    shown[b]+=1
    if sum(shown.values())>28: break
    ctx=' '.join(f'{x:02x}' for x in d[p-12:p])+' ['+f'{d[p]:02x}'+'] '+' '.join(f'{x:02x}' for x in d[p+1:p+20])
    print(f'@{p}: {ctx}')
