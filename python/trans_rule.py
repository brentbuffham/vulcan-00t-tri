#!/usr/bin/env python3
"""Axis-transition rule extraction on the NEW tokenizer.
For every labeled V: delta = (axis - prev_coord_axis)%3 where prev_coord_axis
comes from the previous coordinate-bearing token (V label axis or FULL band).
Crosstabs:
  A) V after V:    delta vs (T1 class, T2)
  B) V after FULL: delta vs (FULL had own T?, escape-prefixed?, V's T1/T2)
  C) FULL after X: does FULL band relate to prev axis? (slot vs re-anchor)"""
import struct, json
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
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
# old positions -> labels
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
# walk
prev=None  # (kind, axis, hadT, esc)
A=defaultdict(Counter); B=defaultdict(Counter); C=Counter()
for t in toks:
    if t[0]=='F':
        a=band(be(t[1]))
        if prev:
            C[(prev[0],prev[1],a,t[2] is not None,t[3])]+=1
        prev=('F',a,t[2] is not None,t[3])
        continue
    l=lab_by_pos.get(t[4])
    if l is None:
        prev=None  # unknown axis breaks the chain
        continue
    a=l['axis']
    T=t[2]
    if prev:
        dlt=(a-prev[1])%3
        t1c=('noT' if T is None else
             '20' if T[0]==0x20 else '21-3F' if T[0]<0x40 else
             '40-5F' if T[0]<0x60 else '60+')
        if prev[0]=='V': A[(t1c,)][dlt]+=1
        else: B[(prev[2],prev[3],t1c)][dlt]+=1
        # detail for the interesting cells
    prev=('V',a,T is not None,False)
print('A) V after V: (T1 class) -> delta')
for k in sorted(A):
    c=A[k];n=sum(c.values())
    print(f'  {k}: n={n:<5} {dict(c.most_common())}')
print('\nB) V after FULL: (full hadT, full escaped, V T1 class) -> delta')
for k in sorted(B,key=lambda k:-sum(B[k].values())):
    c=B[k];n=sum(c.values())
    print(f'  hadT={k[0]} esc={k[1]} T1={k[2]}: n={n:<4} {dict(c.most_common())}')
print('\nC) FULL after prev: (prevkind, prevaxis, fullband, hadT, esc) top 20')
for k,v in C.most_common(20): print(' ',k,v)
