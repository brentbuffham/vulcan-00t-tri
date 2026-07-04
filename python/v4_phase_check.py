#!/usr/bin/env python3
"""Phase agreement of the v4 ANNOUNCEMENT model vs answer key."""
import struct, json
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
d=open(oot,'rb').read()
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
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
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],None,None,pos)); pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        pos+=1; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],None,b,pos)); pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
    if pos+2<=face_start: pos+=2; continue
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
ph=0;expect=0
agree=0;tot=0;runs=[];prev_bad=False
for t in toks:
    if t[0]=='F':
        a=band(be(t[1]))
        if expect>0:
            expect-=1; ph=(a+1)%3
        continue
    l=lab_by_pos.get(t[4])
    if l:
        tot+=1
        ok=l['axis']==ph
        agree+=ok
        if not ok and not prev_bad: runs.append(t[4])
        prev_bad=not ok
    expect=t[3]>>3
    ph=(ph+1)%3
print(f'v4 announcement-model phase agreement: {agree}/{tot} = {agree/tot*100:.2f}%')
print(f'divergence runs: {len(runs)}; first sites: {runs[:15]}')
