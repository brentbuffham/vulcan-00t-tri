#!/usr/bin/env python3
"""What does a FULL do to the cycle? For each FULL with a LABELED V-token
immediately before (axis p) and after (axis n), crosstab (p, band, n).
Slot-occupying model predicts n=(band+1)%3. Out-of-cycle predicts n=(p+1)%3.
Also handle FULL RUNS (consecutive FULLs): use run's last band."""
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
# new tokenizer (same as v3c)
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],lastT,None,pos)); lastT=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        lastT=None; pos+=1; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b,pos)); lastT=None; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
# old tokenizer positions -> labels
def tok_old():
    o=[];pos=8350;lastT=None
    while pos<face_start:
        b=d[pos]
        if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
            while pos<face_start and d[pos]==0: pos+=1
            continue
        if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
            o.append(('F',pos)); pos+=8; continue
        if b<0x20 and pos+1+(b&7)+1<=face_start:
            o.append(('V',pos)); pos+=1+(b&7)+1; continue
        if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
        if b>=0x20 and pos+2<=face_start: pos+=2; continue
        pos+=1
    return o
old=tok_old()
L=json.load(open(sp+r'\commit_labels.json'))
lab_by_pos={}
for l in L:
    if l['tok']<len(old): lab_by_pos[old[l['tok']][1]]=l
# find FULL runs in new toks
i=0
tab=Counter(); tab2=Counter()
runs=[]
while i<len(toks):
    if toks[i][0]=='F':
        j=i
        while j+1<len(toks) and toks[j+1][0]=='F': j+=1
        runs.append((i,j))
        i=j+1
    else: i+=1
print(f'{len(runs)} FULL runs; run lengths:',dict(Counter(j-i+1 for i,j in runs).most_common(8)))
for i,j in runs:
    lp=lab_by_pos.get(toks[i-1][4]) if i>0 and toks[i-1][0]=='V' else None
    ln=lab_by_pos.get(toks[j+1][4]) if j+1<len(toks) and toks[j+1][0]=='V' else None
    if lp is None or ln is None: continue
    p=lp['axis']; n=ln['axis']
    lastband=band(be(toks[j][1]))
    npred_slot=(lastband+1)%3
    npred_out=(p+1)%3
    tab[('slot',n==npred_slot)]+=1
    tab[('out',n==npred_out)]+=1
    tab2[(p,tuple(band(be(toks[k][1])) for k in range(i,j+1))[:4],n)]+=1
print('model check:',dict(tab))
print('\n(prevV axis, run bands, nextV axis) top 25:')
for k,v in tab2.most_common(25): print(' ',k,v)
