#!/usr/bin/env python3
"""Diff v3c (new tokenizer) against the answer key, mapping tokens by FILE
OFFSET. Checks: (1) are the new escaped FULLs real GT coordinates? (2) phase
agreement of the all-advance model under the new framing; (3) where breaks
start; (4) FULL resync rule sanity (does band+1 hold?)."""
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
# OLD tokenizer with positions
def tok_old():
    toks=[];pos=8350;lastT=None
    while pos<face_start:
        b=d[pos]
        if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
            while pos<face_start and d[pos]==0: pos+=1
            continue
        if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
            toks.append(('F',d[pos:pos+8],lastT,None,pos)); lastT=None; pos+=8; continue
        if b<0x20 and pos+1+(b&7)+1<=face_start:
            nb=(b&7)+1
            toks.append(('V',d[pos+1:pos+1+nb],lastT,b,pos)); lastT=None; pos+=1+nb; continue
        if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
        if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
        pos+=1
    return toks
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None
def tok_new():
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
    return toks
old=tok_old(); new=tok_new()
L=json.load(open(sp+r'\commit_labels.json'))
lab_by_pos={old[l['tok']][4]:l for l in L if l['tok']<len(old)}
# 1. new FULLs vs GT
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
gsets=[set(np.round(Gu[:,a],3)) for a in range(3)]
oldpos={t[4] for t in old if t[0]=='F'}
newf=[t for t in new if t[0]=='F']
hits=Counter()
for t in newf:
    v=be(t[1]); a=band(v)
    key='old' if t[4] in oldpos else 'new'
    hits[(key,round(v,3) in gsets[a] or any(abs(v-g)<0.0006 for g in []))]+=0
    ok=round(v,3) in gsets[a]
    if not ok:
        ok=min(abs(np.array(sorted(gsets[a]))-v))<0.0006 if gsets[a] else False
    hits[(key,bool(ok))]+=1
print('FULLs vs GT (old/new, on-grid):',dict(hits))
# 2. phase agreement, all-advance, new framing
ph=0;agree=0;tot=0;breaks=[]
for i,t in enumerate(new):
    if t[0]=='F':
        a=band(be(t[1]))
        l=lab_by_pos.get(t[4])
        if l: tot+=1; agree+=l['axis']==a
        ph=(a+1)%3; continue
    l=lab_by_pos.get(t[4])
    if l:
        tot+=1
        ok=l['axis']==ph
        agree+=ok
        if not ok: breaks.append(i)
    ph=(ph+1)%3
print(f'phase agreement (new framing, all+1): {agree}/{tot} = {agree/tot*100:.2f}%')
print(f'breaks {len(breaks)}, first: {breaks[:12]}')
# 3. break starts: context of first token of each break run
runs=[]
prev=-10
for i in breaks:
    if i!=prev+1: runs.append(i)
    prev=i
print(f'break RUNS: {len(runs)}')
cc=Counter()
for i in runs[:400]:
    t=new[i]
    # what token type precedes the run start?
    tp=new[i-1] if i>0 else None
    cc[(t[0],tp[0] if tp else '-',tp[3] if tp and tp[0]=='V' else None)]+=1
for k,v in cc.most_common(12): print(' ',k,v)
# 4. FULL slot check: does a FULL's band equal the phase slot it occupies?
ph=0;okf=0;nf=0;fullband_next=Counter()
for i,t in enumerate(new):
    if t[0]=='F':
        a=band(be(t[1]))
        okf+=a==ph; nf+=1
        fullband_next[(a-ph)%3]+=1
        ph=(a+1)%3; continue
    ph=(ph+1)%3
print(f'\nFULL occupies expected slot: {okf}/{nf}; (band-phase)%3 dist: {dict(fullband_next)}')
