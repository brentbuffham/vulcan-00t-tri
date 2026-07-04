#!/usr/bin/env python3
"""Compare phase models against answer-key axes:
 A: every V-token advances +1; FULL resyncs to band+1  (strict)
 B: A but noT tokens don't advance (v3b's wrong model)
 C: A + nb==8 tokens (p lo3==7) advance +2 (split carries 2 scalars)
Also: does an UNLABELED-token gap correlate with phase breaks?"""
import struct, json
from collections import Counter
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
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
N=len(toks)
L=json.load(open(sp+r'\commit_labels.json'))
lab={l['tok']:l for l in L}
def sim(advance):
    ph=0; agree=0; tot=0; breaks=[]
    for i,t in enumerate(toks):
        if t[0]=='F':
            ph=(band(be(t[1]))+1)%3; continue
        a=advance(t)          # slots this token covers (0=refine,1=normal,2=split)
        pred=ph if a>0 else (ph-1)%3
        if i in lab:
            tot+=1
            ok=lab[i]['axis']==pred if a<2 else lab[i]['axis'] in (ph,)
            agree+=ok
            if not ok: breaks.append(i)
        ph=(ph+a)%3
    return agree/tot*100,breaks
for name,f in (('A all +1',lambda t:1),
               ('B noT=0',lambda t:0 if t[2] is None else 1),
               ('C nb8=+2',lambda t:2 if len(t[1])==8 else 1),
               ('D nb8=+2,noT-nb8=+2',lambda t:2 if len(t[1])==8 else 1),
               ):
    pu,breaks=sim(f)
    print(f'{name}: {pu:.2f}%  breaks={len(breaks)} first10={breaks[:10]}')
# where are the breaks for model C — token contexts
pu,breaks=sim(lambda t:2 if len(t[1])==8 else 1)
print('\nmodel C break contexts:')
cc=Counter()
for i in breaks:
    t=toks[i]; T=t[2] or (-1,-1)
    cc[(t[3],T[0]>=0x60 if T[0]>=0 else None,lab[i]['role'],lab[i]['flag'])]+=1
for k,v in cc.most_common(12): print(' ',k,v)
# nb==8 census
nb8=[i for i,t in enumerate(toks) if t[0]=='V' and len(t[1])==8]
print(f'\nnb==8 tokens: {len(nb8)}; labeled roles:',
      dict(Counter(lab[i]['role'] for i in nb8 if i in lab)))
print('nb8 p values:',dict(Counter(toks[i][3] for i in nb8)))
