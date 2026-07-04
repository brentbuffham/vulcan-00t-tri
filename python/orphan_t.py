#!/usr/bin/env python3
"""Skip-signal hypothesis: a scalar = T+V pair; a SKIPPED axis slot = orphan
T-token (no V). Re-tokenize keeping ALL T/E tokens between V-tokens; crosstab
(#T, #E between V_{i-1} and V_i) vs axis step from the answer key."""
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
# tokenize keeping every element (same V/F framing as answer key)
elems=[]  # ('V',payload,p) ('F',bytes) ('T',T1,T2) ('E',b0,b1,b2)
pos=8350
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        elems.append(('F',d[pos:pos+8])); pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        elems.append(('V',d[pos+1:pos+1+nb],b)); pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        elems.append(('E',d[pos],d[pos+1],d[pos+2])); pos+=3; continue
    if b>=0x20 and pos+2<=face_start:
        elems.append(('T',d[pos],d[pos+1])); pos+=2; continue
    pos+=1
# V-token index (same ordering as answer-key toks: V and F entries)
vtoks=[]; between=[]  # for each tok index: list of T/E elems since last V/F
cur=[]
for e in elems:
    if e[0] in ('V','F'):
        vtoks.append(e); between.append(cur); cur=[]
    else:
        cur.append(e)
print(f'toks {len(vtoks)} (answer key had these indices)')
L=json.load(open(sp+r'\commit_labels.json'))
lab={l['tok']:l for l in L}
# adjacent labeled pairs
pairs=[]
for t,l in lab.items():
    p=lab.get(t-1)
    if p is None: continue
    step=(l['axis']-p['axis'])%3
    pairs.append((t,p,l,step))
tab=defaultdict(Counter)
for t,pl,l,step in pairs:
    bt=between[t]
    nT=sum(1 for e in bt if e[0]=='T')
    nE=sum(1 for e in bt if e[0]=='E')
    tab[(nT,nE)][step]+=1
print('\n(#T,#E) before current V -> step:')
for k in sorted(tab,key=lambda k:-sum(tab[k].values())):
    c=tab[k];n=sum(c.values())
    print(f'  T={k[0]} E={k[1]}: n={n:<5} steps {dict(c.most_common())}')
# detail: step!=1 pairs — what exactly sits between?
print('\nstep!=1 pairs, between-elements:')
odd=[(t,pl,l,step) for t,pl,l,step in pairs if step!=1]
cc=Counter()
for t,pl,l,step in odd:
    bt=tuple((e[0],)+(tuple(f'{x:02x}' for x in e[1:3]) if e[0]=='T' else
              (tuple(f'{x:02x}' for x in e[1:4]) if e[0]=='E' else ()))
             for e in between[t])
    cc[(step,bt)]+=1
for k,v in cc.most_common(20): print(f'  step={k[0]} between={k[1]}: {v}')
# and for step==1 baseline, the common shapes
print('\nstep==1 baseline shapes:')
cc=Counter()
for t,pl,l,step in pairs:
    if step!=1: continue
    bt=tuple(e[0] for e in between[t])
    cc[bt]+=1
for k,v in cc.most_common(8): print(f'  {k}: {v}')
# ALSO: T1 of the *first* vs *last* T when 2 T-tokens present, step==1?
print('\npairs with >=2 T-tokens between:')
cc=Counter()
for t,pl,l,step in pairs:
    bt=[e for e in between[t] if e[0]=='T']
    if len(bt)>=2: cc[(step,tuple(f'{e[1]:02x}' for e in bt))]+=1
for k,v in cc.most_common(15): print(f'  step={k[0]} T1s={k[1]}: {v}')
