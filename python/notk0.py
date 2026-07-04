#!/usr/bin/env python3
"""Small checks before v3c: (1) k0 used by clean noT labels; (2) nb==8 V-tokens
= k0=0 literal replace? (3) how many sane escaped-FULLs hide in T-token runs."""
import json, struct
from collections import Counter
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1 and l.get('fb')]
noT=[l for l in clean if l['T1']<0]
print('clean noT k0:',dict(Counter(l['matches'][0][1]-(l['nb']-l['matches'][0][0]) for l in noT)))
print('clean noT nb:',dict(Counter(l['nb'] for l in noT)))
nb8=[l for l in L if l['nb']==8 and l['verified']]
print('nb8 labels:',len(nb8))
for l in nb8[:12]:
    x=int(l['ref'],16)^int(l['fb'],16) if l.get('fb') else None
    k0=(64-x.bit_length())//8 if x else '?'
    print(f"  tok {l['tok']} role={l['role']} flag={l['flag']} matches={l['matches']} xor-k0={k0} "
          f"fb==payload? {l.get('fb')==''.join(f'{b:02x}' for b in [])}")
# does payload literally equal fb for nb8?
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(oot,'rb').read()
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
# count sane escaped FULLs in the coord region: b>=0x20 then FULL-lead
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
cnt=0; ex=[]
pos=8350
while pos<face_start-10:
    b=d[pos]
    if b>=0x20 and d[pos+1] in (0x40,0x41,0xC0,0xC1) and sane(be(d[pos+1:pos+9])):
        cnt+=1
        if len(ex)<8: ex.append((pos,f'{b:02x}',d[pos+1:pos+9].hex()))
        pos+=9; continue
    pos+=1
print(f'\npotential escaped FULLs (T-lead + sane double): {cnt}')
for e in ex: print(' ',e)
