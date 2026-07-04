#!/usr/bin/env python3
"""Diff v3b's GT-free decode against the answer key (commit_labels.json),
token by token. Where does the PHASE first diverge? Where does the VALUE
diverge despite correct phase? Print divergence sites with full context."""
import struct, json
import numpy as np
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
def k0_rule(T):
    T1,T2=T
    if 0x21<=T1<=0x3F: return 2
    if 0x40<=T1<=0x5F: return 3
    if T1==0x20: return 3 if T2<0x60 else 2
    return None
# simulate v3b phase only (no value dependence for phase): phase advances on
# every T-carrying V-token and FULL; refine (noT) doesn't advance.
ph=0
agree=0;tot=0
diverge=[]
for i,t in enumerate(toks):
    if t[0]=='F':
        a=band(be(t[1]))
        if i in lab:
            tot+=1; agree+=lab[i]['axis']==a
        ph=(a+1)%3; continue
    T=t[2]
    if T is None:
        # refine: no advance; predicted axis = (ph-1)%3
        if i in lab:
            tot+=1
            ok=lab[i]['axis']==(ph-1)%3
            agree+=ok
            if not ok and len(diverge)<40: diverge.append((i,'refine',(ph-1)%3,lab[i]))
        continue
    if i in lab:
        tot+=1
        ok=lab[i]['axis']==ph
        agree+=ok
        if not ok and len(diverge)<40: diverge.append((i,'delta',ph,lab[i]))
    ph=(ph+1)%3
print(f'phase agreement: {agree}/{tot} = {agree/tot*100:.2f}%')
print('\nfirst divergences:')
for i,knd,pred,l in diverge[:25]:
    t=toks[i]
    T=t[2] or (-1,-1)
    print(f'  tok {i}: pred axis {pred} truth {l["axis"]} role={l["role"]} flag={l["flag"]} '
          f'p={t[3]:#04x} T1={T[0]:#04x} T2={T[1]:#04x} nb={len(t[1])}')
    # context: neighbors
    for j in range(max(0,i-3),min(N,i+3)):
        tj=toks[j]; Tj=tj[2] or (-1,-1)
        lj=lab.get(j)
        print(f'      tok {j}: {tj[0]} p={tj[3] if tj[3] is not None else -1:#04x} '
              f'T=({Tj[0]:#04x},{Tj[1]:#04x}) nb={len(tj[1])} '
              f'truth={"ax%d %s"%(lj["axis"],lj["role"]) if lj else "?"}')
# how far in do we get before first divergence?
if diverge:
    print(f'\nfirst divergence at token {diverge[0][0]} of {N}')
# value check on agreeing plain tokens: replay with truth-forced state
# (use label ref as register, apply k0 rule, compare to label fb)
okv=0;totv=0;wrong=Counter()
for l in L:
    if not (l['verified'] and l['matches'] and l.get('fb')): continue
    t=toks[l['tok']]
    if t[0]!='V' or t[2] is None: continue
    k0=k0_rule(t[2])
    if k0 is None: continue
    nb=len(t[1]); end=k0+nb
    if end>8: k0=8-nb; end=8
    ref=bytes.fromhex(l['ref'])
    vb=ref[:k0]+bytes(t[1])+ref[end:]
    totv+=1
    if vb.hex()==l['fb']: okv+=1
    else:
        tr,te=l['matches'][0]; wrong[(k0,te-(nb-tr))]+=1
print(f'\nvalue via k0-rule with TRUE ref: {okv}/{totv} = {okv/totv*100:.2f}%')
print('wrong (pred_k0, true_k0):',dict(wrong.most_common(6)))
