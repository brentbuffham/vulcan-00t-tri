#!/usr/bin/env python3
"""Classify the 1959 teacher-forced failures into mechanism families:
 F1 carry-splice:  fb = ref with window replaced AND byte k0-1 changed by +-1
 F2 int-arith:     fb_int = ref_int +- payload_int << 8*s  (s=0..5)
 F3 T-inclusion:   the two T bytes are literal value bytes preceding payload:
                   fb = ref[:k] + [T1,T2] + payload + ref[...]  (and variants)
 F4 ref-override:  splice onto an OLDER same-axis value (prev2/prev3/last FULL)
 F5 skip-splice:   payload lands with a 1-byte gap (untouched ref byte inside)
Count coverage; remaining unexplained dumped."""
import json, struct
from collections import Counter
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(oot,'rb').read()
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
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
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
fulls={i:t[1] for i,t in enumerate(toks) if t[0]=='F'}
lab_sorted=[l for l in L if l.get('fb')]
lab_sorted.sort(key=lambda l:l['tok'])
hist={0:[],1:[],2:[]}   # per-axis history of exact byte values (most recent last)
res=Counter(); rem=[]
prev_tok=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev_tok+1,i):
        if j in fulls:
            fb_=bytes(fulls[j]); hist[band(be(fb_))].append(fb_)
    prev_tok=i
    a=l['axis']; t=toks[i]
    fb=bytes.fromhex(l['fb'])
    if t[0]!='V' or l['role']!='val' or not l['verified'] or not hist[a]:
        hist[a].append(fb); continue
    ref=hist[a][-1]
    payload=bytes(t[1]); nb=len(payload)
    T=t[2]
    # baseline: plain splice any k0
    ok=None
    for k0 in range(0,9-nb):
        if ref[:k0]+payload+ref[k0+nb:]==fb: ok='splice'; break
    if not ok:
        # F1 carry-splice: byte k0-1 differs by +-1, rest of prefix equal
        for k0 in range(1,9-nb):
            if (ref[:k0-1]==fb[:k0-1] and abs(fb[k0-1]-ref[k0-1])==1
                    and fb[k0:k0+nb]==payload and fb[k0+nb:]==ref[k0+nb:]):
                ok='carry'; break
    if not ok:
        # F2 integer arithmetic
        ri=int.from_bytes(ref,'big'); fi=int.from_bytes(fb,'big')
        pi=int.from_bytes(payload,'big')
        for s in range(0,6):
            if ri+(pi<<(8*s))==fi or ri-(pi<<(8*s))==fi: ok='arith'; break
            # signed
            bits=8*nb
            ps=pi-(1<<bits) if pi>=(1<<(bits-1)) else pi
            if ri+(ps<<(8*s))==fi: ok='arith_s'; break
    if not ok and T is not None:
        # F3 T-inclusion
        tb=bytes(T)
        for k0 in range(0,7-nb):
            if ref[:k0]+tb+payload+ref[k0+2+nb:]==fb: ok='Tincl'; break
            if ref[:k0]+tb[1:]+payload+ref[k0+1+nb:]==fb: ok='T2incl'; break
    if not ok:
        # F4 older references
        for depth in range(2,min(6,len(hist[a])+1)):
            r2=hist[a][-depth]
            for k0 in range(0,9-nb):
                if r2[:k0]+payload+r2[k0+nb:]==fb: ok=f'ref{depth}'; break
            if ok: break
    if not ok:
        # F5 gap splice: one preserved ref byte inside the window
        for k0 in range(0,8-nb):
            for g in range(1,nb):
                cand=ref[:k0]+payload[:g]+ref[k0+g:k0+g+1]+payload[g:]+ref[k0+nb+1:]
                if len(cand)==8 and cand==fb: ok='gap'; break
            if ok: break
    res[ok or 'none']+=1
    if not ok and len(rem)<15:
        rem.append((i,l,ref.hex(),fb.hex(),payload.hex(),T))
    hist[a].append(fb)
print('failure-family coverage over ALL val tokens:')
for k,v in res.most_common(): print(f'  {k}: {v}')
tot=sum(res.values())
print(f'explained: {tot-res["none"]}/{tot} = {(tot-res["none"])/tot*100:.2f}%')
print('\nstill unexplained samples:')
for i,l,r,f,p,T in rem:
    print(f'  tok {i} ax {l["axis"]} p={l["p"]:#04x} T={tuple(hex(x) for x in T) if T else None} pay={p}')
    print(f'    ref {r}')
    print(f'    fb  {f}')
