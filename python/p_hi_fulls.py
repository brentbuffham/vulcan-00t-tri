#!/usr/bin/env python3
"""Test: V-prefix hi bits (p>>3) == number of FULLs immediately following
this V-token? And: phase model where EVERY token (V and F) advances +1 with
NO band resync — phase = position in a global slot stream."""
import struct, json
from collections import Counter, defaultdict
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
# NEW tokenizer (with escape handling + payload truncation)
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
N=len(toks)
# p_hi vs following-FULL-count
tab=defaultdict(Counter)
for i,t in enumerate(toks):
    if t[0]!='V': continue
    cnt=0; j=i+1
    while j<N and toks[j][0]=='F': cnt+=1; j+=1
    tab[t[3]>>3][min(cnt,4)]+=1
print('p_hi (p>>3) -> #following FULLs:')
tot=0;ok=0
for k in sorted(tab):
    c=tab[k];n=sum(c.values())
    print(f'  hi={k}: n={n:<5} {dict(c.most_common(5))}')
    tot+=n; ok+=c[k] if k in c else 0
print(f'exact equality: {ok}/{tot} = {ok/tot*100:.1f}%')
# variant: count only PLAIN (unescaped) fulls
tab2=defaultdict(Counter)
for i,t in enumerate(toks):
    if t[0]!='V': continue
    cnt=0; j=i+1
    while j<N and toks[j][0]=='F':
        if not toks[j][3]: cnt+=1
        j+=1
    tab2[t[3]>>3][min(cnt,4)]+=1
ok2=sum(tab2[k][k] for k in tab2)
tot2=sum(sum(c.values()) for c in tab2.values())
print(f'exact equality (plain fulls only): {ok2}/{tot2} = {ok2/tot2*100:.1f}%')
# pure +1 phase model, no resync
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
for name,advF,advEsc,resync in (('pure+1 (esc adv too)',1,1,False),
                                ('pure+1 (esc no-adv)',1,0,False),
                                ('F resync (esc no-adv)',1,0,True)):
    ph=0;agree=0;tot=0;fulls_ok=0;fulls_n=0
    for t in toks:
        if t[0]=='F':
            a=band(be(t[1]))
            fulls_n+=1; fulls_ok+=a==ph
            if t[3]: ph=(ph+advEsc)%3
            else:
                if resync: ph=(a+1)%3
                else: ph=(ph+advF)%3
            continue
        l=lab_by_pos.get(t[4])
        if l:
            tot+=1; agree+=l['axis']==ph
        ph=(ph+1)%3
    print(f'{name}: V agree {agree}/{tot}={agree/tot*100:.1f}%  '
          f'FULL band==slot {fulls_ok}/{fulls_n}={fulls_ok/fulls_n*100:.1f}%')
