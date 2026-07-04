#!/usr/bin/env python3
"""Are the T-token signal bits REDUNDANT with the value (usable as a per-token
verifier)? Test T1_lo5 / T2_hi5 against every plausible derived quantity:
payload edge bytes, ref bytes at the window edges, XOR bytes, new-value bytes,
delta mantissa bits. Clean labels only (exact ref+fb known)."""
import json, struct
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1 and l.get('fb')
       and l['T1']>=0]
rows=[]
for l in clean:
    rb=bytes.fromhex(l['ref']); fb=bytes.fromhex(l['fb'])
    r,end=l['matches'][0]; nb=l['nb']; k0=end-(nb-r)
    pay=fb[k0:end]
    rows.append((l,rb,fb,k0,end,pay))
print(f'{len(rows)} rows')
def agree(name,f):
    ok=0;n=0
    for l,rb,fb,k0,end,pay in rows:
        t=f(l,rb,fb,k0,end,pay)
        if t is None: continue
        n+=1; ok+=t
    print(f'  {name:36s}: {ok}/{n} = {ok/n*100:.1f}%')
m1=lambda l:l['T1']&0x1F
m2=lambda l:l['T2']>>3
print('T1_lo5 candidates:')
agree('== payload[0]>>3',      lambda l,rb,fb,k0,end,pay: m1(l)==pay[0]>>3 if pay else None)
agree('== payload[0]&0x1F',    lambda l,rb,fb,k0,end,pay: m1(l)==pay[0]&0x1F if pay else None)
agree('== payload[-1]>>3',     lambda l,rb,fb,k0,end,pay: m1(l)==pay[-1]>>3 if pay else None)
agree('== ref[k0]>>3',         lambda l,rb,fb,k0,end,pay: m1(l)==rb[k0]>>3)
agree('== (ref[k0]^pay0)>>3',  lambda l,rb,fb,k0,end,pay: m1(l)==(rb[k0]^pay[0])>>3 if pay else None)
agree('== fb[1]&0x1F',         lambda l,rb,fb,k0,end,pay: m1(l)==fb[1]&0x1F)
agree('== fb[2]>>3',           lambda l,rb,fb,k0,end,pay: m1(l)==fb[2]>>3)
agree('== (fb[k0]-rb[k0])&1F', lambda l,rb,fb,k0,end,pay: m1(l)==((fb[k0]-rb[k0])&0x1F))
print('T2_hi5 candidates:')
agree('== payload[-1]>>3',     lambda l,rb,fb,k0,end,pay: m2(l)==pay[-1]>>3 if pay else None)
agree('== payload[-1]&0x1F',   lambda l,rb,fb,k0,end,pay: m2(l)==pay[-1]&0x1F if pay else None)
agree('== payload[0]>>3',      lambda l,rb,fb,k0,end,pay: m2(l)==pay[0]>>3 if pay else None)
agree('== fb[7]>>3',           lambda l,rb,fb,k0,end,pay: m2(l)==fb[7]>>3)
agree('== fb[7]&0x1F',         lambda l,rb,fb,k0,end,pay: m2(l)==fb[7]&0x1F)
agree('== ref[end-1]>>3',      lambda l,rb,fb,k0,end,pay: m2(l)==rb[end-1]>>3)
agree('== (pay0^pay-1)>>3',    lambda l,rb,fb,k0,end,pay: m2(l)==(pay[0]^pay[-1])>>3 if pay else None)
# 10-bit concatenations vs 10-bit value slices
print('10-bit concat (T1_lo5<<5 | T2_hi5) candidates:')
def cc(l): return ((l['T1']&0x1F)<<5)|(l['T2']>>3)
agree('== pay[0]<<2|pay[1]>>6',lambda l,rb,fb,k0,end,pay: cc(l)==((pay[0]<<2)|(pay[1]>>6)) if len(pay)>1 else None)
agree('== (fbint>>54)&0x3FF',  lambda l,rb,fb,k0,end,pay: cc(l)==((int.from_bytes(fb,'big')>>54)&0x3FF))
agree('== (fbint>>0)&0x3FF',   lambda l,rb,fb,k0,end,pay: cc(l)==(int.from_bytes(fb,'big')&0x3FF))
# XOR-fold checksums
agree('== xor-fold payload 10b',lambda l,rb,fb,k0,end,pay: cc(l)==(lambda x: (x&0x3FF)^((x>>10)&0x3FF)^((x>>20)&0x3FF)^((x>>30)&0x3FF)^((x>>40)&0x3FF))(int.from_bytes(pay,'big')))
# per-axis constant? entropy check: T1_lo5 distribution overall + per axis
print('\nT1_lo5 distribution (top10):',dict(Counter(m1(l) for l,_,_,_,_,_ in rows).most_common(10)))
print('T2_hi5 distribution (top10):',dict(Counter(m2(l) for l,_,_,_,_,_ in rows).most_common(10)))
# joint with next token? T bits might describe the NEXT scalar's magnitude
# (prefetch): correlate T1_lo5 with |delta| exponent of THIS token
import math
tab=defaultdict(Counter)
for l,rb,fb,k0,end,pay in rows:
    dl=struct.unpack('>d',fb)[0]-struct.unpack('>d',rb)[0]
    e=math.floor(math.log2(abs(dl))) if dl else None
    if e is not None: tab[m1(l)][e]+=1
# purity
tot=sum(sum(c.values()) for c in tab.values())
pure=sum(c.most_common(1)[0][1] for c in tab.values())
print(f'\nT1_lo5 -> delta exponent purity: {pure/tot*100:.1f}% '
      f'(baseline {max(Counter(e for c in tab.values() for e,k in c.items() for _ in range(k)).values())/tot*100:.1f}%)')
