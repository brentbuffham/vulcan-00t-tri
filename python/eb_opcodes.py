#!/usr/bin/env python3
"""Step 1 of the stateful decoder: extract the per-triangle opcode stream from the
topology section and test EdgeBreaker counting/stack invariants to pin the C/L/E/R/S
mapping. Opcode = lead TAG before each CNT data-record (high nibble); 'N' = no lead
tag. Reports symbol distribution, bigrams, and tests #E ~= #S + components for
candidate E/S assignments."""
import sys, struct
from collections import Counter
oot=sys.argv[1]
START=int(sys.argv[2]) if len(sys.argv)>2 else 25_300_000
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
# extract: for each CNT record, the immediately preceding TAG high-nibble (or 'N')
syms=[]; pos=START; cur=None
while pos<geo_end:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pos+=1+nb
        syms.append((cur>>4) if cur is not None else -1)
        cur=None
    elif is_sep(b): pos+=1
    elif (b&0xE0) in TAG: cur=b; pos+=1
    else: pos+=1
n=len(syms)
print(f'opcodes (=CNT records): {n:,}   GT triangles=3,232,402')
dist=Counter(syms)
def nm(h): return 'N' if h==-1 else f'{h:x}0'
print('symbol dist:', [(nm(k),v,f'{100*v/n:.1f}%') for k,v in dist.most_common()])
# bigram: what precedes/follows the E0 (C) symbol
big=Counter(zip(syms,syms[1:]))
print('top bigrams:', [(f'{nm(a)}->{nm(b)}',v) for (a,b),v in big.most_common(12)])
# stack test: try each candidate (E-sym, S-sym) and report balance + min depth.
# forward EB: S pushes a branch, E pops. depth=#S-#E should stay>=0, end ~0.
cands=[0xe,0x2,0x4,0x6,0x8,0xc,0xf,-1]
print('\nstack-balance test (S=push,E=pop): want end~0, minDepth>=0')
for S in cands:
    for E in cands:
        if S==E: continue
        depth=0; mind=0; bad=False
        for s in syms:
            if s==S: depth+=1
            elif s==E:
                depth-=1
                if depth<mind: mind=depth
        if -50<depth<5000 and mind>-5:
            print(f'  S={nm(S)} E={nm(E)}: endDepth={depth} minDepth={mind}')
