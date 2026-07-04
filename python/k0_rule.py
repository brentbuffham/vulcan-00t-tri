#!/usr/bin/env python3
"""Candidate DECODER rule for window start k0, + event signatures.
k0 rule: T1 in [0x21,0x3F] -> 2; [0x40,0x5F] -> 3; T1==0x20 -> ? (T2 / state).
Events: what T1/p contexts mark refine/split/two/unmodeled tokens?"""
import json
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1 and l.get('fb')]
rows=[]
for l in clean:
    x=int(l['ref'],16)^int(l['fb'],16)
    if x==0 or l['T1']<0: continue
    rows.append((l,(64-x.bit_length())//8))
# ---- rule variants for T1==0x20 ----
# state: previous k0 on the SAME token stream (any axis) and same-axis
def evalrule(name,f):
    ok=0;n=0
    prevk={0:None,1:None,2:None}; prevs=None
    bytok=sorted(rows,key=lambda x:x[0]['tok'])
    for l,k0 in bytok:
        t1=l['T1']
        if 0x21<=t1<=0x3F: pred=2
        elif 0x40<=t1<=0x5F: pred=3
        elif t1==0x20: pred=f(l,prevk[l['axis']],prevs)
        else: pred=None
        if pred is not None:
            ok+=pred==k0; n+=1
        prevk[l['axis']]=k0; prevs=k0
    print(f'  {name}: {ok}/{n} = {ok/n*100:.2f}%')
evalrule('0x20->always 3',lambda l,pa,ps:3)
evalrule('0x20->T2<0x60?3:2',lambda l,pa,ps:3 if l['T2']<0x60 else 2)
evalrule('0x20->T2<0x78?3:2',lambda l,pa,ps:3 if l['T2']<0x78 else 2)
evalrule('0x20->T2==0x17or0x2f?3:2',lambda l,pa,ps:3 if l['T2'] in (0x17,0x2f) else 2)
evalrule('0x20->prev same-axis k0',lambda l,pa,ps:pa if pa else 3)
evalrule('0x20->prev stream k0',lambda l,pa,ps:ps if ps else 3)
evalrule('0x20->T2<0x40?3:(prev-axis)',lambda l,pa,ps:3 if l['T2']<0x40 else (pa or 2))

# what about nb: for k0 known, end=k0+nb must be <=8; check consistency
bad=sum(1 for l,k0 in rows if k0+l['nb']-l['matches'][0][0]>8)
print(f'k0+nb>8 violations: {bad}')

# ---- event signatures ----
print('\n---- T1 ranges by class ----')
def ev_class(l):
    if not l['verified']: return l['role']
    if not l['matches']: return 'unmod'
    return 'normal'
def t1range(t1):
    if t1 is None or t1<0: return 'noT'
    if t1==0x20: return '0x20'
    if t1<0x40: return '0x21-3F'
    if t1<0x60: return '0x40-5F'
    if t1<0x80: return '0x60-7F'
    if t1<0xE0: return '0x80-DF'
    return '0xE0+'
tab=defaultdict(Counter)
for l in L:
    if l['role'] in ('val','refine','two1','two2','split'):
        tab[ev_class(l)][t1range(l['T1'])]+=1
for c in tab:
    tot=sum(tab[c].values())
    print(f'  {c:8s} (n={tot}): {dict(tab[c].most_common(8))}')
# p prefix hi bits by class
print('\n---- p_hi2 by class ----')
tab=defaultdict(Counter)
for l in L:
    if l['p'] is not None: tab[ev_class(l)][l['p']>>3]+=1
for c in tab:
    print(f'  {c:8s}: {dict(tab[c].most_common())}')
# unmod: how many are actually resync/lenient GT-packs (flag) vs true events?
print('\nunmod flags:',dict(Counter(l['flag'] for l in L if ev_class(l)=='unmod').most_common()))
print('unmod axis:',dict(Counter(l['axis'] for l in L if ev_class(l)=='unmod').most_common()))
