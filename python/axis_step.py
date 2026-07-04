#!/usr/bin/env python3
"""Is the AXIS STEP (ax_i - ax_{i-1} mod 3) signaled in the token bytes?
Use adjacent labeled V-token pairs (tok indices consecutive, both in answer
key). Crosstab step against T2/T1/p of the CURRENT token (and prev token).
W2 toy rule said SEP (=T2) drives an axis state machine — test it at scale."""
import json
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
lab={l['tok']:l for l in L}
pairs=[]
for t,l in lab.items():
    p=lab.get(t-1)
    if p is None: continue
    step=(l['axis']-p['axis'])%3
    pairs.append((p,l,step))
print(f'{len(pairs)} adjacent labeled pairs')
print('step distribution:',dict(Counter(s for _,_,s in pairs).most_common()))
def fld(l):
    T1=l['T1'];T2=l['T2'];p=l['p']
    f={'T1':T1,'T2':T2,'p':p if p is not None else -1,
       'T2_hi5':T2>>3 if T2>=0 else -1,'T1_lo5':T1&0x1F if T1>=0 else -1,
       'p_hi2':p>>3 if p is not None else -1,'noT':1 if T1<0 else 0}
    return f
def purity(f):
    tab=defaultdict(Counter)
    for pl,l,s in pairs: tab[f(pl,l)][s]+=1
    tot=sum(sum(c.values()) for c in tab.values())
    pure=sum(c.most_common(1)[0][1] for c in tab.values())
    return pure/tot,tab
base=Counter(s for _,_,s in pairs).most_common(1)[0][1]/len(pairs)
print(f'baseline {base*100:.1f}%')
tests={
 'cur T2':      lambda pl,l:fld(l)['T2'],
 'cur T2_hi5':  lambda pl,l:fld(l)['T2_hi5'],
 'cur T1':      lambda pl,l:fld(l)['T1'],
 'cur p':       lambda pl,l:fld(l)['p'],
 'cur p_hi2':   lambda pl,l:fld(l)['p_hi2'],
 'cur noT':     lambda pl,l:fld(l)['noT'],
 'prev T2':     lambda pl,l:fld(pl)['T2'],
 'prev T2_hi5': lambda pl,l:fld(pl)['T2_hi5'],
 'prev p':      lambda pl,l:fld(pl)['p'],
 'cur (T1,T2)': lambda pl,l:(l['T1'],l['T2']),
 'cur (p,T2)':  lambda pl,l:(fld(l)['p'],l['T2']),
 'cur (T2,noT)':lambda pl,l:(l['T2'],fld(l)['noT']),
 'prevT2+curT2':lambda pl,l:(pl['T2'],l['T2']),
}
res=[]
for name,f in tests.items():
    pu,tab=purity(f)
    res.append((pu,name,tab))
res.sort(reverse=True)
for pu,name,tab in res:
    print(f'  {name:14s}: {pu*100:.2f}%  [{len(tab)} ctx]')
# detailed table for cur T2
print('\ncur T2 -> step (n>=8):')
_,_,tab=[r for r in res if r[1]=='cur T2'][0]
for k in sorted(tab,key=lambda k:-sum(tab[k].values())):
    c=tab[k];n=sum(c.values())
    if n<8: continue
    print(f'  T2={k:#04x} (hi5={k>>3 if k>=0 else -1:2}) n={n:<5} {dict(c.most_common(3))}')
# T2 lo3: in coords always 7? check
print('\nT2 lo3 distribution:',dict(Counter(l['T2']&7 for l in lab.values() if l['T2']>=0)))
# conditional: within T2==0x17 only, what explains step?
sub=[(pl,l,s) for pl,l,s in pairs if l['T2']==0x17]
print(f'\nwithin T2==0x17 ({len(sub)}): step {dict(Counter(s for _,_,s in sub))}')
tab=defaultdict(Counter)
for pl,l,s in sub: tab[(l['T1'])][s]+=1
pure=sum(c.most_common(1)[0][1] for c in tab.values())
print(f'  T1 within: {pure/len(sub)*100:.1f}%')
tab=defaultdict(Counter)
for pl,l,s in sub: tab[(pl['T2'])][s]+=1
pure=sum(c.most_common(1)[0][1] for c in tab.values())
print(f'  prevT2 within: {pure/len(sub)*100:.1f}%')
