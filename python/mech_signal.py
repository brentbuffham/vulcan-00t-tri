#!/usr/bin/env python3
"""Mine token-byte signals for the mechanism choice on mech_labels.json.
Families: sp_k2, sp_k3, carry(k3), refN(d>1), NONE.
Predictors: T1, T1_lo5, T1 class, T2, T2_hi5, p, p_hi2, combinations."""
import json, itertools
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
M=json.load(open(sp+r'\mech_labels.json'))
def fam(m):
    if m is None: return 'NONE'
    parts=m.split('_')
    if parts[0].startswith('esc'): return 'esc'
    if parts[0].startswith('ca'):
        d=parts[1]
        return 'ca_d1' if d=='d1' else 'ca_dN'
    d=parts[1]; k=parts[2]
    if d=='d1': return f'sp_{k}'
    return 'sp_dN'
rows=[(l,fam(l['mech'])) for l in M]
print('family census:',dict(Counter(f for _,f in rows).most_common()))
known=[(l,f) for l,f in rows if f!='NONE']
def purity(labels,fk,tk):
    tab=defaultdict(Counter)
    for l,f in labels: tab[fk(l)][tk(l,f)]+=1
    tot=sum(sum(c.values()) for c in tab.values())
    pure=sum(c.most_common(1)[0][1] for c in tab.values())
    return pure/tot,tab
F={'T1':lambda l:l['T1'],'T2':lambda l:l['T2'],
   'T1_lo5':lambda l:l['T1']&0x1F if l['T1']>=0 else -1,
   'T1_cls':lambda l:-1 if l['T1']<0 else (0x20 if l['T1']==0x20 else (l['T1']>>5)),
   'T2_hi5':lambda l:l['T2']>>3 if l['T2']>=0 else -1,
   'p':lambda l:l['p'],'p_hi2':lambda l:l['p']>>3,
   'T1T2':lambda l:(l['T1'],l['T2']),
   'pT1':lambda l:(l['p'],l['T1']),
   'pT1T2':lambda l:(l['p'],l['T1'],l['T2'])}
tk=lambda l,f:f
base=Counter(f for _,f in known).most_common(1)[0][1]/len(known)
print(f'\nknown-family prediction, baseline {base*100:.1f}%:')
res=[]
for name,f in F.items():
    pu,tab=purity(known,f,tk)
    res.append((pu,name,tab))
res.sort(reverse=True)
for pu,name,tab in res:
    print(f'  {name:7s}: {pu*100:.2f}% [{len(tab)} ctx]')
# carry signal: is 'ca' distinguishable from 'sp'?
print('\ncarry vs sp_k3 (both write at k>=3):')
sub=[(l,f) for l,f in known if f in ('ca_d1','sp_k3')]
for name in ('T1','T1_lo5','T2','T2_hi5','p','T1T2'):
    pu,tab=purity(sub,F[name],tk)
    print(f'  {name:7s}: {pu*100:.2f}%')
subb=Counter(f for _,f in sub)
print(f'  baseline: {subb.most_common(1)[0][1]/len(sub)*100:.2f}%  {dict(subb)}')
# depth signal
print('\nd1 vs dN (any):')
sub=[(l,'d1' if '_d1' in ('_'+ (l['mech'] or '')) or (l['mech'] and 'd1' in l['mech']) else 'dN') for l,f in known]
sub=[(l,('d1' if 'd1' in l['mech'] else 'dN')) for l,f in known]
for name in ('T1','T2','T2_hi5','p','T1T2'):
    pu,tab=purity(sub,F[name],lambda l,f:f)
    print(f'  {name:7s}: {pu*100:.2f}%')
subb=Counter(f for _,f in sub)
print(f'  baseline: {subb.most_common(1)[0][1]/len(sub)*100:.2f}%')
# NONE prediction (is 'unexplained' contextually marked? -> those are likely
# the events/other mechanisms)
print('\nNONE vs known:')
sub=[(l,'N' if f=='NONE' else 'K') for l,f in rows]
for name in ('T1','T2','p','T1_lo5','T2_hi5','pT1'):
    pu,tab=purity(sub,F[name],lambda l,f:f)
    print(f'  {name:7s}: {pu*100:.2f}%')
subb=Counter(f for _,f in sub)
print(f'  baseline: {subb.most_common(1)[0][1]/len(sub)*100:.2f}%')
# k2/k3 within sp_d1 by T1 (sanity: should match k0 rule)
sub=[(l,f) for l,f in known if f in ('sp_k2','sp_k3')]
pu,tab=purity(sub,F['T1_cls'],tk)
print(f'\nsp k2/k3 by T1 class: {pu*100:.2f}%')
for k in sorted(tab,key=lambda k:-sum(tab[k].values()))[:8]:
    c=tab[k];n=sum(c.values())
    print(f'  T1cls={k if k==-1 or k==0x20 else hex(k<<5)}: n={n:<5} {dict(c.most_common(3))}')
