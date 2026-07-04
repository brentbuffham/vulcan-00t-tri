#!/usr/bin/env python3
"""Do the T-token bits encode the BIT-level changed span of ref XOR new?
For each clean label compute x = ref XOR new (uint64): nlz (leading zero bits),
ntz (trailing zero bits), first/last changed bit. Correlate every T field.
If T2_hi5 (or T1_lo5) = f(last changed bit), placement end derives directly."""
import json, struct
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1 and l.get('fb')]
rows=[]
for l in clean:
    r=int(l['ref'],16); n=int(l['fb'],16)
    x=r^n
    if x==0: continue
    nlz=64-x.bit_length()          # leading zero bits
    ntz=(x & -x).bit_length()-1    # trailing zero bits
    rows.append((l,nlz,ntz))
print(f'{len(rows)} rows')
print('ntz distribution:',dict(Counter(t for _,_,t in rows).most_common(12)))
print('nlz distribution:',dict(Counter(z for _,z,_ in rows).most_common(12)))

def fld(l):
    out={}
    if l['T1']>=0:
        out['T1_lo5']=l['T1']&0x1F; out['T1']=l['T1']
    if l['T2']>=0:
        out['T2_hi5']=l['T2']>>3; out['T2']=l['T2']
    if l['p'] is not None: out['p_hi2']=l['p']>>3
    return out
# purity of field -> ntz , field -> nlz, and reverse (ntz -> field)
for tgt,name in ((lambda z,t:t,'ntz'),(lambda z,t:z,'nlz'),
                 (lambda z,t:t//8,'ntz//8'),(lambda z,t:t%8,'ntz%8'),
                 (lambda z,t:z//8,'nlz//8'),(lambda z,t:z%8,'nlz%8')):
    print(f'\n--- predict {name} ---')
    base=Counter(tgt(z,t) for _,z,t in rows)
    print(f'  baseline {base.most_common(1)[0][1]/len(rows)*100:.1f}%')
    for fk in ('T1_lo5','T2_hi5','T1','T2','p_hi2'):
        tab=defaultdict(Counter)
        for l,z,t in rows:
            f=fld(l)
            if fk in f: tab[f[fk]][tgt(z,t)]+=1
        tot=sum(sum(c.values()) for c in tab.values())
        pure=sum(c.most_common(1)[0][1] for c in tab.values())
        print(f'  {fk:7s}: {pure/tot*100:.1f}%')
# direct equality tests
eq=Counter()
for l,z,t in rows:
    f=fld(l)
    if 'T1_lo5' in f:
        eq['T1_lo5==ntz']+=f['T1_lo5']==t
        eq['T1_lo5==nlz']+=f['T1_lo5']==z
        eq['T1_lo5==63-nlz']+=f['T1_lo5']==(63-z)&0x1F
    if 'T2_hi5' in f:
        eq['T2_hi5==ntz']+=f['T2_hi5']==t
        eq['T2_hi5==nlz']+=f['T2_hi5']==z
        eq['T2_hi5==ntz&0x1F']+=f['T2_hi5']==(t&0x1F)
        eq['T2_hi5==(63-nlz)&0x1F']+=f['T2_hi5']==(63-z)&0x1F
    eq['n']+=1
print('\nequality tests:',dict(eq))
# joint: (T1_lo5,T2_hi5) -> (nlz,ntz)?
tab=defaultdict(Counter)
for l,z,t in rows:
    f=fld(l)
    if 'T1_lo5' in f and 'T2_hi5' in f:
        tab[(f['T1_lo5'],f['T2_hi5'])][(z,t)]+=1
tot=sum(sum(c.values()) for c in tab.values())
pure=sum(c.most_common(1)[0][1] for c in tab.values())
print(f'(T1_lo5,T2_hi5)->(nlz,ntz): {pure/tot*100:.1f}% over {len(tab)} ctx')
# ntz -> end already known; check ntz//8 == 8-end? (trailing UNCHANGED bytes)
c=Counter()
for l,z,t in rows:
    r_,end=l['matches'][0]
    c[(t//8,8-end)]+=1
print('\n(ntz//8, 8-end) agreement:',sum(v for (a,b),v in c.items() if a==b)/sum(c.values())*100,'%')
