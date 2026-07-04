#!/usr/bin/env python3
"""Extract the exact T1 -> k0 (window start byte) mapping.
k0 = nlz//8 of ref XOR new = leading unchanged bytes. T1 predicts 97.3%.
Find the bit rule + explain the misfits (prev context? axis?)."""
import json
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1 and l.get('fb')]
rows=[]
for l in clean:
    x=int(l['ref'],16)^int(l['fb'],16)
    if x==0 or l['T1']<0: continue
    k0=(64-x.bit_length())//8
    rows.append((l,k0))
print(f'{len(rows)} rows')
tab=defaultdict(Counter)
for l,k0 in rows: tab[l['T1']][k0]+=1
print('T1 -> k0 (all T1 with n>=3):')
for t1 in sorted(tab):
    c=tab[t1]; n=sum(c.values())
    if n<3: continue
    top=c.most_common(1)[0]
    print(f'  T1={t1:#04x} ({t1:3d}) n={n:<5} k0 {dict(c.most_common(4))}  '
          f'lo5={t1&0x1F:2d} hi3={t1>>5}')
# candidate formulas
tests={
 'k0==2+(T1==0x20)': lambda t1:2+(1 if t1==0x20 else 0),
 'k0==3-(T1>0x20)':  lambda t1:3-(1 if t1>0x20 else 0),
 'k0==(T1>>5)+1':    lambda t1:(t1>>5)+1,
}
for name,f in tests.items():
    ok=sum(1 for l,k0 in rows if f(l['T1'])==k0)
    print(f'{name}: {ok/len(rows)*100:.1f}%')
# per (T1, axis)
print('\nT1 x axis -> k0 purity:')
tab2=defaultdict(Counter)
for l,k0 in rows: tab2[(l['T1'],l['axis'])][k0]+=1
pure=sum(c.most_common(1)[0][1] for c in tab2.values())
print(f'  {pure/len(rows)*100:.2f}% over {len(tab2)} contexts')
# per (T1,T2)
tab3=defaultdict(Counter)
for l,k0 in rows: tab3[(l['T1'],l['T2'])][k0]+=1
pure=sum(c.most_common(1)[0][1] for c in tab3.values())
print(f'(T1,T2)->k0: {pure/len(rows)*100:.2f}% over {len(tab3)} contexts')
# per (T1, p_hi2)
tab4=defaultdict(Counter)
for l,k0 in rows: tab4[(l['T1'],l['p']>>3)][k0]+=1
pure=sum(c.most_common(1)[0][1] for c in tab4.values())
print(f'(T1,p_hi2)->k0: {pure/len(rows)*100:.2f}% over {len(tab4)} contexts')
# misfit analysis for the best simple rule: majority per T1
maj={t1:tab[t1].most_common(1)[0][0] for t1 in tab}
mis=[(l,k0) for l,k0 in rows if maj[l['T1']]!=k0]
print(f'\nmisfits vs per-T1 majority: {len(mis)}')
mc=Counter((l['T1'],l['axis'],k0) for l,k0 in mis)
for k,v in mc.most_common(12): print('  T1=%#04x axis=%d k0=%d: %d'%(*k,v))
# does p_hi2 rescue T1=0x20 misfits?
sub=[(l,k0) for l,k0 in rows if l['T1']==0x20]
t=defaultdict(Counter)
for l,k0 in sub: t[l['p']>>3][k0]+=1
print('\nT1==0x20: p_hi2 -> k0:',{k:dict(v) for k,v in t.items()})
sub2=[(l,k0) for l,k0 in sub if (l['p']>>3)==0]
t2=defaultdict(Counter)
for l,k0 in sub2: t2[l['T2']][k0]+=1
print('T1==0x20,p_hi2==0: T2 -> k0 (n>=5):')
for t2k in sorted(t2):
    c=t2[t2k];n=sum(c.values())
    if n<5: continue
    print(f'  T2={t2k:#04x} n={n:<4} {dict(c.most_common(3))}')
