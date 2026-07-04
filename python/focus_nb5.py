#!/usr/bin/env python3
"""Focus: the ONLY ambiguous placement class = nb=5, p_hi2=0 (p=0x04).
end=7 (k0=2) vs end=8 (k0=3). Which bit of (T1,T2,axis,neighbors) decides?
Also reframe: k0=end-nb is 2 or 3 everywhere -> test k0 as the target across
ALL nb classes (maybe one formula covers everything)."""
import json, itertools
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1]
for l in clean: l['r'],l['end']=l['matches'][0]
bytok={l['tok']:l for l in L}

# ---- reframe: k0 across all clean labels ----
k0c=Counter(l['end']-(l['nb']-l['r']) for l in clean)
print('k0 (window start byte) distribution, all clean:',dict(k0c))
print('k0 by axis:')
t=defaultdict(Counter)
for l in clean: t[l['axis']][l['end']-(l['nb']-l['r'])]+=1
for a in sorted(t): print(f'  axis {a}: {dict(t[a])}')

# ---- the ambiguous class ----
amb=[l for l in clean if l['nb']==5 and l['p']==0x04]
print(f'\nnb=5 p=0x04 class: {len(amb)}  end7={sum(1 for l in amb if l["end"]==7)} end8={sum(1 for l in amb if l["end"]==8)}')

def purity(labels,fkeyf,tkey):
    tab=defaultdict(Counter)
    for l in labels: tab[fkeyf(l)][tkey(l)]+=1
    tot=sum(sum(c.values()) for c in tab.values())
    pure=sum(c.most_common(1)[0][1] for c in tab.values())
    return pure/tot,tab

tget=lambda l:l['end']
base=Counter(tget(l) for l in amb)
print(f'baseline: {base.most_common(1)[0][1]/len(amb)*100:.1f}%')

cands={}
cands['axis']=lambda l:l['axis']
for b in range(8):
    cands[f'T1b{b}']=lambda l,b=b:((l['T1']>>b)&1) if l['T1']>=0 else -1
    cands[f'T2b{b}']=lambda l,b=b:((l['T2']>>b)&1) if l['T2']>=0 else -1
cands['T1']=lambda l:l['T1']
cands['T2']=lambda l:l['T2']
cands['T1_lo5']=lambda l:l['T1']&0x1F if l['T1']>=0 else -1
cands['T2_hi5']=lambda l:l['T2']>>3 if l['T2']>=0 else -1
cands['T1_hi3']=lambda l:l['T1']>>5 if l['T1']>=0 else -1
# neighbor context: previous label's (p / end / axis), token adjacency
def prev_ctx(l,key):
    pl=bytok.get(l['tok']-1)
    if pl is None: return -2
    if key=='p': return pl['p'] if pl['p'] is not None else -1
    if key=='end': return pl['matches'][0][1] if pl.get('matches') else -1
    return -2
cands['prev_p']=lambda l:prev_ctx(l,'p')
cands['prev_end']=lambda l:prev_ctx(l,'end')

sc=[]
for name,f in cands.items():
    pu,tab=purity(amb,f,tget)
    sc.append((pu,name,tab))
sc.sort(key=lambda x:-x[0])
print('\nsingle-field purity on the ambiguous class:')
for pu,name,tab in sc[:12]:
    print(f'  {name:8s}: {pu*100:.1f}%')
print('\ntop-3 field tables:')
for pu,name,tab in sc[:3]:
    for k in sorted(tab,key=lambda k:-sum(tab[k].values()))[:10]:
        c=tab[k]; n=sum(c.values())
        print(f'  {name}={k}: n={n:<5} {dict(c.most_common(3))}')
    print()

print('field PAIRS on ambiguous class:')
tops=[name for _,name,_ in sc[:10]]
ps=[]
for a,b in itertools.combinations(tops,2):
    fa,fb=cands[a],cands[b]
    pu,tab=purity(amb,lambda l:(fa(l),fb(l)),tget)
    ps.append((pu,a,b,len(tab)))
ps.sort(reverse=True)
for pu,a,b,n in ps[:10]:
    print(f'  ({a},{b}): {pu*100:.1f}%  [{n} contexts]')

# full T1,T2 on ambiguous class
pu,tab=purity(amb,lambda l:(l['T1'],l['T2']),tget)
ns=sum(1 for c in tab.values() if len(c)==1)
print(f'\nfull (T1,T2) on ambiguous: {pu*100:.2f}% over {len(tab)} contexts ({ns} pure)')
# how many ambiguous tokens sit in a MIXED (T1,T2) context?
mixed=sum(sum(c.values()) for c in tab.values() if len(c)>1)
print(f'tokens in mixed (T1,T2) contexts: {mixed}/{len(amb)}')
# show largest mixed contexts
print('largest MIXED contexts:')
for k in sorted((k for k in tab if len(tab[k])>1),key=lambda k:-sum(tab[k].values()))[:10]:
    print(f'  T1={k[0]:#04x} T2={k[1]:#04x}: {dict(tab[k])}')
