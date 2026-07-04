#!/usr/bin/env python3
"""TASK 2 — read the placement/event bit formula from commit labels.
Input: commit_labels.json (from instrumented closing_solve.py) = exact
per-token actions at verified commits. NO ground truth used here — only the
solver's own labels. Questions:
  1. PLACEMENT: which bits of (p, T1, T2) predict (r, end)?
  2. EVENTS: which contexts mark refine / split / two-token / unmodeled?
Method: purity crosstabs over candidate bit fields + per-bit mutual info."""
import json, itertools
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
print(f'{len(L)} labels loaded')

# ---------- partition ----------
# clean splice labels: verified, exactly one (r,end) match, normal-flag
clean=[l for l in L if l['verified'] and len(l['matches'])==1
       and l['flag'] in ('plain','yid','x2','y2','z2','refX','refY','refZpre','splitZX','splitYZ','splitXY','resync')]
ambig=[l for l in L if l['verified'] and len(l['matches'])>1]
gtpk =[l for l in L if l['verified'] and not l['matches']]       # unmodeled events
evs  =[l for l in L if not l['verified']]                        # refine/split/two halves
print(f'clean(unique r,end)={len(clean)}  ambiguous={len(ambig)}  gt-packed(event)={len(gtpk)}  struct-events={len(evs)}')

for l in clean: l['r'],l['end']=l['matches'][0]
print('\n(r,end) distribution on clean labels:')
for k,c in Counter((l['r'],l['end']) for l in clean).most_common():
    print(f'  r={k[0]} end={k[1]}: {c}')
print('\nby nb (payload length):')
tab=defaultdict(Counter)
for l in clean: tab[l['nb']][(l['r'],l['end'])]+=1
for nb in sorted(tab):
    print(f'  nb={nb}: {dict(tab[nb].most_common(6))}')

# ---------- candidate bit fields ----------
def fields(l):
    p=l['p'] if l['p'] is not None else -1
    T1=l['T1']; T2=l['T2']
    f={
      'p':p, 'p_hi2':p>>3 if p>=0 else -1, 'p_lo3':p&7 if p>=0 else -1,
      'T1':T1,'T2':T2,
      'T1_lo5':T1&0x1F if T1>=0 else -1, 'T1_hi3':T1>>5 if T1>=0 else -1,
      'T2_hi5':T2>>3 if T2>=0 else -1, 'T2_lo3':T2&7 if T2>=0 else -1,
      'noT':1 if T1<0 else 0, 'nb':l['nb'],
    }
    for b in range(8):
        if T1>=0: f[f'T1b{b}']=(T1>>b)&1
        if T2>=0: f[f'T2b{b}']=(T2>>b)&1
        if p>=0 and b<5: f[f'pb{b}']=(p>>b)&1
    return f

def purity(labels,fkey,tkey):
    """weighted purity of field->target mapping + table"""
    tab=defaultdict(Counter)
    for l in labels:
        f=fields(l)
        if fkey not in f: continue
        tab[f[fkey]][tkey(l)]+=1
    tot=sum(sum(c.values()) for c in tab.values())
    if not tot: return 0,tab
    pure=sum(c.most_common(1)[0][1] for c in tab.values())
    return pure/tot,tab

# ---------- 1. placement formula ----------
print('\n================ PLACEMENT (r,end) predictors on clean labels ================')
tget=lambda l:(l['r'],l['end'])
base=Counter(tget(l) for l in clean)
print(f'baseline (majority class): {base.most_common(1)[0][1]/len(clean)*100:.1f}%')
scores=[]
for fk in ['p','p_hi2','p_lo3','T1','T2','T1_lo5','T1_hi3','T2_hi5','T2_lo3','noT','nb']+\
          [f'T1b{b}' for b in range(8)]+[f'T2b{b}' for b in range(8)]+[f'pb{b}' for b in range(5)]:
    pu,_=purity(clean,fk,tget)
    scores.append((pu,fk))
scores.sort(reverse=True)
for pu,fk in scores[:14]:
    print(f'  {fk:8s}: {pu*100:.1f}%')

# pairs of top single fields
print('\ntop field PAIRS:')
tops=[fk for _,fk in scores[:8]]
pairsc=[]
for a,b in itertools.combinations(tops,2):
    tab=defaultdict(Counter)
    for l in clean:
        f=fields(l); tab[(f.get(a),f.get(b))][tget(l)]+=1
    tot=sum(sum(c.values()) for c in tab.values())
    pure=sum(c.most_common(1)[0][1] for c in tab.values())
    pairsc.append((pure/tot,a,b,len(tab)))
pairsc.sort(reverse=True)
for pu,a,b,nctx in pairsc[:8]:
    print(f'  ({a},{b}): {pu*100:.1f}%  [{nctx} contexts]')

# full (p,T1,T2) context purity (upper bound)
tab=defaultdict(Counter)
for l in clean: tab[(l['p'],l['T1'],l['T2'])][tget(l)]+=1
tot=sum(sum(c.values()) for c in tab.values())
pure=sum(c.most_common(1)[0][1] for c in tab.values())
print(f'\nfull (p,T1,T2) context: {pure/tot*100:.2f}% over {len(tab)} contexts '
      f'({sum(1 for c in tab.values() if len(c)==1)} single-action)')

# show the crosstab for the best pair
pu,a,b,_=pairsc[0]
print(f'\ncrosstab {a} x {b} -> (r,end)  [n>=5 shown]')
tab=defaultdict(Counter)
for l in clean:
    f=fields(l); tab[(f.get(a),f.get(b))][tget(l)]+=1
for k in sorted(tab,key=lambda k:-sum(tab[k].values())):
    c=tab[k]; n=sum(c.values())
    if n<5: continue
    top=c.most_common(1)[0]
    print(f'  {a}={k[0]:>4} {b}={k[1]:>4}: n={n:<5} top={top[0]} ({top[1]/n*100:.0f}%)  {dict(c.most_common(3))}')

# ---------- 2. event signal ----------
print('\n================ EVENT signal ================')
# classes: normal(clean val) vs each event role
def ev_class(l):
    if not l['verified']: return l['role']            # refine/split/two1/two2
    if not l['matches']: return 'unmod'               # GT-packed (lenY/lenZ/yid2 fail)
    return 'normal'
allL=clean+gtpk+evs
cls=Counter(ev_class(l) for l in allL)
print('classes:',dict(cls))
print('\nper-class context profile (p_lo3 / T1_lo5 / T2_hi5 / noT):')
for c in cls:
    sub=[l for l in allL if ev_class(l)==c]
    for fk in ('p_lo3','T1_lo5','T2_hi5','noT'):
        cc=Counter(fields(l).get(fk) for l in sub)
        top=', '.join(f'{k}:{v}' for k,v in cc.most_common(5))
        print(f'  {c:8s} {fk:7s}: {top}')
    print()

# can any single field separate normal vs any event class?
print('field separation power normal-vs-event (purity of field->is_event):')
evmark=lambda l:0 if ev_class(l)=='normal' else 1
sc=[]
for fk in ['p','p_hi2','p_lo3','T1_lo5','T1_hi3','T2_hi5','T2_lo3','noT','nb']+\
          [f'T1b{b}' for b in range(8)]+[f'T2b{b}' for b in range(8)]+[f'pb{b}' for b in range(5)]:
    pu,_=purity(allL,fk,evmark)
    sc.append((pu,fk))
sc.sort(reverse=True)
nev=sum(1 for l in allL if evmark(l))
print(f'baseline (all-normal): {(1-nev/len(allL))*100:.1f}%  (events={nev})')
for pu,fk in sc[:10]:
    print(f'  {fk:8s}: {pu*100:.1f}%')

# save the trusted full-context table for deterministic_v3
out={}
for k,c in tab.items(): pass
ctx=defaultdict(Counter)
for l in clean: ctx[f"{l['p']},{l['T1']},{l['T2']}"][f"{l['r']},{l['end']}"]+=1
json.dump({k:dict(v) for k,v in ctx.items()},open(sp+r'\action_table.json','w'))
print(f'\nsaved action_table.json ({len(ctx)} contexts)')
