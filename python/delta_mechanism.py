#!/usr/bin/env python3
"""MECHANISM test for placement: is the payload window simply the span of
CHANGED bytes between ref and new (minimal window)? Then what do the T-token
bit fields (T1 lo5, T2 hi5) physically encode? Correlate against:
delta magnitude (log2), delta sign, changed-byte span, last-changed byte."""
import json, math, struct
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
clean=[l for l in L if l['verified'] and len(l['matches'])==1 and l.get('fb')]
print(f'{len(clean)} clean labels with bytes')
def f64(h): return struct.unpack('>d',bytes.fromhex(h))[0]
rows=[]
for l in clean:
    rb=bytes.fromhex(l['ref']); nb_=bytes.fromhex(l['fb'])
    r,end=l['matches'][0]; k0=end-(l['nb']-r)
    diffs=[i for i in range(8) if rb[i]!=nb_[i]]
    first=diffs[0] if diffs else -1; last=diffs[-1] if diffs else -1
    rv=f64(l['ref']); nv=f64(l['fb']); dl=nv-rv
    rows.append(dict(l=l,k0=k0,end=end,first=first,last=last,
                     dl=dl,mag=math.floor(math.log2(abs(dl))) if dl else -99))
# 1. minimal window?
ok_end=sum(1 for x in rows if (x['end']==8)==(x['last']==7))
ok_k0 =sum(1 for x in rows if x['first']==x['k0'] or x['first']==-1)
within=sum(1 for x in rows if x['first']>=x['k0'] and x['last']<x['end'])
exact =sum(1 for x in rows if x['first']==x['k0'] and x['last']==x['end']-1)
print(f'end==8 iff byte7 changed: {ok_end}/{len(rows)} ({ok_end/len(rows)*100:.1f}%)')
print(f'window starts AT first changed byte: {ok_k0}/{len(rows)} ({ok_k0/len(rows)*100:.1f}%)')
print(f'changed span within window: {within}/{len(rows)}; window EXACTLY = span: {exact}/{len(rows)}')
# window slack distribution (payload bytes equal to ref at edges)
slack=Counter((x['first']-x['k0'],(x['end']-1)-x['last']) for x in rows if x['first']>=0)
print('window slack (lead,trail):',dict(slack.most_common(8)))

# 2. what do T1 lo5 / T2 hi5 encode?
print('\n--- T1 vs delta magnitude (log2|delta|), per axis ---')
for a in range(3):
    sub=[x for x in rows if x['l']['axis']==a and x['l']['T1']>=0]
    tab=defaultdict(Counter)
    for x in sub: tab[x['l']['T1']&0x1F][x['mag']]+=1
    print(f'axis {a}: T1_lo5 -> mag (top rows)')
    for k in sorted(tab,key=lambda k:-sum(tab[k].values()))[:8]:
        c=tab[k];n=sum(c.values())
        print(f'  lo5={k:<3} n={n:<5} mags {dict(c.most_common(5))}')
print('\n--- T2_hi5 vs delta magnitude, per axis ---')
for a in range(3):
    sub=[x for x in rows if x['l']['axis']==a and x['l']['T2']>=0]
    tab=defaultdict(Counter)
    for x in sub: tab[x['l']['T2']>>3][x['mag']]+=1
    print(f'axis {a}:')
    for k in sorted(tab,key=lambda k:-sum(tab[k].values()))[:8]:
        c=tab[k];n=sum(c.values())
        print(f'  hi5={k:<3} n={n:<5} mags {dict(c.most_common(5))}')
# sign?
print('\n--- delta sign vs T bits ---')
for fk,f in (('T1_lo5',lambda l:l['T1']&0x1F if l['T1']>=0 else -1),
             ('T2_hi5',lambda l:l['T2']>>3 if l['T2']>=0 else -1),
             ('T1b5',lambda l:(l['T1']>>5)&1 if l['T1']>=0 else -1),
             ('T2b3',lambda l:(l['T2']>>3)&1 if l['T2']>=0 else -1),
             ('T2b7',lambda l:(l['T2']>>7)&1 if l['T2']>=0 else -1)):
    tab=defaultdict(Counter)
    for x in rows: tab[f(x['l'])][1 if x['dl']>0 else 0]+=1
    pure=sum(c.most_common(1)[0][1] for c in tab.values());tot=sum(sum(c.values()) for c in tab.values())
    print(f'  {fk}: sign purity {pure/tot*100:.1f}%')
# 3. is T1==0x20 <-> byte7 changed, globally?
tab=Counter(((x['l']['T1']==0x20),(x['last']==7)) for x in rows if x['l']['T1']>=0)
print('\n(T1==0x20, byte7changed):',dict(tab))
# 4. maybe T fields encode the LOW BITS of the new value's last window byte?
agree=Counter()
for x in rows:
    l=x['l']
    if l['T1']<0: continue
    nbytes=bytes.fromhex(l['fb'])
    lastpay=nbytes[x['end']-1]
    agree['T1lo5==last&0x1F']+= (l['T1']&0x1F)==(lastpay&0x1F)
    agree['T2hi5==last>>3']+= (l['T2']>>3)==(lastpay>>3)
    agree['n']+=1
print('low-bit ride hypothesis:',dict(agree))
