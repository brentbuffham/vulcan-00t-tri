#!/usr/bin/env python3
"""Cross-correlate record features vs GT newness at lags; split variants:
(a) no split, (b) split on all E, (c) split only on E with specific lead byte/arg.
Report best agreement config."""
import numpy as np
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
dxf=r'C:/Users/brent/Downloads/ac-653-221-inteceptsDXF.dxf'
lines=open(dxf,'r',errors='ignore').read().split('\n')
i=0;n=len(lines);tris_xyz=[];cur={};in3d=False
def fnum(s):
    try: return float(s)
    except: return None
while i<n-1:
    code=lines[i].strip(); val=lines[i+1].strip() if i+1<n else ''
    if code=='0':
        if in3d and len(cur)>=9: tris_xyz.append(cur.copy())
        in3d=(val.upper()=='3DFACE'); cur={}
    elif in3d:
        c=fnum(code); f=fnum(val)
        if c is not None and f is not None and abs(f)<1e8:
            ci=int(c)
            for k in range(4):
                if ci==10+k: cur[(k,0)]=f
                elif ci==20+k: cur[(k,1)]=f
                elif ci==30+k: cur[(k,2)]=f
    i+=2
vid={};nn=[]
for t in tris_xyz:
    new=0
    for k in range(3):
        p=(round(t[(k,0)],3),round(t[(k,1)],3),round(t[(k,2)],3))
        if p not in vid: vid[p]=len(vid);new+=1
    nn.append(new)
nn=np.array(nn);NT=len(nn)

d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
def tokenize(pl):
    toks=[];j=0
    if pl[:1]==b'\x00': j=1
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl): toks.append(('V1',pl[j+1]));j+=2
        elif b==0x01 and j+2<len(pl): toks.append(('V2',(pl[j+1]<<8)|pl[j+2]));j+=3
        elif b==0x15: toks.append(('X15',0));j+=1
        elif 0xe0<=b<=0xff and j+2<len(pl): toks.append(('E',b,pl[j+1],pl[j+2]));j+=3
        elif b>=0x20 and j+1<len(pl): toks.append((f'T{b>>5}',b,pl[j+1]));j+=2
        else: toks.append(('?',b,0));j+=1
    return toks
allt=[tokenize(r[2:]) for r in recs]
# which E lead-bytes/args exist mid-record?
ec=Counter((t[1],t[2]) for toks in allt for t in toks if t[0]=='E')
print('mid-record E (lead,arg1) counts:',ec.most_common(12))

def build_subrecs(split_pred):
    subs=[]
    for toks in allt:
        curt=[]
        for t in toks:
            if t[0]=='E' and split_pred(t):
                subs.append(curt);curt=[('Elead',)+t[1:]]
            else: curt.append(t)
        subs.append(curt)
    return subs

variants={
 'no-split': build_subrecs(lambda t: False),
 'all-E': build_subrecs(lambda t: True),
 'E-e0-only': build_subrecs(lambda t: t[1]==0xe0),
 'E-arg-odd': build_subrecs(lambda t: t[2]%2==1),
 'E-arg07-0b': build_subrecs(lambda t: t[2] in (0x07,0x0b)),
}
isNew=(nn==1)|(nn>=2)
for name,subs in variants.items():
    hasV=np.array([any(t[0] in ('V1','V2') for t in toks) for toks in subs])
    best=(0,-99)
    for lag in range(-4,5):
        if lag>=0: a=hasV[:len(hasV)-lag if lag else None]; b=isNew[lag:lag+len(a)]
        else: a=hasV[-lag:]; b=isNew[:len(a)]
        L=min(len(a),len(b)); a=a[:L]; b=b[:L]
        ag=(a==b).mean()*100
        if ag>best[1]: best=(lag,ag)
    print(f'{name:12s}: n={len(subs):5d}  best lag={best[0]:+d} agreement={best[1]:.1f}%')
