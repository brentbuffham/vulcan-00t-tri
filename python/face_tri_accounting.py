#!/usr/bin/env python3
"""Close the accounting: sub-records (split on mid-record E tokens) should equal
NT=5724. Then align sub-record k <-> GT tri k (DXF order) and test: has-V-token
predicts nn==0 (no new vertex)."""
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
vid={};gt=[];nn=[]
for t in tris_xyz:
    tri=[];new=0
    for k in range(3):
        p=(round(t[(k,0)],3),round(t[(k,1)],3),round(t[(k,2)],3))
        if p not in vid: vid[p]=len(vid);new+=1
        tri.append(vid[p])
    gt.append(tuple(tri));nn.append(new)
nn=np.array(nn);NT=len(gt)

d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
def tokenize(pl):
    toks=[];j=0
    if pl[:1] in (b'\x00',):  # leading pre byte
        toks.append(('pre',0));j=1
    while j<len(pl):
        b=pl[j]
        if b==0x00 and j+1<len(pl): toks.append(('V1',pl[j+1]));j+=2
        elif b==0x01 and j+2<len(pl): toks.append(('V2',(pl[j+1]<<8)|pl[j+2]));j+=3
        elif b==0x15: toks.append(('X15',0));j+=1
        elif 0xe0<=b<=0xff and j+2<len(pl): toks.append(('E',(b<<16)|(pl[j+1]<<8)|pl[j+2]));j+=3
        elif b>=0x20 and j+1<len(pl): toks.append((f'T{b>>5}',(b<<8)|pl[j+1]));j+=2
        else: toks.append(('?',b));j+=1
    return toks
subrecs=[]
for ri,r in enumerate(recs):
    toks=tokenize(r[2:])
    curt=[]
    for t in toks:
        if t[0]=='E':
            subrecs.append((ri,curt));curt=[('E-lead',t[1])]
        else: curt.append(t)
    subrecs.append((ri,curt))
print(f'records {len(recs)} -> sub-records {len(subrecs)}  (GT tris {NT})')
L=min(len(subrecs),NT)
hasV=np.array([any(t[0] in ('V1','V2') for t in toks) for _,toks in subrecs][:L])
isOld=(nn[:L]==0)
agree=(hasV==isOld).mean()*100
print(f'sub-record has-V vs tri nn==0 agreement: {agree:.1f}%  (chance ~50%)')
# where do mismatches happen? first 20 mismatch indices
mis=np.where(hasV!=isOld)[0]
print(f'mismatches: {len(mis)}; first 15: {mis[:15].tolist()}')
print('\nfirst 30: hasV vs nn:')
print('  hasV:',''.join('V' if h else '.' for h in hasV[:30]))
print('  nn  :',''.join(str(x) for x in nn[:30]))
