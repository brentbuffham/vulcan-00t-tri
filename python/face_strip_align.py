#!/usr/bin/env python3
"""GT strip structure vs record classes.
GT: classify each tri (in DXF order) by relation to predecessor: shares edge (strip
continue) vs restart. Also newness. Records: tokenize with the unified grammar,
classify by leading token signature. Compare sequences/counts."""
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
vid={};gt=[]
for t in tris_xyz:
    tri=[]
    for k in range(3):
        p=(round(t[(k,0)],3),round(t[(k,1)],3),round(t[(k,2)],3))
        if p not in vid: vid[p]=len(vid)
        tri.append(vid[p])
    gt.append(tuple(tri))
NT=len(gt)
# classify each tri vs predecessor
kinds=[];prev=None
for k,tri in enumerate(gt):
    s=set(tri)
    if prev is None: kinds.append('S')  # start
    else:
        shared=len(s & set(prev))
        nn=len([v for v in tri if v>=len(set(v2 for t2 in gt[:k] for v2 in t2))]) if False else None
        kinds.append({2:'C',1:'V',0:'R',3:'D'}[shared])
    prev=tri
kc=Counter(kinds)
print(f'GT tris {NT}: continue(share edge)={kc["C"]} share-vertex-only={kc["V"]} restart(disjoint)={kc["R"]} dup={kc.get("D",0)}')
# run lengths of C between non-C
runs=[];r=0
for k in kinds:
    if k=='C': r+=1
    else:
        if r: runs.append(r)
        r=0
if r: runs.append(r)
print(f'strip segments: {len(runs)+1}ish, mean len {np.mean(runs):.1f}, restarts(V/R total)={kc["V"]+kc["R"]}')

# ---- tokenize records ----
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
recs=[d[occ[k]:occ[k+1]] for k in range(1,len(occ)-1)]
def tokenize(pl):
    toks=[];j=0
    while j<len(pl):
        b=pl[j]
        if b in (0x00,0x05) and j+1<len(pl) and j==0: toks.append(('pre',b));j+=1
        elif b==0x00 and j+1<len(pl): toks.append(('V1',pl[j+1]));j+=2
        elif b==0x01 and j+2<len(pl): toks.append(('V2',(pl[j+1]<<8)|pl[j+2]));j+=3
        elif b==0x15: toks.append(('X15',));j+=1
        elif 0xe0<=b<=0xff and j+2<len(pl): toks.append(('E',b,pl[j+1],pl[j+2]));j+=3
        elif b>=0x20 and j+1<len(pl): toks.append((f'T{b>>5}',b,pl[j+1]));j+=2
        else: toks.append(('?',b));j+=1
    return toks
sigs=Counter();recstok=[]
for r in recs:
    toks=tokenize(r[2:])
    recstok.append(toks)
    sigs[' '.join(t[0] for t in toks)]+=1
print(f'\nrecords {len(recs)}; top 20 token signatures:')
for s,c in sigs.most_common(20): print(f'  {c:5d}  {s}')
# counts of interest
nV=sum(1 for toks in recstok if any(t[0] in ('V1','V2') for t in toks))
print(f'\nrecords containing V-token: {nV}')
print(f'total V tokens: {sum(1 for toks in recstok for t in toks if t[0] in ("V1","V2"))}')
nT2=sum(1 for toks in recstok if sum(1 for t in toks if t[0].startswith("T"))>=4)
print(f'records with >=4 T-tokens: {nT2}')
