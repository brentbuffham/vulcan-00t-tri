#!/usr/bin/env python3
"""DP-align records (each consuming 1..3 GT tris in DXF order) minimizing newness
mismatch. Parts = record split on mid-record E tokens; part i predicts tri t+i via
has-V-token -> isNew. Report cost, consumption histogram, and per-part stats."""
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
isNew=(nn>=1).astype(np.int8)

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
        elif b==0x15: toks.append(('X15',0,0));j+=1
        elif 0xe0<=b<=0xff and j+2<len(pl): toks.append(('E',b,pl[j+1],pl[j+2]));j+=3
        elif b>=0x20 and j+1<len(pl): toks.append((f'T{b>>5}',b,pl[j+1]));j+=2
        else: toks.append(('?',b,0));j+=1
    return toks
recparts=[]
for r in recs:
    toks=tokenize(r[2:])
    parts=[];curt=[]
    for t in toks:
        if t[0]=='E':
            parts.append(curt);curt=[t]
        else: curt.append(t)
    parts.append(curt)
    recparts.append(parts)
partV=[[1 if any(t[0] in ('V1','V2') for t in p) else 0 for p in parts] for parts in recparts]
R=len(recparts)
print(f'records {R}, tris {NT}, total parts {sum(len(p) for p in recparts)}')

# DP: cost[r][t] = min cost aligning first r records to first t tris
BIG=10**9
NEG=-1
# use int16 costs; per record allow k in 1..min(3,len(parts)+1)
INF=np.int32(1<<28)
dp=np.full((R+1,NT+1),INF,dtype=np.int32)
bk=np.zeros((R+1,NT+1),dtype=np.int8)
dp[0,0]=0
for r in range(R):
    pv=partV[r];nparts=len(pv)
    row=dp[r];nrow=dp[r+1]
    for k in (1,2,3):
        # cost of record r consuming tris t..t+k-1
        # part i predicts isNew[t+i]; missing part costs 1, extra parts cost 1 each
        maxt=NT-k
        ts=np.arange(0,maxt+1)
        cost=np.zeros(len(ts),dtype=np.int32)
        for i2 in range(k):
            if i2<nparts:
                cost+= (pv[i2]!=isNew[ts+i2]).astype(np.int32)
            else:
                cost+=1
        cost+=max(0,nparts-k)  # unused parts penalty
        cand=row[ts]+cost
        upd=cand<nrow[ts+k]
        nrow[ts+k]=np.where(upd,cand,nrow[ts+k])
        bk[r+1,ts[upd]+k]=k
print(f'DP total cost @ (R,NT): {dp[R,NT]}  ({dp[R,NT]/NT*100:.1f}% of tris)')
# other endpoints
best_t=int(np.argmin(dp[R])); print(f'best endpoint t={best_t} cost={dp[R,best_t]}')
# backtrack
r,t=R,NT
ks=[]
while r>0:
    k=int(bk[r,t]);ks.append(k);t-=k;r-=1
ks=ks[::-1]
print('consumption histogram:',Counter(ks))
# which records consume 2? correlate with #parts
np_arr=np.array([len(p) for p in recparts]);ka=np.array(ks)
print('parts vs consumed cross-tab:')
for pn in sorted(set(np_arr.tolist())):
    sub=Counter(ka[np_arr==pn].tolist())
    print(f'  parts={pn}: {dict(sorted(sub.items()))}')
