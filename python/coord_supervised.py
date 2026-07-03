#!/usr/bin/env python3
"""GT-supervised axis labeling with the UNIFIED token grammar.
Tokens: FULL = raw 8-byte BE double (first byte in {40,41,C0,C1} + sane value);
T-token = 2 bytes (b>=0x20, incl 0xa0/0xc0-class not matching FULL);
E-token = 3 bytes (0xe0-0xff); V-token = prefix c in 0x00..0x06 -> c+1 payload bytes.
State: 3 splice registers (X,Y,Z). Each V-token: splice each register; label = axis
whose result hits the GT grid (2mm). Snap register to GT (cascade-exact, scoring only).
Learn: (prev_axis, preceding T-token) -> axis transition. Report purity."""
import sys, struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=sys.argv[1] if len(sys.argv)>1 else r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gt_snap(v,a,tol=0.0006):
    arr=gA[a]; i=np.searchsorted(arr,v)
    best=None
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol:
            if best is None or abs(arr[j]-v)<abs(best-v): best=arr[j]
    return best
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1

regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
pos=8350
lastT=None; prev_axis=2
labels=[]  # (pos, lastT, prev_axis, label axis or -1/-2, count)
stats=Counter()
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        v=be(d[pos:pos+8]); a=band(v)
        regs[a][:]=d[pos:pos+8]
        labels.append((pos,lastT,prev_axis,a,'F'))
        prev_axis=a; stats['full']+=1; pos+=8; lastT=None; continue
    if b<=0x06 and pos+1+b+1<=face_start:
        nb=b+1; payload=d[pos+1:pos+1+nb]
        cands=[]
        for a in range(3):
            vb=bytes(regs[a][:8-nb])+payload
            v=be(vb)
            m=gt_snap(v,a)
            if m is not None: cands.append((a,m))
        if len(cands)==1:
            a,m=cands[0]
            regs[a][:]=bytes(regs[a][:8-nb])+payload  # keep byte-exact cascade
            labels.append((pos,lastT,prev_axis,a,b))
            prev_axis=a; stats['delta_labeled']+=1
        elif len(cands)>1:
            labels.append((pos,lastT,prev_axis,-2,b)); stats['delta_ambig']+=1
        else:
            labels.append((pos,lastT,prev_axis,-1,b)); stats['delta_miss']+=1
        pos+=1+nb; lastT=None; continue
    if 0xe0<=b<=0xff and pos+3<=face_start:
        lastT=('E',d[pos],d[pos+1],d[pos+2]); pos+=3; stats['etok']+=1; continue
    if b>=0x20 and pos+2<=face_start:
        lastT=('T',d[pos],d[pos+1]); pos+=2; stats['ttok']+=1; continue
    if 0x07<=b<=0x1f:
        lastT=('S',d[pos],None); pos+=1; stats['solo']+=1; continue
    stats['junk']+=1; pos+=1
print('token stats:',dict(stats))
lab=[l for l in labels if l[3]>=0 and l[4]!='F']
print(f'labeled deltas: {len(lab)}  ambig: {stats["delta_ambig"]}  miss: {stats["delta_miss"]}')
axc=Counter(l[3] for l in lab)
print('axis label counts: X=%d Y=%d Z=%d'%(axc[0],axc[1],axc[2]))
# transition purity: (prev_axis, T-token bytes) -> label
rule=defaultdict(Counter)
for pos_,lt,pa,a,c in lab:
    key=(pa, lt[1] if lt else None, lt[2] if lt else None)
    rule[key][a]+=1
tot=pure=0
rows=[]
for key,c in rule.items():
    n=sum(c.values()); top=c.most_common(1)[0][1]
    tot+=n; pure+=top
    rows.append((n,key,dict(c)))
print(f'\nrule purity (prev_axis, Tbytes)->axis: {pure}/{tot} = {pure/max(tot,1)*100:.1f}%')
rows.sort(key=lambda r:(-r[0],str(r[1])))
print('top 25 contexts:')
for n,key,c in rows[:25]:
    pa,t1,t2=key
    t=f'{t1:02x} {t2:02x}' if t1 is not None else 'None '
    print(f'  n={n:4d} prev={"XYZ"[pa]} T=[{t}] -> {c}')
# also: transition delta histogram (label - prev_axis mod 3)
dc=Counter((l[3]-l[2])%3 for l in lab)
print('\naxis transition (label-prev)%3: STAY=%d FWD=%d BACK=%d'%(dc[0],dc[1],dc[2]))
