#!/usr/bin/env python3
"""Rigorous, NON-degenerate grammar learning. Keep prev EXACT (snap to GT). For each
DELTA, search axis a in {0,1,2} and splice length k in 3..7 for a result that (a) hits
a TRUE GT coordinate on axis a within 5mm AND (b) actually MOVES (>5cm from prev) ->
rules out the degenerate copy-prev. Tabulate which (count->k) and which axis-vs-cycle
wins, and coverage. This learns the real per-record axis + splice rule."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gax=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def gmatch(v,a,tol=0.005):
    arr=gax[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return arr[j]
    return None
d=open(oot,'rb').read()
face_start=next((i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03), len(d))
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
prevb=[None,None,None]; prevv=[None,None,None]; pos=8326; cyc=0
ck=Counter(); axcyc=Counter(); cov=0; nd=0; multi=0
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); a=band(v); m=gmatch(v,a)
        vv=m if m is not None else v
        prevb[a]=struct.pack('>d',vv); prevv[a]=vv; cyc=(a+1)%3; pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            nd+=1; cands=[]
            for a in range(3):
                if prevb[a] is None: continue
                for k in range(3,8):
                    val=be(bytes(prevb[a][:8-k])+d[rec_end-k:rec_end])
                    m=gmatch(val,a)
                    if m is not None and abs(m-prevv[a])>0.05:
                        cands.append((a,k,m)); break
            if cands:
                cov+=1
                if len(cands)>1: multi+=1
                a,k,m=cands[0]; ck[(count,k)]+=1; axcyc[('same' if a==cyc else 'diff')]+=1
                prevb[a]=struct.pack('>d',m); prevv[a]=m; cyc=(a+1)%3
            pos=rec_end; continue
    pos+=1
print(f'deltas={nd:,} matched(moved+exactGT)={cov:,} ({cov/max(1,nd)*100:.1f}%) ambiguous={multi:,}')
print(f'count->k winners: {dict(sorted(ck.items()))}')
print(f'axis vs cycle: {dict(axcyc)}')
