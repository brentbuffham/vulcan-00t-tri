#!/usr/bin/env python3
"""The splice is exact; the lock is AXIS. Decode with exact splice + GT-picked axis
(keep prev exact), and for every correctly-decoded delta record the (tag, sep, count)
and its TRUE axis. Tabulate which byte predicts the axis -> the GT-free axis rule."""
import sys, struct
import numpy as np
from collections import Counter, defaultdict
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def near(v,a,tol=0.002):
    arr=gA[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return arr[j]
    return None
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
prev=[d[8326:8334],d[8334:8342],d[8342:8350]]; pos=8350
bySep=defaultdict(lambda:[0,0,0]); byTag=defaultdict(lambda:[0,0,0]); byCnt=defaultdict(lambda:[0,0,0])
ambig=0; nd=0; lastaxis=2; bySepTrans=defaultdict(lambda:[0,0,0])
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); a=band(v); prev[a]=d[pos:pos+8]; lastaxis=a; pos+=8; continue
    p=pos; tag=-1
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): tag=d[p]; p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        sep=d[p]; count=d[p+1]; nb=count+1; rec_end=p+2+nb
        if rec_end<=face_start:
            nd+=1; payload=d[rec_end-nb:rec_end]
            cand=[]
            for a in range(3):
                val=be(bytes(prev[a][:8-nb])+payload); m=near(val,a)
                if m is not None: cand.append((a,m))
            if len(cand)==1:
                a,m=cand[0]; bySep[sep][a]+=1; byTag[tag][a]+=1; byCnt[count][a]+=1
                bySepTrans[(lastaxis,sep)][a]+=1
                prev[a]=struct.pack('>d',m); lastaxis=a
            elif len(cand)>1: ambig+=1
            pos=rec_end; continue
    pos+=1
def show(name,tab):
    print(f'\n{name} -> [X,Y,Z] axis (pure rules only):')
    for k in sorted(tab,key=lambda x:-sum(tab[x]))[:16]:
        c=tab[k]; t=sum(c); top=max(range(3),key=lambda a:c[a]); pur=c[top]/t*100
        flag=' <== PURE' if pur>=90 and t>=20 else ''
        kk=k if isinstance(k,int) else k
        print(f'  {kk if not isinstance(kk,int) else hex(kk)}: X={c[0]} Y={c[1]} Z={c[2]}  ->{"XYZ"[top]} {pur:.0f}% (n={t}){flag}')
print(f'unambiguous deltas={nd-ambig:,} ambiguous={ambig:,}')
show('SEP byte',bySep); show('COUNT',byCnt)
print('\n(lastaxis,SEP) -> axis [X,Y,Z] top 16:')
for k in sorted(bySepTrans,key=lambda x:-sum(bySepTrans[x]))[:16]:
    c=bySepTrans[k]; t=sum(c); top=max(range(3),key=lambda a:c[a]); pur=c[top]/t*100
    flag=' <== PURE' if pur>=90 and t>=15 else ''
    print(f'  last={"XYZ"[k[0]]} sep={hex(k[1])}: X={c[0]} Y={c[1]} Z={c[2]} ->{"XYZ"[top]} {pur:.0f}% (n={t}){flag}')
