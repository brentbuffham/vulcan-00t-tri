#!/usr/bin/env python3
"""(1) Rule out inversion/swap: confirm X-fulls are GT eastings, Y-fulls GT northings.
(2) Test whether the byte-splice deltas are REALLY decoding or just hitting by chance:
compute the COINCIDENTAL hit rate per axis (fraction of random in-range values that land
within 1mm of some GT coordinate) and compare to the splice hit counts. If splice hits ~=
coincidental, the byte-splice delta model is wrong."""
import sys, struct
import numpy as np
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def near(v,a,tol=0.001):
    arr=gA[a]; i=np.searchsorted(arr,v)
    return any(0<=j<len(arr) and abs(arr[j]-v)<=tol for j in (i-1,i))
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def be(o): return struct.unpack('>d',d[o:o+8])[0]
def band(v):
    a=abs(v); return 2 if a<5000 else (0 if a<100000 else 1)
def is_full(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(o)); return (400<v<900) or (54000<v<58000) or (158000<v<166000)
fulls=[be(o) for o in range(8326,face_start-8) if is_full(o)]
# (1) inversion check
for a,nm in [(0,'X/east'),(1,'Y/north'),(2,'Z/elev')]:
    vals=[v for v in fulls if band(v)==a]
    inrange=sum(1 for v in vals if gA[a][0]-1<=v<=gA[a][-1]+1)
    print(f'{nm}: {len(vals)} fulls, {inrange} in GT range [{gA[a][0]:.1f},{gA[a][-1]:.1f}]  (swap/invert would put them out of range)')
# (2) coincidental hit rate per axis
print('\ncoincidental hit rate (random in-range value within 1mm of a GT coord):')
rng=np.random.RandomState(0) if False else None
for a,nm in [(0,'X'),(1,'Y'),(2,'Z')]:
    lo,hi=gA[a][0],gA[a][-1]
    # deterministic sample across range
    test=np.linspace(lo,hi,20000)
    rate=np.mean([near(v,a) for v in test])*100
    print(f'  {nm}: range {hi-lo:.1f}m, {len(gA[a])} unique GT vals (~{(hi-lo)/len(gA[a])*1000:.0f}mm apart) -> coincidental hit rate {rate:.0f}%')
print('\nNB: byte-splice deltas hit X~2%, Y~3%, Z~21% in origin_test -> compare to coincidental rates above.')
