#!/usr/bin/env python3
"""Row-block hypothesis test: decode coord stream with a SINGLE splice register
(no axis separation). Classify each decoded scalar by disjoint GT band
(X~55.6-56k, Y~162.9-163.1k, Z~653-668). If emission is row-blocked
(n X, then n Y, then n Z per row), the band sequence shows long clean runs.
GT used for scoring only (band classification + value hit check)."""
import sys, struct
import numpy as np
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=sys.argv[1] if len(sys.argv)>1 else r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def near(v,a,tol=0.002):
    arr=gA[a]; i=np.searchsorted(arr,v)
    for j in (i-1,i):
        if 0<=j<len(arr) and abs(arr[j]-v)<=tol: return True
    return False
d=open(oot,'rb').read()
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
print(f'coord section: 8326..{face_start}')
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    if 160000<a<166000: return 1
    return -1
def is_sep(b): return (b&7)==7
def is_tag(b): return 0x20<=b<=0x2f and not is_sep(b)
def full_here(o):
    if o+8>face_start or d[o] not in (0x40,0x41,0xC0,0xC1): return False
    v=abs(be(d[o:o+8])); return (400<v<900) or (54000<v<58000) or (158000<v<166000)

prev=d[8326:8334]
stream=[]  # (pos, kind, value, band, gt_hit)
for seed_off in (8326,8334,8342):
    v=be(d[seed_off:seed_off+8]); stream.append((seed_off,'seed',v,band(v),True))
prev=d[8342:8350]
pos=8350
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); prev=d[pos:pos+8]
        stream.append((pos,'full',v,band(v),near(v,band(v)) if band(v)>=0 else False))
        pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; nb=count+1; rec_end=p+2+count+1
        if rec_end<=face_start:
            payload=d[rec_end-nb:rec_end]
            vb=bytes(prev[:8-nb])+payload
            v=be(vb)
            b=band(v)
            hit=near(v,b) if b>=0 else False
            stream.append((pos,'delta',v,b,hit))
            prev=vb
            pos=rec_end; continue
    pos+=1
bands=[x[3] for x in stream]
hits=[x[4] for x in stream]
n=len(stream)
print(f'scalars decoded: {n}; band histogram: X={bands.count(0)} Y={bands.count(1)} Z={bands.count(2)} ?={bands.count(-1)}')
print(f'GT value hit rate overall: {sum(hits)/n*100:.1f}%')
for bb,nm in ((0,'X'),(1,'Y'),(2,'Z')):
    sel=[h for x,h in zip(stream,hits) if x[3]==bb]
    if sel: print(f'  {nm}: {sum(sel)}/{len(sel)} = {sum(sel)/len(sel)*100:.1f}%')
# run-length encode band sequence
rle=[];curb=bands[0];c=1
for b in bands[1:]:
    if b==curb: c+=1
    else: rle.append((curb,c));curb=b;c=1
rle.append((curb,c))
print(f'\nband runs: {len(rle)}; first 40:',[(("XYZ?")[b if b>=0 else 3],c) for b,c in rle[:40]])
runlens=[c for b,c in rle]
print(f'run length: median={np.median(runlens):.0f} mean={np.mean(runlens):.1f} max={max(runlens)}')
# expected total scalars = 3*NV = 8925
print(f'expected 3*NV = {3*len(np.unique(G,axis=0))}')
