#!/usr/bin/env python3
"""Row-traversal model (Brent's spatial-sort, confirmed by X descending in runs):
each point = X then Z (toggle); Y updates on a row change (band-Y full). Emit a point
when Z is set. Snap to GT to validate the MODEL (recall) and reveal the pattern; if it
works, implement GT-free. X-delta ~4m steps, Z-delta ~1m -> distinct."""
import sys, struct
import numpy as np
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gset=set(zip(np.round(G[:,0]*100).astype(int),np.round(G[:,1]*100).astype(int),np.round(G[:,2]*100).astype(int)))
gA=[np.sort(np.unique(np.round(G[:,a],3))) for a in range(3)]
def snap(v,a,tol):
    arr=gA[a]; i=np.searchsorted(arr,v); c=[arr[j] for j in (i-1,i) if 0<=j<len(arr)]
    if not c: return None
    b=min(c,key=lambda x:abs(x-v)); return b if abs(b-v)<=tol else None
def in_gt(x,y,z): return None not in (x,y,z) and (round(x*100),round(y*100),round(z*100)) in gset
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
cx=snap(be(d[8326:8334]),0,1); cy=snap(be(d[8334:8342]),1,1); cz=snap(be(d[8342:8350]),2,1)
pxb=d[8326:8334]; pzb=d[8342:8350]; expect='X'; got=set(); pos=8350; npts=0
if in_gt(cx,cy,cz): got.add((round(cx*100),round(cy*100),round(cz*100)))
def emit():
    global npts
    npts+=1
    if in_gt(cx,cy,cz): got.add((round(cx*100),round(cy*100),round(cz*100)))
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); a=band(v); s=snap(v,a,1)
        if s is not None:
            if a==0: cx=s; pxb=d[pos:pos+8]; expect='Z'
            elif a==2: cz=s; pzb=d[pos:pos+8]; emit(); expect='X'
            else: cy=s
        pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            if expect=='X':
                cand=be(bytes(pxb[:3])+d[rec_end-5:rec_end]); s=snap(cand,0,5)
                if s is not None: cx=s; pxb=struct.pack('>d',s)
                expect='Z'
            else:
                cand=be(bytes(pzb[:3])+d[rec_end-5:rec_end]); s=snap(cand,2,5)
                if s is not None: cz=s; pzb=struct.pack('>d',s)
                emit(); expect='X'
            pos=rec_end; continue
    pos+=1
print(f'points emitted={npts:,}  GT vertices reconstructed={len(got):,}/{len(gset):,} = {len(got)/len(gset)*100:.1f}%')
