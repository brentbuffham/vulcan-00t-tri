#!/usr/bin/env python3
"""Crack the assembly WITHOUT guessing: use GT as a decoder to LABEL the exact
structure. Walk records; each updates one running coord (full=exact, delta=k=5 splice).
After each update, if current (x,y,z) is an EXACT GT vertex -> a vertex completed
(this is the boundary detector; it also picks the delta's axis = the one that lands on
a real vertex). Reconstructs vertices + emits the labeled order/dedup trace to read the
GT-free rule from. GT used only to LABEL; recall shows if values are right."""
import sys, struct
import numpy as np
oot=sys.argv[1]; gtcsv=sys.argv[2]
G=np.loadtxt(gtcsv,delimiter=',')
gset=set(zip(np.round(G[:,0]*100).astype(int),np.round(G[:,1]*100).astype(int),np.round(G[:,2]*100).astype(int)))
gaxis=[set(np.round(G[:,a],3).tolist()) for a in range(3)]
def in_gt(x,y,z): return (round(x*100),round(y*100),round(z*100)) in gset
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
cur=[be(d[8326:8334]),be(d[8334:8342]),be(d[8342:8350])]
prevb=[d[8326:8334],d[8334:8342],d[8342:8350]]
got=set(); trace=[]; pos=8350; nrec=0; nesc=0
if in_gt(*cur): got.add((round(cur[0]*100),round(cur[1]*100),round(cur[2]*100)))
def emit_check(changed_axis, kind):
    if in_gt(*cur):
        got.add((round(cur[0]*100),round(cur[1]*100),round(cur[2]*100)))
        if len(trace)<60: trace.append('XYZ'[changed_axis]+kind+'|')   # | = vertex boundary
    else:
        if len(trace)<60: trace.append('XYZ'[changed_axis]+kind)
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); a=band(v); cur[a]=v; prevb[a]=d[pos:pos+8]; nrec+=1
        emit_check(a,'F'); pos+=8; continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start and d[p+1]<=6:
        count=d[p+1]; rec_end=p+2+count+1
        if rec_end<=face_start:
            nrec+=1
            # try k=5 splice onto each axis; prefer the axis that COMPLETES a GT vertex
            best=None; midcand=None
            for a in range(3):
                if prevb[a] is None: continue
                cand=be(bytes(prevb[a][:3])+d[rec_end-5:rec_end])
                if round(cand,3) in gaxis[a] and abs(cand-cur[a])>0.03:
                    save=cur[a]; cur[a]=cand
                    if in_gt(*cur): best=(a,cand)
                    cur[a]=save
                    if midcand is None: midcand=(a,cand)
            pick=best or midcand
            if pick is not None:
                a,cand=pick; cur[a]=cand; prevb[a]=struct.pack('>d',cand); emit_check(a,'d')
            else: nesc+=1
            pos=rec_end; continue
    nesc+=1; pos+=1
print(f'records={nrec:,} unresolved={nesc:,}')
print(f'GT vertices reconstructed = {len(got):,} / {len(gset):,}  = {len(got)/len(gset)*100:.1f}%')
print('labeled order trace (| = vertex boundary):')
print(' '+' '.join(trace))
