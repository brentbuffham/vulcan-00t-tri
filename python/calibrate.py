#!/usr/bin/env python3
"""Calibrate the DELTA splice against INDEPENDENT GT (the DXF vertices). Lockstep walk:
keep prev EXACT by snapping each decoded coord to the true GT axis value (discovery
only). For each DELTA, try splice lengths k and see which makes the result land on a
true GT coordinate (<1cm) -> derives the real splice rule per record type. Reports
recall, the winning-k distribution, and records that match NOTHING (unknown rules)."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1] if len(sys.argv)>1 else r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=sys.argv[2] if len(sys.argv)>2 else r'C:/Users/brent/AppData/Local/Temp/claude/C--Users-brent-desktop-git-vulcan-00t-tri/201af130-259a-4aee-9ee4-c17962d15f8e/scratchpad/gt_intercepts.csv'
G=np.loadtxt(gtcsv,delimiter=',')
gax=[np.sort(np.unique(G[:,a])) for a in range(3)]
gtset=set(zip(np.round(G[:,0]*100).astype(int),np.round(G[:,1]*100).astype(int),np.round(G[:,2]*100).astype(int)))
def snap(v,a,tol):
    arr=gax[a]; i=np.searchsorted(arr,v); c=[]
    if i<len(arr):c.append(arr[i])
    if i>0:c.append(arr[i-1])
    if not c: return None
    b=min(c,key=lambda x:abs(x-v)); return b if abs(b-v)<=tol else None
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
prevb=[None,None,None]; pos=8326; filled={}; verts=[]
kwin=Counter(); kbycount=Counter(); nfail=0; fails=[]; ndelta=0
def flush():
    global filled
    if len(filled)==3: verts.append((filled[0],filled[1],filled[2]))
    filled={}
while pos<face_start-1:
    if full_here(pos):
        v=be(d[pos:pos+8]); ax=band(v); s=snap(v,ax,2.0)
        if ax in filled: flush()
        prevb[ax]=struct.pack('>d', s if s is not None else v); filled[ax]=(s if s is not None else v)
        pos+=8
        if len(filled)==3: flush()
        continue
    p=pos
    if is_tag(d[p]) and p+1<face_start and is_sep(d[p+1]): p+=1
    if is_sep(d[p]) and p+1<face_start:
        count=d[p+1]
        if count<=6:
            rec_end=p+2+count+1
            if rec_end<=face_start:
                ndelta+=1
                cand_axes=[a for a in range(3) if a not in filled and prevb[a] is not None] or [a for a in range(3) if prevb[a] is not None]
                hit=None
                for a in cand_axes:
                    for k in (3,4,5,6):
                        if k>8: continue
                        val=be(bytes(prevb[a][:8-k])+d[rec_end-k:rec_end])
                        s=snap(val,a,0.05)
                        if s is not None and abs(s-val)<0.02:
                            hit=(a,k,s); break
                    if hit: break
                if hit:
                    a,k,s=hit; kwin[k]+=1; kbycount[(count,k)]+=1
                    prevb[a]=struct.pack('>d',s); filled[a]=s
                else:
                    nfail+=1
                    if len(fails)<20: fails.append((pos,count,d[pos:rec_end].hex()))
                pos=rec_end
                if len(filled)==3: flush()
                continue
    pos+=1
P=np.array(verts)
hits=sum(1 for v in P if (round(v[0]*100),round(v[1]*100),round(v[2]*100)) in gtset)
print(f'deltas={ndelta:,} matched-splice={sum(kwin.values()):,} unknown={nfail:,}')
print(f'winning splice-length k: {dict(kwin)}')
print(f'k by count byte (count->k): {dict(sorted(kbycount.items()))}')
print(f'vertices emitted={len(P):,}  EXACT GT vertex hits={hits:,} / {len(gtset):,}  recall={hits/len(gtset)*100:.1f}%')
print('unknown-rule records (offset,count,bytes):')
for fp,c,h in fails[:12]: print(f'  @{fp} count={c} {h}')
