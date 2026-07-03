#!/usr/bin/env python3
"""Register-free FINGERPRINT labeling: for each V-token, find all (axis, GT double
w, window start k) with w.bytes[k:k+nb] == payload. Unique (axis,w) => CERTAIN
label. Then: (1) axis sequence purity vs strict cycle, (2) (p,T1,T2)->k rule on
certain labels, (3) how many tokens certain, (4) consecutive-value prefix
consistency (splice compatibility)."""
import struct
import numpy as np
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\intercepts_gt.csv'
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
# GT doubles: note DXF is mm-rounded; the FILE stores full-precision doubles that
# ROUND to these. Fingerprint must use the FILE's doubles -> we can't know them
# exactly from GT... BUT the low bytes of the file doubles come from the payloads
# themselves. Compromise: fingerprint on the mm-rounded double bytes AND on
# quantization-tolerant prefix bytes (top 5 bytes are stable within +-0.5mm).
# Instead: index GT values by TOP-bytes; for a candidate (payload,k) the value is
# reg-prefix + payload (+suffix) — without registers we can only pin k when the
# payload's leading bytes uniquely align inside SOME GT value's byte pattern
# within tolerance. Practical approach: build for each axis the sorted list of
# doubles; for a given payload at window [k,k+nb), the payload determines value
# bits at positions k..k+nb; search GT values whose byte range [k:k+nb] matches
# payload EXACTLY (using the mm-rounded double bytes) — works when the window
# does not extend into sub-mm bits. Byte 0-5 of the double are stable vs mm
# rounding for these magnitudes; bytes 6-7 are not. So fingerprint on the
# overlap of window with bytes [0..6).
vals=[np.sort(np.unique(np.round(Gu[:,a],3))) for a in range(3)]
bytemaps=[]  # per axis: dict (k, window_bytes_prefixpart) -> set of value indices
for a in range(3):
    arr=vals[a]
    bm=defaultdict(list)
    for vi,v in enumerate(arr):
        bb=struct.pack('>d',v)
        for k in range(0,7):
            for e in range(k+1,8):
                if e<=6:
                    bm[(k,bytes(bb[k:e]))].append(vi)
    bytemaps.append(bm)
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
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
print(f'tokens {len(toks)}')
labels=[]  # per token: None or (axis, valueIdx, k) if UNIQUE
nuniq=0; nmulti=0; nzero=0
for t in toks:
    if t[0]=='F':
        v=be(t[1]); a=band(v)
        arr=vals[a]; i=np.searchsorted(arr,round(v,3))
        labels.append(('F',a,None)); continue
    payload=t[1]; nb=len(payload)
    cands=set()
    for a in range(3):
        bm=bytemaps[a]
        for k in range(0,min(7,9-nb)):
            e=k+nb
            fp_end=min(e,6)
            if fp_end<=k: continue
            key=(k,bytes(payload[:fp_end-k]))
            for vi in bm.get(key,[]):
                cands.add((a,vi,k))
    # unique by (a,vi)?
    av=set((a,vi) for a,vi,k in cands)
    if len(av)==1:
        a,vi=next(iter(av))
        ks=sorted(k for a2,v2,k in cands)
        labels.append(('U',a,(vi,tuple(ks)))); nuniq+=1
    elif len(av)==0:
        labels.append(('0',None,None)); nzero+=1
    else:
        labels.append(('M',None,None)); nmulti+=1
print(f'V-tokens: unique={nuniq} multi={nmulti} zero={nzero}')
# axis sequence from certain labels + fulls
seq=[(i,l[1]) for i,l in enumerate(labels) if l[0] in ('U','F')]
axstr=''.join('XYZ'[a] for _,a in seq)
print('axis seq (certain only, first 150):',axstr[:150])
# cycle test on certain: consecutive certain tokens that are ADJACENT in token idx
trans=Counter()
for (i1,a1),(i2,a2) in zip(seq,seq[1:]):
    if i2==i1+1: trans[(a2-a1)%3]+=1
print('adjacent-certain transitions (0 stay,1 fwd,2 back):',dict(trans))
# tokens-per-axis
print('certain axis counts:',Counter(a for _,a in seq if a is not None))
np.save(r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad\fp_labels.npy',np.array(labels,dtype=object),allow_pickle=True)
