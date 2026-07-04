#!/usr/bin/env python3
"""Teacher-forcing accuracy: for each labeled V-token, set all three registers
to the answer key's exact previous values (spliced bytes, not GT-rounded),
then decode this ONE token with (prev-same-axis ref + k0 formula). Measures
the true per-token model accuracy with no cascade contamination.
Failures are then classified: other-k0 fixes it? other-axis ref fixes it?
2-token composition? etc."""
import json, struct
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
L.sort(key=lambda l:l['tok'])
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
d=open(oot,'rb').read()
# payload per old-token index (recreate old tokenizer)
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
        toks.append(('F',d[pos:pos+8],lastT,None)); lastT=None; pos+=8; continue
    if b<0x20 and pos+1+(b&7)+1<=face_start:
        nb=(b&7)+1
        toks.append(('V',d[pos+1:pos+1+nb],lastT,b)); lastT=None; pos+=1+nb; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if b>=0x20 and pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
# previous same-axis TRUE value bytes: walk labels in token order, keep per-axis
# last fb (or FULL bytes when a FULL sits between)
fulls={}
for i,t in enumerate(toks):
    if t[0]=='F': fulls[i]=t[1]
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
last={0:None,1:None,2:None}
lastidx={0:-1,1:-1,2:-1}
res=Counter(); fails=[]
events=0
for l in L:
    i=l['tok']
    # apply any FULLs between previous processed index and i
    for j in sorted(k for k in fulls if k<i):
        if j>min(lastidx.values())-999:  # cheap: apply all fulls seen so far once
            pass
    # (simpler: fulls applied below by scanning range)
for a in (0,1,2): last[a]=None
lab_sorted=[l for l in L if l.get('fb')]
lab_sorted.sort(key=lambda l:l['tok'])
prev_tok=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev_tok+1,i):
        if j in fulls:
            fb=fulls[j]; last[band(be(fb))]=bytes(fb)
    prev_tok=i
    a=l['axis']; t=toks[i]
    fb=bytes.fromhex(l['fb'])
    if t[0]!='V':
        last[a]=fb; continue
    if l['role']!='val' or not l['verified']:
        events+=1; last[a]=fb; continue
    ref=last[a]
    if ref is None:
        last[a]=fb; continue
    payload=t[1]; nb=len(payload)
    k0=k0_rule(t[2],nb); end=k0+nb
    if end>8: k0=max(0,8-nb); end=k0+nb
    vb=ref[:k0]+bytes(payload)+ref[end:]
    if vb==fb: res['exact']+=1
    else:
        # classify
        fixed=None
        for kk in (0,1,2,3,4):
            e2=kk+nb
            if e2>8: continue
            if ref[:kk]+bytes(payload)+ref[e2:]==fb: fixed=('k0',kk); break
        if fixed is None:
            for aa in (0,1,2):
                if aa==a or last[aa] is None: continue
                for kk in (0,1,2,3):
                    e2=kk+nb
                    if e2>8: continue
                    if last[aa][:kk]+bytes(payload)+last[aa][e2:]==fb:
                        fixed=('xref',aa,kk); break
                if fixed: break
        res[('fail',fixed[0] if fixed else 'none')]+=1
        if len(fails)<12 and fixed is None:
            fails.append((i,l,ref.hex(),fb.hex(),bytes(payload).hex()))
    last[a]=fb
print('teacher-forced per-token results:',dict(res))
tot=sum(res.values())
print(f"exact rate: {res['exact']}/{tot} = {res['exact']/tot*100:.2f}%  (events excluded: {events})")
print('\nunexplained failures (ref/fb/payload):')
for i,l,r,f,p in fails:
    print(f'  tok {i} axis {l["axis"]} p={l["p"]:#04x} T=({l["T1"]:#04x},{l["T2"]:#04x}) pay={p}')
    print(f'    ref {r}')
    print(f'    fb  {f}')
