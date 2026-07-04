#!/usr/bin/env python3
"""Decode the FULL-neighborhood transition rule. For every FULL run, record:
  prevV axis (labeled), run structure [(esc?,band,escbyte)...], then for the
  next labeled V: its axis + its T1/T2.
Goal: a deterministic next-phase function f(prev_axis, run, nextT) usable by
the sole parser. Also inspect the escape BYTES themselves for signal."""
import struct, json
from collections import Counter, defaultdict
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
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
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None
toks=[];pos=8350;lastT=None;escb=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    v=full_at(pos)
    if v is not None:
        toks.append(('F',d[pos:pos+8],lastT,escb,pos)); lastT=None; escb=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        escb=b; lastT=None; pos+=1; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b,pos)); lastT=None; escb=None; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
def tok_old():
    o=[];pos=8350
    while pos<face_start:
        b=d[pos]
        if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
            while pos<face_start and d[pos]==0: pos+=1
            continue
        if b in (0x40,0x41,0xC0,0xC1) and pos+8<=face_start and sane(be(d[pos:pos+8])):
            o.append(pos); pos+=8; continue
        if b<0x20 and pos+1+(b&7)+1<=face_start:
            o.append(pos); pos+=1+(b&7)+1; continue
        if 0xe0<=b<=0xff and pos+3<=face_start: pos+=3; continue
        if b>=0x20 and pos+2<=face_start: pos+=2; continue
        pos+=1
    return o
oldpos=tok_old()
L=json.load(open(sp+r'\commit_labels.json'))
lab_by_pos={oldpos[l['tok']]:l for l in L if l['tok']<len(oldpos)}
# gather full-run neighborhoods
i=0; recs=[]
while i<len(toks):
    if toks[i][0]!='F': i+=1; continue
    j=i
    while j+1<len(toks) and toks[j+1][0]=='F': j+=1
    # prev labeled V immediately before
    lp=lab_by_pos.get(toks[i-1][4]) if i>0 and toks[i-1][0]=='V' else None
    ln=lab_by_pos.get(toks[j+1][4]) if j+1<len(toks) and toks[j+1][0]=='V' else None
    run=[( toks[k][3] is not None, band(be(toks[k][1])), toks[k][3]) for k in range(i,j+1)]
    nT=toks[j+1][2] if j+1<len(toks) and toks[j+1][0]=='V' else None
    recs.append((lp['axis'] if lp else None, run,
                 ln['axis'] if ln else None, nT))
    i=j+1
print(f'{len(recs)} full runs; with both labels: {sum(1 for r in recs if r[0] is not None and r[2] is not None)}')
# escape byte census
escbytes=Counter()
for _,run,_,_ in recs:
    for e,b,eb in run:
        if e: escbytes[eb]+=1
print('escape bytes:',dict(escbytes.most_common(20)))
# classify: does next axis follow SLOT (last band+1) or PREV (prev axis+1)?
cc=Counter(); detail=defaultdict(Counter)
for p,run,n,nT in recs:
    if p is None or n is None: continue
    lastb=run[-1][1]; anyesc=any(e for e,_,_ in run)
    slot=(lastb+1)%3==n; cont=(p+1)%3==n
    key=('esc' if anyesc else 'plain',len(run))
    cc[(key,slot,cont)]+=1
    t1c='noT' if nT is None else ('20' if nT[0]==0x20 else '%02x-class'%(nT[0]&0xE0))
    detail[(key,t1c)][('slot' if slot else '')+('cont' if cont else '')+
                      ('' if slot or cont else 'other:%d'%((n-lastb)%3))]+=1
print('\n(escaped?,runlen, slot?, continue?):')
for k,v in cc.most_common(14): print(' ',k,v)
print('\ndetail by next-V T1 class:')
for k in sorted(detail,key=lambda k:-sum(detail[k].values())):
    c=detail[k];ntot=sum(c.values())
    print(f'  {k}: n={ntot:<4} {dict(c.most_common())}')
# for escaped singles: escape byte vs relation
print('\nescaped single-full runs: escbyte -> relation (slot/cont/other)')
t=defaultdict(Counter)
for p,run,n,nT in recs:
    if p is None or n is None or len(run)!=1: continue
    e,b,eb=run[0]
    if not e: continue
    rel='slot' if (b+1)%3==n else ('cont' if (p+1)%3==n else 'other')
    # bucket escape byte by hi nibble
    t[eb>>4][rel]+=1
for k in sorted(t):
    print(f'  esc hi-nib {k:x}: {dict(t[k].most_common())}')
