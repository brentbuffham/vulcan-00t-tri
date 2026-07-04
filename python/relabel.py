#!/usr/bin/env python3
"""MECHANISM RE-LABELER. Teacher-force with answer-key VALUES only (never GT
bytes): walk labeled tokens in stream order; per token enumerate mechanism
candidates; accept those landing within 0.6mm of the GT value; record exact
bytes into per-axis history. Mechanisms:
  M1 splice(ref1, k0=0..4)            M2 carry-splice(ref1, k0, +-1 at k0-1)
  M3 splice(refN, k0) N=2..6          M4 escape-lead: payload[0] in
     {0x00-0x1F,0xF0-0xFF} stripped, then M1/M2/M3 with payload[1:]
  M5 double-carry (+-1 at k0-1, +-1 propagation two bytes)
Output: coverage by mechanism; per-token mechanism labels saved for signal
mining (mech_labels.json)."""
import json, struct
from collections import Counter, defaultdict
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
L=json.load(open(sp+r'\commit_labels.json'))
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
gtcsv=sp+r'\intercepts_gt.csv'
import numpy as np
G=np.loadtxt(gtcsv,delimiter=',')
Gu=np.unique(G,axis=0)
d=open(oot,'rb').read()
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
def band(v):
    a=abs(v)
    if 500<a<1000: return 2
    if 50000<a<60000: return 0
    return 1
TOL=0.0006
fulls={i:bytes(t[1]) for i,t in enumerate(toks) if t[0]=='F'}
# answer-key targets: order file gives (vertex,tok); labels give axis per token.
# Use labels: tok -> (axis, GT value) via closing_order + Gu? labels lack value;
# but fb value is within 0.6mm of GT — use round(be(fb),3) as target value.
lab_sorted=[l for l in L if l.get('fb')]
lab_sorted.sort(key=lambda l:l['tok'])
def gen(payload,hist,a):
    """yield (mechname, bytes) candidates."""
    nb=len(payload)
    H=hist[a]
    def splices(pl,tag):
        n=len(pl)
        for depth in range(1,min(7,len(H)+1)):
            r=H[-depth]
            for k0 in range(0,9-n):
                yield (f'{tag}sp_d{depth}_k{k0}',r[:k0]+pl+r[k0+n:])
            # carry at k0-1
            for k0 in range(1,9-n):
                for c in (1,-1):
                    b2=r[k0-1]+c
                    if 0<=b2<=255:
                        yield (f'{tag}ca{c:+d}_d{depth}_k{k0}',
                               r[:k0-1]+bytes([b2])+pl+r[k0+n:])
    yield from splices(payload,'')
    if nb>1 and (payload[0]<0x20 or payload[0]>=0xF0):
        yield from splices(payload[1:],f'esc{payload[0]:02x}_')
print('relabeling...')
hist={0:[],1:[],2:[]}
mech=Counter(); nolab=0; amb=0
out=[]
prev_tok=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev_tok+1,i):
        if j in fulls: hist[band(be(fulls[j]))].append(fulls[j])
    prev_tok=i
    a=l['axis']; t=toks[i]
    tgt=round(be(bytes.fromhex(l['fb'])),3)
    if t[0]!='V':
        hist[a].append(bytes.fromhex(l['fb'])); continue
    if l['role']!='val':
        hist[a].append(bytes.fromhex(l['fb'])); continue
    payload=bytes(t[1])
    hits=[]
    seen=set()
    for name,vb in gen(payload,hist,a):
        if vb in seen: continue
        seen.add(vb)
        v=be(vb)
        if abs(v-tgt)<=TOL: hits.append((name,vb))
    # byte-true anchor: if the original label was splice-verified its fb bytes
    # are exact -> pin selection to them
    truefb=bytes.fromhex(l['fb']) if l.get('matches') else None
    if truefb is not None:
        pinned=[(n,vb) for n,vb in hits if vb==truefb]
        if pinned: hits=pinned
        elif hits: hits=[]  # candidates exist but none match true bytes: unexplained
    if not hits:
        mech['NONE']+=1; nolab+=1
        hist[a].append(truefb if truefb is not None else struct.pack('>d',tgt))
        out.append(dict(tok=i,axis=a,mech=None,p=t[3],
                        T1=t[2][0] if t[2] else -1,T2=t[2][1] if t[2] else -1))
        continue
    if len(set(vb for _,vb in hits))>1: amb+=1
    name,vb=hits[0]
    # simplify name: family only
    fam=name.split('_')[0]+('_'+name.split('_')[1] if 'd1' not in name else '')
    mech[name]+=1
    hist[a].append(vb)
    out.append(dict(tok=i,axis=a,mech=name,p=t[3],
                    T1=t[2][0] if t[2] else -1,T2=t[2][1] if t[2] else -1))
tot=sum(mech.values())
print(f'total {tot}, unexplained {nolab} ({nolab/tot*100:.1f}%), ambiguous-bytes {amb}')
print('\nmechanism census (top 30):')
for k,v in mech.most_common(30): print(f'  {k}: {v}')
json.dump(out,open(sp+r'\mech_labels.json','w'))
print('saved mech_labels.json')
