#!/usr/bin/env python3
"""Topology tokenizer v2 — corrected grammar.

group := delim(e0/e1 pair) body
body  := [0x08-0x1f stray skips] ( op | value )*
op    := [lead 0x20-0x7f][arg]          (arg lo2==11 usually)
value := 0x00-0x06 count byte -> nb=b+1 payload bytes (BE int)
         EXCEPT 0x00 at body start before a tag-class byte = skip
"""
import struct, pickle
from collections import Counter
import numpy as np

d=open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t','rb').read()
geo_end=struct.unpack('<15i',d[0:60])[11]
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break

groups=[];pos=face_start
cur=None
def newgroup(delim,pos):
    return {'delim':delim,'pos':pos,'ops':[],'vals':[],'strays':[],'seq':[]}
while pos<geo_end:
    b=d[pos]
    if b in (0xE0,0xE1):
        if cur: groups.append(cur)
        cur=newgroup(d[pos:pos+2].hex(),pos); pos+=2; continue
    if cur is None: cur=newgroup('HEAD',pos)
    atstart=(not cur['seq'])
    if b==0x00:
        nxt=d[pos+1] if pos+1<geo_end else 0
        if 0x20<=nxt<0x80:
            # skip byte before an op
            pos+=1; continue
        # count: 1-byte value
        cur['vals'].append(nxt); cur['seq'].append(('V',nxt,1)); pos+=2; continue
    if 0x01<=b<=0x06:
        nb=b+1; v=int.from_bytes(d[pos+1:pos+1+nb],'big')
        cur['vals'].append(v); cur['seq'].append(('V',v,nb)); pos+=1+nb; continue
    if 0x08<=b<0x20:
        cur['strays'].append(b); cur['seq'].append(('K',b,0)); pos+=1; continue
    # tag op pair
    lead,arg=b,(d[pos+1] if pos+1<geo_end else 0)
    cur['ops'].append((lead,arg)); cur['seq'].append(('T',(lead,arg),2)); pos+=2
if cur: groups.append(cur)
print('groups:',len(groups))
print('delims:',Counter(g['delim'] for g in groups).most_common(10))

# census
opc=Counter(); argl2=Counter(); vw=Counter(); nvals=Counter(); nops=Counter()
firstop=Counter(); finc=Counter()
for g in groups:
    for l,a in g['ops']:
        opc[f'{l:02x}:{a:02x}']+=1; argl2[a&3]+=1
    for k,v,w in [s for s in g['seq'] if s[0]=='V']:
        vw[w]+=1
    nvals[len(g['vals'])]+=1
    ops=[o for o in g['ops'] if o[1]!=0x1b]
    nops[len(ops)]+=1
    if g['ops']: firstop[f"{g['ops'][0][0]:02x}:{g['ops'][0][1]:02x}"]+=1
    fins=[o for o in g['ops'] if o[1]==0x1b]
    finc[' '.join(f'{l:02x}' for l,_ in fins)]+=1
print('arg lo2:',dict(argl2))
print('value widths:',dict(vw))
print('vals per group:',sorted(nvals.items()))
print('non-fin ops per group:',sorted(nops.items())[:12])
print('first op census:',firstop.most_common(15))
print('finalizer leads:',finc.most_common(8))
print('top ops:',opc.most_common(25))
va=np.array([v for g in groups for s0,v,w in g['seq'] if s0=='V' and w<=2])
print('clean vals: n',len(va),'>2974:',(va>2974).sum())
vb=np.array([v for g in groups for s0,v,w in g['seq'] if s0=='V' and w>2])
print('wide vals: n',len(vb),' sample',vb[:8])
pickle.dump(groups,open('groups_v2.pkl','wb'))
