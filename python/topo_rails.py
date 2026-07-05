#!/usr/bin/env python3
"""Cluster the topology ref stream into RAILS (monotone-ish runs in slot space),
pair concurrent rails into STRIP CONTEXTS, and correlate context switches with
delimiter families / first-ops.  GT-free throughout."""
import struct, pickle
import numpy as np
from collections import defaultdict, Counter

d=open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t','rb').read()
geo_end=struct.unpack('<15i',d[0:60])[11]
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break

# tokenize topo section (v2 grammar) keeping group records
pos=face_start; groups=[]; cur=None
def ng(delim,pos): return {'delim':delim,'pos':pos,'ops':[],'refs':[],'raw':[]}
prev_ref=0
while pos<geo_end:
    b=d[pos]
    if b in (0xE0,0xE1):
        if cur: groups.append(cur)
        cur=ng(d[pos:pos+2].hex(),pos); pos+=2; continue
    if cur is None: cur=ng('HEAD',pos)
    if b==0x00:
        nxt=d[pos+1] if pos+1<geo_end else 0
        if 0x20<=nxt<0x80: pos+=1; continue
        r=(prev_ref&~0xFF)|nxt
        cur['refs'].append(r); prev_ref=r; pos+=2; continue
    if 0x01<=b<=0x06:
        nb=b+1; v=int.from_bytes(d[pos+1:pos+1+nb],'big')
        if nb==2 and v<=2974: cur['refs'].append(v); prev_ref=v
        pos+=1+nb; continue
    if 0x08<=b<0x20: pos+=1; continue
    cur['ops'].append((b,d[pos+1] if pos+1<geo_end else 0)); pos+=2
if cur: groups.append(cur)
print('groups',len(groups))

# --- rail clustering: assign each ref to the active rail whose last value is
# within JUMP of it; else open a new rail.
JUMP=6
rails=[]           # list of dicts: id, vals[(gi,ref)], last
active={}          # rail_id -> last ref
ref_events=[]      # (gi, ref, rail_id)
for gi,g in enumerate(groups):
    for r in g['refs']:
        best=None
        for rid,last in active.items():
            dd=abs(r-last)
            if dd<=JUMP and (best is None or dd<best[0]): best=(dd,rid)
        if best is None:
            rid=len(rails); rails.append({'id':rid,'vals':[]})
        else: rid=best[1]
        rails[rid]['vals'].append((gi,r)); active[rid]=r
        ref_events.append((gi,r,rid))
        # retire stale rails (not touched for 80 groups)
        for k in [k for k,v in list(active.items()) if rails[k]['vals'][-1][0]<gi-80]:
            del active[k]
print('rails:',len(rails))
sz=Counter(len(r['vals']) for r in rails)
print('rail size census:',sorted(sz.items())[:12],' rails>=5:',sum(1 for r in rails if len(r["vals"])>=5))
big=[r for r in rails if len(r['vals'])>=5]
# rail direction + span
for r in big[:15]:
    v=[x[1] for x in r['vals']]; g0=r['vals'][0][0]; g1=r['vals'][-1][0]
    dirn='asc' if v[-1]>v[0] else 'desc'
    print(f"rail{r['id']:3d}: groups {g0}-{g1}  slots {v[0]}->{v[-1]} ({dirn}) n={len(v)}")
# --- concurrent rail pairs: rails overlapping in group-time; check sum constancy
print('\nconcurrent rail pairs with constant-ish sum:')
for i in range(len(big)):
    for j in range(i+1,len(big)):
        a,b=big[i],big[j]
        ga=(a['vals'][0][0],a['vals'][-1][0]); gb=(b['vals'][0][0],b['vals'][-1][0])
        lo=max(ga[0],gb[0]); hi=min(ga[1],gb[1])
        if hi-lo<5: continue
        # interleave refs in overlap window, pair nearest-in-time
        va=[(g,r) for g,r in a['vals'] if lo<=g<=hi]
        vb=[(g,r) for g,r in b['vals'] if lo<=g<=hi]
        if len(va)<3 or len(vb)<3: continue
        sums=[]
        for g,r in va:
            g2,r2=min(vb,key=lambda x:abs(x[0]-g))
            sums.append(r+r2)
        sums=np.array(sums)
        if sums.std()<=3:
            print(f"  rail{a['id']} x rail{b['id']}: groups {lo}-{hi}, sum {sums.mean():.0f}±{sums.std():.1f}, n={len(sums)}")
pickle.dump((groups,rails,ref_events),open('rails.pkl','wb'))
