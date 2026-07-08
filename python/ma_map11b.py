#!/usr/bin/env python3
"""Diagnose indexing offset between P_base map (thread.pkl) and P_v11 map,
and decide which indexing the topology refs use.
Test A: offset census between the two maps (same GT row).
Test B: ref-slot sanity under each map — for consecutive refs on a rail
(|dr|=1), are (map[r], map[r']) GT edges? Rail steps ARE mesh edges (proven
75.9% via anchors), so the right indexing scores high.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
slot2gt, gt2slot, rows = pickle.load(open('thread.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
E=set()
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)): E.add((min(u,v),max(u,v)))

# A: offset census
off=Counter()
for s,g in slot2gt.items():
    if g in gt2slot11: off[gt2slot11[g]-s]+=1
print('offset (v11_slot - base_slot) census:', off.most_common(12))

# B: rail-step edge rate under each map
def rail_edge_rate(m, shift=0):
    hit=tot=0
    for rail in rails:
        vals=rail['vals']
        for i in range(1,len(vals)):
            (g0,r0),(g1,r1)=vals[i-1],vals[i]
            if abs(r1-r0)!=1: continue
            a=m.get(r0+shift); b=m.get(r1+shift)
            if a is None or b is None: continue
            tot+=1
            if (min(a,b),max(a,b)) in E: hit+=1
    return hit,tot
for name,m,sh in (('base-map',slot2gt,0),('v11-map sh0',map11,0),
                  ('v11-map sh-1',map11,-1),('v11-map sh+1',map11,1),
                  ('v11-map sh-2',map11,-2),('v11-map sh+2',map11,2),
                  ('v11-map sh-11',map11,-11),('v11-map sh+11',map11,11)):
    h,t=rail_edge_rate(m,sh)
    print(f'rail |dr|=1 step edge rate [{name}]: {h}/{t} = {100*h/max(t,1):.1f}%')
