#!/usr/bin/env python3
"""Pair-level face-law census using the PROVEN allocation rule n = S - r
(serpentine mirror, alloc7) refitted on the dense v11 map.

Per motif pair (ref group r_k -> idless group) on a rail with fitted S:
  n_k = S - r_k ; n_prev = S - r_prev (previous pair, same rail)
  test faces:  fan  = (r_k, n_prev, n_k)          [when r_k == r_prev]
               A1   = (r_prev, r_k, n_prev)  A2 = (r_k, n_prev, n_k)
               B1   = (r_prev, r_k, n_k)     B2 = (r_prev, n_prev, n_k)
Census complete-quad rate, phase (A/B) vs step direction (dr, dn), and
op-byte correlation with phase. GT = scoring only; S fitted by GT votes
(teacher-forced allocation — stated as such).
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
faceset=set(tuple(sorted(f)) for f in F)
nbr=defaultdict(set)
for a,b,c in F:
    for u,v in ((a,b),(b,c),(c,a)): nbr[u].add(v); nbr[v].add(u)

g2 = {}
for gi,r,rid in ref_events: g2[gi]=(rid,r)
# motif pairs per rail
pairs=defaultdict(list)   # rid -> [(gi_ref, gi_idless, r)]
last=None
for gi,g in enumerate(groups):
    if g['refs']:
        if len(g['refs'])>10: last=None; continue
        if gi in g2: last=(gi, g2[gi][0], g['refs'][-1])
        continue
    if g['delim']=='e003' and not g['refs'] and last is not None:
        pairs[last[1]].append((last[0], gi, last[2]))

# fit S per rail (vote: mapped GT-neighbors of map11[r], cross-rail)
fitS={}
for rid,lst in pairs.items():
    votes=Counter()
    for gr_gi, gi, r in lst:
        g=map11.get(r)
        if g is None: continue
        for v in nbr[g]:
            s=gt2slot11.get(v)
            if s is not None and abs(s-r)>3: votes[s+r]+=1
    if votes:
        S,c=votes.most_common(1)[0]
        if c>=2: fitS[rid]=S
print(f'rails with fitted S: {len(fitS)} / {len(pairs)}')

lab=Counter(); phase_dir=Counter()
op_phase=defaultdict(Counter)
mirror_hit=mirror_chk=0
for rid,lst in pairs.items():
    S=fitS.get(rid)
    if S is None: continue
    for i in range(len(lst)):
        gr_gi, gi, r = lst[i]
        n=S-r
        a=map11.get(r); b=map11.get(n)
        if a is not None and b is not None:
            mirror_chk+=1
            mirror_hit+= (min(a,b),max(a,b)) in [(min(a,b),max(a,b))] and b in nbr[a]
        if i==0: continue
        gr_gi0, gi0, rp = lst[i-1]
        if gi-gi0>60: continue
        np_=S-rp
        ids=[map11.get(x) for x in (rp,np_,r,n)]
        if any(x is None for x in ids): lab['unmapped']+=1; continue
        grp,gnp,grk,gnk=ids
        dr=r-rp
        if dr==0:
            ok=tuple(sorted((grk,gnp,gnk))) in faceset if gnp!=gnk else False
            lab['fan_ok' if ok else 'fan_bad']+=1
            continue
        A=(tuple(sorted((grp,grk,gnp))) in faceset) and (tuple(sorted((grk,gnp,gnk))) in faceset)
        B=(tuple(sorted((grp,grk,gnk))) in faceset) and (tuple(sorted((grp,gnp,gnk))) in faceset)
        cls='A' if (A and not B) else 'B' if (B and not A) else 'AB' if (A and B) else 'none'
        lab[cls]+=1
        if cls in ('A','B'):
            phase_dir[(cls, int(np.sign(dr)) if False else (1 if dr>0 else -1))]+=1
            rg=groups[gr_gi]; ig=groups[gi]
            if rg['ops']: op_phase[cls][f"ref1 {rg['ops'][0][0]:02x}"]+=1
            if ig['ops']: op_phase[cls][f"idl1 {ig['ops'][0][0]:02x}:{ig['ops'][0][1]:02x}"]+=1
            if len(ig['ops'])>1: op_phase[cls][f"idl_fin {ig['ops'][-1][0]:02x}:{ig['ops'][-1][1]:02x}"]+=1

print(f'S-mirror edge rate (map11): {mirror_hit}/{mirror_chk} = {100*mirror_hit/max(mirror_chk,1):.1f}%')
print('pair labels:', lab.most_common())
tot=sum(v for k,v in lab.items() if k in ('A','B','AB','none'))
good=lab['A']+lab['B']+lab['AB']
print(f'complete-quad rate (A/B/AB over quad pairs): {good}/{tot} = {100*good/max(tot,1):.1f}%')
fs=lab['fan_ok']; fb=lab['fan_bad']
print(f'fan law: {fs}/{fs+fb} = {100*fs/max(fs+fb,1):.1f}%')
print('phase vs dr sign:', dict(phase_dir))
for cls in ('A','B'):
    print(f'ops [{cls}]:', op_phase[cls].most_common(10))
