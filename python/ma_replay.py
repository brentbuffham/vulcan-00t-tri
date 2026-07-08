#!/usr/bin/env python3
"""MYSTERY A replay test — the CR strip machine, replayed generatively.

MACHINE (hypothesis, from ma_gate2/3 evidence):
  per strip: state (r_last, n_last)
  REF group (op R):    r_new = explicit ref
                       emit face (r_last, r_new, n_last);  r_last = r_new
  IDLESS group (op C): n_new = n_last + s   (s = +-1 fixed per strip)
                       emit face (r_last, n_last, n_new);  n_last = n_new

Unknowns per strip segment: n0 (initial n_last) and s. FIT by maximizing
GT-face hits (teacher-forced fit — mechanism verification only; the GT-free
version of this fit is the next step and uses the P_v11 parallelogram oracle).

Segments: rail event runs split at gi gaps > GAP. Report per-segment best hit
rate, global face hit rate, and unique GT-face coverage.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
F = np.load('faces_gt.npy')
faceset=set(tuple(sorted(f)) for f in F)

# per-rail event streams: R events from ref_events; C events = idless e003
# groups assigned to the rail of the last preceding ref group.
g2 = {}
for gi,r,rid in ref_events: g2[gi]=(rid,r)
events=defaultdict(list)     # rid -> [(gi, 'R', r) | (gi, 'C', None)]
last_rid=None
for gi,g in enumerate(groups):
    if g['refs']:
        if len(g['refs'])>10: last_rid=None; continue
        if gi in g2:
            rid,r=g2[gi]
            events[rid].append((gi,'R',g['refs'][-1]))
            last_rid=rid
        continue
    if g['delim']=='e003' and not g['refs'] and last_rid is not None:
        events[last_rid].append((gi,'C',None))

GAP=60
def segments(ev):
    seg=[]; cur=[]
    for e in ev:
        if cur and e[0]-cur[-1][0]>GAP:
            seg.append(cur); cur=[]
        cur.append(e)
    if cur: seg.append(cur)
    return seg

def replay(seg, n0, s):
    """returns emitted faces [(slots triple, kind)]"""
    r_last=None; n_last=n0; out=[]
    for gi,k,r in seg:
        if k=='R':
            if r_last is not None and r!=r_last:
                out.append(((r_last,r,n_last),'R'))
            r_last=r
        else:
            if r_last is None: continue
            n_new=n_last+s
            out.append(((r_last,n_last,n_new),'C'))
            n_last=n_new
    return out

def score(faces):
    hit=chk=0
    for (a,b,c),k in faces:
        ga,gb,gc=map11.get(a),map11.get(b),map11.get(c)
        if None in (ga,gb,gc) or len({ga,gb,gc})<3: continue
        chk+=1
        hit+= tuple(sorted((ga,gb,gc))) in faceset
    return hit,chk

results=[]; all_faces=[]
tot_pairs=0
for rid,ev in events.items():
    for seg in segments(ev):
        ncount=sum(1 for e in seg if e[1]=='C')
        rrefs=[e[2] for e in seg if e[1]=='R']
        if ncount<3 or len(rrefs)<2: continue
        tot_pairs+=ncount
        r0=rrefs[0]
        best=None
        for s in (1,-1):
            for n0 in range(max(0,r0-250), min(2963,r0+250)):
                fs=replay(seg,n0,s)
                h,c=score(fs)
                if c>=3 and (best is None or h/c>best[0] or (h/c==best[0] and c>best[3])):
                    if best is None or h/c>best[0]: best=(h/c,n0,s,c,h,fs)
        if best:
            rate,n0,s,c,h,fs=best
            results.append((rid,seg[0][0],seg[-1][0],ncount,rate,c,h,n0,s))
            all_faces.extend(fs)

results.sort(key=lambda x:-x[3])
print(f'segments fitted: {len(results)}  (C events total {tot_pairs})')
rates=np.array([r[4] for r in results]); ws=np.array([r[5] for r in results])
print(f'checkable-weighted global hit rate: {sum(r[6] for r in results)}/{sum(r[5] for r in results)}'
      f' = {100*sum(r[6] for r in results)/max(sum(r[5] for r in results),1):.1f}%')
print(f'segments with rate>=0.8: {(rates>=0.8).sum()}, 0.5-0.8: {((rates>=0.5)&(rates<0.8)).sum()}, <0.5: {(rates<0.5).sum()}')
print('\ntop segments (rid, gi0, gi1, nC, rate, chk, hit, n0, s):')
for r in results[:15]: print('  ',r)

# unique GT-face coverage from the best fits
cov=set()
for (a,b,c),k in all_faces:
    ga,gb,gc=map11.get(a),map11.get(b),map11.get(c)
    if None in (ga,gb,gc): continue
    t=tuple(sorted((ga,gb,gc)))
    if t in faceset: cov.add(t)
print(f'\nunique GT faces hit: {len(cov)} / {len(faceset)}')

# kind breakdown
kh=Counter(); kc=Counter()
for (a,b,c),k in all_faces:
    ga,gb,gc=map11.get(a),map11.get(b),map11.get(c)
    if None in (ga,gb,gc) or len({ga,gb,gc})<3: continue
    kc[k]+=1
    kh[k]+= tuple(sorted((ga,gb,gc))) in faceset
print('by kind: R %d/%d = %.1f%%   C %d/%d = %.1f%%' % (
    kh['R'],kc['R'],100*kh['R']/max(kc['R'],1),
    kh['C'],kc['C'],100*kh['C']/max(kc['C'],1)))
