#!/usr/bin/env python3
"""MYSTERY A: do the op bytes encode the quad SPLIT (R vs L / diagonal choice)?

For each strict-adjacent pair site, label the quad by GT faces:
  splitA = (rp,rk,np)+(rk,nk,np) both faces   [diagonal rk-np]
  splitB = (rp,rk,nk)+(rp,nk,np) both faces   [diagonal rp-nk]
  fan    = dr==0 and (r,np,nk) is a face
Then census the REF group's op bytes and the IDLESS group's op bytes per label.
GT used to label sites only (mechanism/answer-key); rule must be byte-only.
"""
import pickle
import numpy as np
from collections import Counter, defaultdict

map11, gt2slot11 = pickle.load(open('map11.pkl','rb'))
groups, rails, ref_events = pickle.load(open('rails.pkl','rb'))
seqs, sites, triples = pickle.load(open('ma_chains.pkl','rb'))
F = np.load('faces_gt.npy')
faceset=set(tuple(sorted(f)) for f in F)

def gid(s): return map11.get(s)

# find each site's ref-group gi: the pair list built in ma_gate3 stored idless gi.
# rebuild pair->refgroup gi map
pair_ref_gi={}
last_ref_gi=None; last_ref=None
for gi,g in enumerate(groups):
    if g['refs']:
        if len(g['refs'])>10: last_ref_gi=None; continue
        last_ref_gi=gi; last_ref=g['refs'][-1]; continue
    if g['delim']=='e003' and not g['refs'] and last_ref_gi is not None:
        pair_ref_gi[gi]=last_ref_gi

lab_ops=defaultdict(lambda: defaultdict(Counter))
lab_count=Counter()
examples=defaultdict(list)
for rid,gp,gi,rp,npv,rk,nk in sites:
    ids=[gid(x) for x in (rp,npv,rk,nk)]
    if any(x is None for x in ids): continue
    grp,gnp,grk,gnk=ids
    a=(tuple(sorted((grp,grk,gnp))) in faceset) and (tuple(sorted((grk,gnk,gnp))) in faceset)
    b=(tuple(sorted((grp,grk,gnk))) in faceset) and (tuple(sorted((grp,gnk,gnp))) in faceset)
    dr=rk-rp
    if dr==0:
        lab='fan' if tuple(sorted((grk,gnp,gnk))) in faceset else 'fan?'
    elif a and not b: lab='A'
    elif b and not a: lab='B'
    elif a and b: lab='AB'
    else: lab='none'
    lab_count[lab]+=1
    rg=groups[pair_ref_gi.get(gi,-1)] if pair_ref_gi.get(gi) is not None else None
    ig=groups[gi]
    if rg is not None:
        fo=rg['ops'][0] if rg['ops'] else (0,0)
        lab_ops[lab]['ref_first'][f'{fo[0]:02x}:{fo[1]:02x}']+=1
        lab_ops[lab]['ref_lead'][f'{fo[0]:02x}']+=1
        lab_ops[lab]['ref_nops'][len(rg['ops'])]+=1
        lab_ops[lab]['ref_delim'][rg['delim']]+=1
        # second op lead if present
        if len(rg['ops'])>1:
            lab_ops[lab]['ref_op2'][f"{rg['ops'][1][0]:02x}:{rg['ops'][1][1]:02x}"]+=1
    fo=ig['ops'][0] if ig['ops'] else (0,0)
    lab_ops[lab]['idl_first'][f'{fo[0]:02x}:{fo[1]:02x}']+=1
    lab_ops[lab]['idl_ops'][' '.join(f'{l:02x}:{a2:02x}' for l,a2 in ig['ops'])]+=1
    if len(examples[lab])<6: examples[lab].append((gi,rp,npv,rk,nk))

print('site labels:', lab_count.most_common())
for lab in ('A','B','fan','AB','none'):
    if lab not in lab_ops: continue
    print(f'\n=== label {lab} (n={lab_count[lab]}) ===')
    for ch in ('ref_first','ref_op2','ref_lead','idl_first','idl_ops','ref_delim'):
        if ch in lab_ops[lab]:
            print(f'  {ch}: {lab_ops[lab][ch].most_common(8)}')
    print('  examples (gi,rp,np,rk,nk):', examples[lab])
