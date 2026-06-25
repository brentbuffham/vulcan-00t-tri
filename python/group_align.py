#!/usr/bin/env python3
"""Vertex = group of records ending at a 0x60 refine (pattern [20][20][60]).
Parse groups in a constant-X run, align each group to the next GT column vertex
(descending Y), print the two primary payloads + refine + GT (Y,Z). Crack what
A and B encode."""
import sys, struct, pickle
import numpy as np
from collections import defaultdict
oot=sys.argv[1]; SP=sys.argv[2]
START=int(sys.argv[3]) if len(sys.argv)>3 else 8989
END=int(sys.argv[4]) if len(sys.argv)>4 else 9300
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
GT=pickle.load(open(f'{SP}/gt_keys.pkl','rb'))
cols=defaultdict(list)
for (xk,yk,zk) in GT: cols[xk].append((yk,zk))
col=sorted(cols[6066070], key=lambda t:-t[0])  # X=60660.70 descending Y
def be(b): return struct.unpack('>d',(bytes(b)+b'\x00'*8)[:8])[0]
d=open(oot,'rb').read()
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
# parse tokens
toks=[]; pos=START
while pos<END:
    b=d[pos]
    if b<=0x06:
        nb=b+1; toks.append(('C',nb,d[pos+1:pos+1+nb],pos)); pos+=1+nb
    elif is_sep(b): toks.append(('S',b,None,pos)); pos+=1
    elif (b&0xE0) in TAG_CLASSES: toks.append(('T',b,None,pos)); pos+=1
    else: toks.append(('?',b,None,pos)); pos+=1
# build groups: a group = records up to and including a 0x60-tagged coord
groups=[]; cur=[]; lasttag=0x20
for k,v,pl,p in toks:
    if k=='T': lasttag=v
    elif k=='C':
        cur.append((lasttag,pl,p))
        if (lasttag&0xE0)==0x60:
            groups.append(cur); cur=[]
if cur: groups.append(cur)
# find GT entry near Y=214670 (we're past the first window); just list groups vs col tail
# align: assume each group = one vertex, descending. Find entry by first group.
print(f'{len(groups)} groups in [{START}..{END}]')
# GT window: take col points with Y < 214672 (we are below entry)
gi=0
while gi<len(col) and col[gi][0]>21467125: gi+=1
print(f"{'grp@':>6} {'A(tag/pl)':>22} {'B(tag/pl)':>22} {'refine':>14}   {'GTy':>10} {'GTz':>8}")
for g in groups:
    prim=[(t,pl) for (t,pl,p) in g if (t&0xE0)!=0x60]
    refs=[(t,pl) for (t,pl,p) in g if (t&0xE0)==0x60]
    A=prim[0] if len(prim)>0 else (0,b'')
    B=prim[1] if len(prim)>1 else (0,b'')
    R=refs[0] if refs else (0,b'')
    gy,gz=(col[gi] if gi<len(col) else (0,0))
    print(f'{g[0][2]:6d} {A[0]:02x}:{A[1].hex():>18} {B[0]:02x}:{B[1].hex():>18} '
          f'{R[0]:02x}:{R[1].hex():>9}   {gy/100:10.2f} {gz/100:8.3f}')
    gi+=1
