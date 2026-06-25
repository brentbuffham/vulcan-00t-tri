#!/usr/bin/env python3
"""Decisive delta test. For the GT column (X=60660.70) descending in Y from the
entry point, compute Y and Z as IEEE-754 BE doubles, take consecutive integer
deltas of the 64-bit patterns, and print alongside the actual stream payloads.
If the payload == low bytes of a float-bit-delta (Y or Z), the model is bit-delta."""
import sys, struct, pickle
import numpy as np
from collections import defaultdict
oot=sys.argv[1]; SP=sys.argv[2]
gt={0:np.load(f'{SP}/gt_x.npy'),1:np.load(f'{SP}/gt_y.npy'),2:np.load(f'{SP}/gt_z.npy')}
GT=pickle.load(open(f'{SP}/gt_keys.pkl','rb'))
cols=defaultdict(list)
for (xk,yk,zk) in GT: cols[xk].append((yk,zk))
col=sorted(cols[6066070], key=lambda t:-t[0])  # X=60660.70 descending Y
# entry near Y=214677.25
ys=[y for y,_ in col]
ei=0
while ei<len(ys) and ys[ei]>21467725: ei+=1
sub=col[ei:ei+14]
def bits(v): return struct.unpack('>Q',struct.pack('>d',v))[0]
print('GT column X=60660.70 descending from entry:')
print(f"{'Y':>11} {'Z':>9}  {'Ybits':>16} {'dYbits(signed)':>16}  {'Zbits':>16} {'dZbits(signed)':>16}")
pY=pZ=None
for (yk,zk) in sub:
    Y=yk/100; Z=zk/100; by=bits(Y); bz=bits(Z)
    dY=(by-pY) if pY is not None else 0
    dZ=(bz-pZ) if pZ is not None else 0
    print(f'{Y:11.2f} {Z:9.3f}  {by:016x} {dY:16d}  {bz:016x} {dZ:16d}')
    pY,pZ=by,bz
# now the stream payloads
d=open(oot,'rb').read()
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
print('\nstream records 8895..8990 (raw):')
pos=8895
while pos<8990:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=d[pos+1:pos+1+nb]
        print(f'  {pos:6d} CNT nb={nb} payload={pl.hex(" ")}  int={int.from_bytes(pl,"big")}')
        pos+=1+nb
    elif is_sep(b): print(f'  {pos:6d} SEP {b:02x}'); pos+=1
    elif (b&0xE0) in TAG_CLASSES: print(f'  {pos:6d} TAG {b:02x}'); pos+=1
    else: print(f'  {pos:6d} ??? {b:02x}'); pos+=1
