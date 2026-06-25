#!/usr/bin/env python3
"""Dump the compact token sequence (TAG/SEP/nb/firstbyte) over a range to find
the per-vertex grouping (3.43M records / 1.21M verts ~= 2.8 rec/vertex). Look for
a repeating unit and a vertex delimiter tag."""
import sys, struct
from collections import Counter
oot=sys.argv[1]
START=int(sys.argv[2]) if len(sys.argv)>2 else 8904
END=int(sys.argv[3]) if len(sys.argv)>3 else 9120
d=open(oot,'rb').read()
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
pos=START
seq=[]
while pos<END:
    b=d[pos]
    if b<=0x06:
        nb=b+1; pl=d[pos+1:pos+1+nb]; seq.append(('C',nb,pl[0] if pl else -1)); pos+=1+nb
    elif is_sep(b): seq.append(('S',b)); pos+=1
    elif (b&0xE0) in TAG_CLASSES: seq.append(('T',b)); pos+=1
    else: seq.append(('?',b)); pos+=1
# print one record-group per line: TAG SEP CNT
line=[]
for t in seq:
    if t[0]=='T':
        if line: print('  '.join(line));
        line=[f'TAG {t[1]:02x}']
    elif t[0]=='S': line.append(f'sep{t[1]:02x}')
    elif t[0]=='C': line.append(f'CNT nb={t[1]} fb={t[2]:02x}')
    else: line.append(f'?{t[1]:02x}')
if line: print('  '.join(line))
# stats over a big range
print('\n--- TAG low-nibble census over [START..END] ---')
ln=Counter();
for t in seq:
    if t[0]=='T': ln[t[1]&0x0f]+=1
print('TAG low nibble:', dict(sorted(ln.items())))
hn=Counter()
for t in seq:
    if t[0]=='T': hn[t[1]&0xf0]+=1
print('TAG high nibble:', {hex(k):v for k,v in sorted(hn.items())})
