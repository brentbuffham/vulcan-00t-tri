#!/usr/bin/env python3
"""Strict state machine: TAG -> SEP -> COUNT(<=6) -> payload -> TAG ...
At each COUNT-expected slot, record the byte. Clean = 0..6. Anything >6 is a
MARKER. Count markers, histogram their opener byte, and compare to GT rows
(2907) and verts (1.21M). Also histogram the TAG byte that opened each marker."""
import sys, struct
import numpy as np
from collections import Counter
oot=sys.argv[1]; cachedir=sys.argv[2]
BOUND=int(sys.argv[3]) if len(sys.argv)>3 else 25_300_000
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&0x07)==0x07 and b>=0x07
FULL_IND=(0x40,0x41,0xC0,0xC1)
clean=0; marker=0; opener=Counter(); marker_tag=Counter(); marker_sep=Counter()
nb_dist=Counter()
pos=8328+24
END=min(geo_end,BOUND)
# state machine
state='TAG'; cur_tag=None; cur_sep=None
while pos<END:
    b=d[pos]
    if state=='TAG':
        if (b&0xE0) in TAG_CLASSES and b>0x06:
            cur_tag=b; state='SEP'; pos+=1
        elif is_sep(b):  # sometimes SEP without explicit new TAG? skip
            pos+=1
        elif b<=0x06:
            # count without tag/sep (shouldn't happen in strict); treat as clean
            nb=b+1; pos+=1+nb; clean+=1; nb_dist[b]+=1; state='TAG'
        else:
            pos+=1
    elif state=='SEP':
        if is_sep(b):
            cur_sep=b; state='COUNT'; pos+=1
        elif (b&0xE0) in TAG_CLASSES:  # TAG TAG (no sep) -> marker territory
            marker+=1; opener[b]+=1; marker_tag[cur_tag]+=1; state='TAG'
        else:
            marker+=1; opener[b]+=1; marker_tag[cur_tag]+=1; pos+=1; state='TAG'
    elif state=='COUNT':
        if b<=0x06:
            nb=b+1; pos+=1+nb; clean+=1; nb_dist[b]+=1; state='TAG'
        else:
            marker+=1; opener[b]+=1; marker_tag[cur_tag]+=1; marker_sep[cur_sep]+=1
            pos+=1; state='TAG'
print(f'clean records: {clean:,}   markers (bad count slot): {marker:,}')
print(f'GT rows=2907  GT verts~1,212,272')
print('marker opener byte (top 15):', opener.most_common(15))
print('TAG before marker (top 12):', marker_tag.most_common(12))
print('SEP before marker (top 12):', marker_sep.most_common(12))
print('clean count-byte dist:', dict(sorted(nb_dist.items())))
