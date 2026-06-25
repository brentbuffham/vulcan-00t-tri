#!/usr/bin/env python3
"""Dump raw tokens in the topology section and tally tag low-nibble / opcode
candidates. CLERS expects: C dominant (~50%), R next, then L/E/S."""
import sys, struct
from collections import Counter
oot=sys.argv[1]
START=int(sys.argv[2]) if len(sys.argv)>2 else 35_000_000
MODE=sys.argv[3] if len(sys.argv)>3 else 'dump'  # 'dump' or 'stats'
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG_CLASSES=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7
if MODE=='dump':
    pos=START; n=0
    line=[]
    while pos<geo_end and n<80:
        b=d[pos]
        if b<=0x06:
            nb=b+1; pl=d[pos+1:pos+1+nb]
            line.append(f'CNT{nb}[{pl.hex()}]'); pos+=1+nb
            print('  '.join(line)); line=[]; n+=1
        elif is_sep(b): line.append(f's{b:02x}'); pos+=1
        elif (b&0xE0) in TAG_CLASSES: line.append(f'T{b:02x}'); pos+=1
        else: line.append(f'?{b:02x}'); pos+=1
else:
    # stats: tag byte census + tag-high-nibble + per-record leading tag
    pos=START; tags=Counter(); recs=0; lead=Counter(); seps=Counter()
    cur_tag=None
    END=min(geo_end,START+4_000_000)
    while pos<END:
        b=d[pos]
        if b<=0x06:
            nb=b+1; pos+=1+nb; recs+=1
            if cur_tag is not None: lead[cur_tag]+=1
            cur_tag=None
        elif is_sep(b): seps[b]+=1; pos+=1
        elif (b&0xE0) in TAG_CLASSES: tags[b]+=1; cur_tag=b; pos+=1
        else: pos+=1
    print(f'records: {recs:,}')
    print('all tag bytes top20:', tags.most_common(20))
    print('lead tag before CNT top20:', lead.most_common(20))
    hn=Counter()
    for k,v in tags.items(): hn[k&0xf0]+=v
    print('tag high-nibble:', {hex(k):v for k,v in sorted(hn.items())})
    print('sep top10:', seps.most_common(10))
