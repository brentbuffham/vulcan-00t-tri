#!/usr/bin/env python3
"""Validate the [tag][sep][count][payload] framing: sep must satisfy (b&7)==7.
Report % valid, where it first breaks, tag/count histograms."""
import sys
from collections import Counter
oot=sys.argv[1]; BOUND=int(sys.argv[2]) if len(sys.argv)>2 else 26_222_853
d=open(oot,'rb').read()
pos=8352; ok=0; bad=0; first_bad=None
tagh=Counter(); cnth=Counter(); seph=Counter(); clsh=Counter()
while pos+3<=BOUND:
    tag=d[pos]; sep=d[pos+1]; count=d[pos+2]; nb=count+1
    if (sep&7)==7:
        ok+=1; tagh[tag]+=1; cnth[count]+=1; seph[sep]+=1; clsh[tag&0xE0]+=1
    else:
        bad+=1
        if first_bad is None: first_bad=pos
        pos+=1; continue   # try to resync by 1
    pos=pos+3+nb
tot=ok+bad
print(f'records ok(sep valid)={ok:,}  bad={bad:,}  validRate={ok/max(1,tot)*100:.2f}%  first_bad@{first_bad}')
print(f'\ntag&0xE0 class histogram:')
for k,v in clsh.most_common(): print(f'  {k:#04x}: {v:,}')
print(f'\ntop tags:')
for k,v in tagh.most_common(12): print(f'  {k:#04x}: {v:,}')
print(f'\ncount(nb-1) histogram:')
for k,v in sorted(cnth.items()): print(f'  count={k:#04x} (nb={k+1}): {v:,}')
print(f'\ntop seps:')
for k,v in seph.most_common(10): print(f'  {k:#04x}: {v:,}')
