#!/usr/bin/env python3
"""Map the tagged-section structure of the geometry region:
ASCII string runs + the e0..40 17 section markers."""
import sys, re

stem = sys.argv[1] if len(sys.argv) > 1 else 'tri-crack-SPHERE'
d = open(f'exampleFiles/{stem}.00t', 'rb').read()
GEO = 8252

# 1) printable ASCII runs (>=3 chars) in the geometry region
print(f'=== {stem}  size={len(d)}  geo@{GEO} ===')
print('-- ASCII runs (offset: text) --')
for m in re.finditer(rb'[\x20-\x7e]{3,}', d[GEO:]):
    print(f'  {GEO+m.start():6d}: {m.group().decode()!r}')

# 2) the e0 ?? 14 20 00 40 17 family of section markers
print('-- section markers (e0 .. 40 17) --')
for m in re.finditer(rb'\xe0.\x14\x20\x00\x40\x17', d):
    print(f'  {m.start():6d}: ' + ' '.join(f'{b:02x}' for b in m.group()))
print('  count:', len(re.findall(rb'\xe0.\x14\x20\x00\x40\x17', d)))
