#!/usr/bin/env python3
"""Map the macro-layout of a .00t: runs of zeros vs. data, and 8-byte framing."""
import sys

stem = sys.argv[1] if len(sys.argv) > 1 else 'tri-crack-solid'
data = open(f'exampleFiles/{stem}.00t', 'rb').read()
n = len(data)
print(f'== {stem} ==  size={n}\n')

# run-length map of zero vs non-zero regions
runs = []
i = 0
while i < n:
    z = data[i] == 0
    j = i
    while j < n and (data[j] == 0) == z:
        j += 1
    runs.append((i, j, 'ZERO' if z else 'DATA', j - i))
    i = j

print('region map (runs >= 8 bytes shown; tiny runs merged into context):')
for (a, b, kind, ln) in runs:
    if ln >= 16 or kind == 'DATA':
        sample = data[a:min(a+24, b)].hex()
        print(f'  {a:6d}-{b:6d}  {kind:4s} len={ln:5d}  {sample}')

# show ASCII strings >= 4 chars (headers like "Variant", "POLHED", etc.)
print('\nASCII strings (>=4 printable):')
import re
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    print(f'  {m.start():6d}: {m.group().decode("latin1")!r}')
