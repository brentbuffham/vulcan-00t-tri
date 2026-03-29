import struct

# The pyramid has 116 bytes in the coord section for 20 vertices.
# The cube has 61 bytes for 8 vertices. That's ~7.6 bytes/vertex.
# The pyramid has 116/20 = 5.8 bytes/vertex - similar ratio.
# So the byte count is reasonable.

# The cube extracts 6 coord values from 61 bytes:
# 3 FULL (2-3 data bytes + count byte = 3-4 bytes each) = ~10 bytes
# 3 DELTA (1-2 data bytes + count byte = 2-3 bytes each) = ~7 bytes
# Tags and seps: ~44 bytes for metadata
# That's 17 bytes of coord data, 44 bytes of tags/seps.
# Ratio: 28% data, 72% tags.

# For pyramid: we extract 5 coords:
# 1 zero (1 byte) + 2 FULL (3 bytes each) + 2 DELTA (2-3 bytes each) = ~12 bytes
# That's 12 bytes data, 104 bytes tags/seps.
# For 20 vertices we'd expect ~20-40 bytes of coord data.
# So ~20-30 bytes of coord data are hiding in what we think are tags.

# Many of the "zero coordinates" might be E0:00 tags where the 00 is BOTH
# the tag's second byte AND a zero coordinate value.
# If E0:00 = "zero coord + E0 axis stay", we'd get many more zeros.

# Let me count how many E0:00 tags are in the pyramid coord section:
coord = bytes.fromhex(
    'e0 17 00 01 40 69 e0 05 21 01 40 59 e0 05 0f c0'
    ' 00 e0 07 17 c0 0f e0 00 07 e0 0e 47 c0 17 e0 1f'
    ' 27 c0 00 e0 00 37 a0 57 e0 00 07 a0 9f e0 00 0f'
    ' e0 07 1f 01 72 c0 c0 42 60 00 e0 00 2f e0 07 17'
    ' c0 37 a0 17 e0 00 0f c0 5f e0 07 17 c0 2f 00 79'
    ' 60 56 e0 08 00 e0 07 17 e0 00 47 a0 2f c0 3f c0'
    ' 00 e0 07 17 e0 00 2f 01 7f 40 c0 22 e0 04 00 c0'
    ' 17 e0 07 47'.replace(' ', ''))

# Count E0 00 sequences:
e0_00_count = 0
for i in range(len(coord)-1):
    if coord[i] == 0xE0 and coord[i+1] == 0x00:
        e0_00_count += 1
print(f"E0 00 sequences: {e0_00_count}")

# Count C0 00 sequences:
c0_00_count = 0
for i in range(len(coord)-1):
    if coord[i] == 0xC0 and coord[i+1] == 0x00:
        c0_00_count += 1
print(f"C0 00 sequences: {c0_00_count}")

# Count 60 00 sequences:
s60_00_count = 0
for i in range(len(coord)-1):
    if coord[i] == 0x60 and coord[i+1] == 0x00:
        s60_00_count += 1
print(f"60 00 sequences: {s60_00_count}")

# Total potential embedded zeros: E0:00 + C0:00 + 60:00 + standalone 00
standalone_00 = 0
# Parse sequentially to find standalone 00s
pos = 0
while pos < len(coord):
    b = coord[pos]
    if b <= 0x06:
        if b == 0:
            standalone_00 += 1
            pos += 1
        else:
            pos += 1 + b + 1
    elif (b & 7) == 7 and b >= 7:
        pos += 1
    elif b >= 0x60 and pos + 1 < len(coord):
        pos += 2
    else:
        pos += 1
print(f"Standalone 00 bytes: {standalone_00}")

print(f"\nTotal potential zeros: {e0_00_count + c0_00_count + s60_00_count + standalone_00}")
print(f"If each E0:00 and C0:00 also carries a zero coord:")
print(f"  Coords = standalone zeros + E0:00 zeros + explicit count values")
print(f"  = {standalone_00} + {e0_00_count} + 5 non-zero = {standalone_00 + e0_00_count + 5}")

# The pyramid has 20 vertices. If first vertex uses 3 coords (X,Y,Z),
# subsequent vertices use 1 coord each (changing one axis),
# total coords = 3 + 19 = 22.
# But some vertices might not need explicit coords if they share via C0 slots.
# With C0 tags pointing to shared vertices, we might need fewer coords.

# Let me check how many C0 tags there are:
c0_tags = 0
pos = 0
while pos < len(coord):
    b = coord[pos]
    if b <= 0x06:
        if b == 0:
            pos += 1
        else:
            pos += 1 + b + 1
    elif (b & 7) == 7 and b >= 7:
        pos += 1
    elif b >= 0x60:
        if (b & 0xE0) == 0xC0:
            c0_tags += 1
        if pos + 1 < len(coord):
            pos += 2
        else:
            pos += 1
    else:
        pos += 1
print(f"\nC0 tags in coord section: {c0_tags}")
print("C0 tags assign vertices to shared coord slots, reducing needed coords")
