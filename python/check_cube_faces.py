with open('C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/tri-crack-solid.00t', 'rb') as f:
    data = f.read()

hdrIdx = data.find(bytes([0x43, 0xE0, 0x0E, 0x2F]))
ds = hdrIdx - 5

fm = -1
for i in range(ds + 30, len(data) - 1):
    if data[i] == 0x20 and data[i+1] == 0x00:
        fm = i
        break

attr_suffix = bytes([0x00,0x05,0x40,0x04,0x00,0x0A,0x20,0x08,0x07])
attr_pos = data.find(attr_suffix, ds)

face_region = data[fm:attr_pos]
print(f"Cube face section ({len(face_region)} bytes):")
print(' '.join(f'{b:02x}' for b in face_region[:40]))
print('...')
print(f"Header: verts={data[ds+12]}, faces={data[ds+19]}")

# After 20 00, what comes first?
# 20 00 then...
for i in range(2, min(20, len(face_region))):
    b = face_region[i]
    print(f"  +{i}: 0x{b:02x}", end='')
    if b <= 0x06:
        print(f" (count={b}, data byte={face_region[i+1]:02x})")
    elif b & 0xE0 == 0x40:
        print(f" (40-class tag, byte2=0x{face_region[i+1]:02x})")
        break
    elif b & 0xE0 == 0x00 and b > 0x06:
        print(f" (potential vertex ref)")
    else:
        print()
