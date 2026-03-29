with open('C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/tri-crack.00t', 'rb') as f:
    data = f.read()

hdrIdx = data.find(bytes([0x43, 0xE0, 0x0E, 0x2F]))
ds = hdrIdx - 5

# Find face marker
fm = -1
for i in range(ds + 30, len(data) - 1):
    if data[i] == 0x20 and data[i+1] == 0x00:
        fm = i
        break

# Find attr section
shaded = data.find(b'SHADED', ds)
attr_suffix = bytes([0x00,0x05,0x40,0x04,0x00,0x0A,0x20,0x08,0x07])
attr_pos = data.find(attr_suffix, ds)

face_end = attr_pos if attr_pos > 0 else (shaded - 20 if shaded > 0 else len(data))

face_region = data[fm:face_end]
print(f"Face section: 0x{fm:04x} to 0x{face_end:04x} ({len(face_region)} bytes)")
print(f"Bytes: {' '.join(f'{b:02x}' for b in face_region)}")
print(f"Header: verts={data[ds+12]}, faces={data[ds+19]}")

# The plane should have 5 vertices and 2 faces
# 5 vertices = triangle + 1 extra point = 2 triangles (a quad split)
