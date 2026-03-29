with open('C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/tri-crack-4sides-prism.00t', 'rb') as f:
    data = f.read()
hdrIdx = data.find(bytes([0x43, 0xE0, 0x0E, 0x2F]))
ds = hdrIdx - 5
cs = ds + 23
print('4prism coord bytes:', ' '.join(f'{b:02x}' for b in data[cs:cs+40]))
print('header verts:', data[ds+12], 'faces:', data[ds+19])
