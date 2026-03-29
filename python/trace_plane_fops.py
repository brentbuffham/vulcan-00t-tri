# Trace the fops for the plane face section
face_bytes = bytes.fromhex('20 00 40 a7 00 03 20 07 00 04 20 03 e0 03 00 40 17 40 ab 40 1b e0 00 00 00 01 20 09 00 82 20 03'.replace(' ', ''))

def isSep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

fops = []
fpos = 0
while fpos < len(face_bytes):
    fb = face_bytes[fpos]
    if fb <= 0x06:
        fnb = fb + 1
        if fpos+1+fnb > len(face_bytes): break
        fops.append({'type':'DATA', 'value': face_bytes[fpos+1]})
        fpos += 1 + fnb
    elif isSep(fb):
        fops.append({'type':'SEP', 'value': fb})
        fpos += 1
    elif fpos+1 < len(face_bytes):
        fb2 = face_bytes[fpos+1]
        cls_map = {0x20:'20',0x40:'40',0xC0:'C0',0xE0:'E0'}
        fc = cls_map.get(fb & 0xE0, '??')
        if fb == 0xE1: fc = 'E1'
        fops.append({'type':'TAG', 'cls':fc, 'byte2':fb2, 'lo':fb2&0xF, 'hi':(fb2>>4)&0xF})
        fpos += 2
    else:
        break

print("Face section fops:")
for i, op in enumerate(fops):
    if op['type'] == 'DATA':
        print(f"  [{i}] DATA value={op['value']} (0x{op['value']:02x})")
    elif op['type'] == 'TAG':
        print(f"  [{i}] TAG {op['cls']}:{op['byte2']:02x}")
    elif op['type'] == 'SEP':
        print(f"  [{i}] SEP 0x{op['value']:02x}")

# Now trace the init vertex extraction with the fix
print("\nInit vertex extraction:")
fs2 = False
skippedInitMeta = False
iv2 = []
for op in fops:
    if op['type'] == 'TAG' and op['cls'] == '20' and op['byte2'] == 0x00:
        fs2 = True
        print("  -> fs2=true (found 20:00)")
        continue
    if fs2:
        if not skippedInitMeta and op['type'] == 'TAG' and op['cls'] == '40':
            skippedInitMeta = True
            print(f"  -> skipped init meta TAG 40:{op['byte2']:02x}")
            continue
        if op['type'] == 'TAG' and (op['cls'] == '40' or op['cls'] == 'C0'):
            print(f"  -> break at TAG {op['cls']}:{op['byte2']:02x}")
            break
        if op['type'] == 'DATA' and 1 <= op['value'] <= 200:
            iv2.append(op['value'])
            print(f"  -> vertex ref: {op['value']}")
        if op['type'] == 'TAG' and op['cls'] == 'E0':
            print(f"  -> break at E0:{op['byte2']:02x}")
            break

print(f"\niv2 = {iv2}")
if len(iv2) >= 3:
    initTri = [iv2[0]-1, iv2[1]-1, iv2[2]-1]
    print(f"initTri = {initTri}")
else:
    print(f"iv2 has {len(iv2)} entries (need >= 3), defaulting to [0,1,2]")

# The plane has only 2 vertex refs (3 and 4). 
# But 20:07 between them isn't being counted.
# Wait - in the fops, how is "00 03 20 07 00 04 20 03" parsed?
# 00 -> count=0, nb=1, DATA value=face_bytes[fpos+1]=03. fpos+=2.
# 20 07 -> TAG(20:07). fpos+=2.
# 00 -> count=0, nb=1, DATA value=04. fpos+=2.  
# 20 03 -> TAG(20:03). fpos+=2.
# So we get DATA(3), TAG(20:07), DATA(4), TAG(20:03)

# But the init vertex extraction code at line 399:
# "if (op.type==='DATA' && op.value >= 1 && op.value <= 200) iv2.push(op.value);"
# The TAG(20:07) is ignored (not DATA, not 40/C0/E0)
# So iv2 = [3, 4] - only 2 vertex refs!

# In the cube: 00 01 -> DATA(1), 20 03 -> TAG(20:03) [ignored], 
#              00 02 -> DATA(2), 20 03 -> TAG(20:03) [ignored],
#              00 04 -> DATA(4), 20 03 -> TAG(20:03) [ignored]
# iv2 = [1, 2, 4] -> 3 refs -> initTri = [0, 1, 3]

# The plane only lists 2 vertices (3 and 4) in the init section!
# But it needs 3 for a triangle. Maybe the 40:a7 metadata carries the third vertex?
# 0xa7: lo=7, hi=0xa=10. Vertex 10+1? No, that's too high.
# Or maybe the initial triangle is implicit (0,1,2) and vertex refs 3,4 are for C ops?

print("\nAlternative: initial tri is implicit [0,1,2]")
print("Vertex refs 3,4 are for the face decoder (C ops)")
print("initTri = [0,1,2], vertex queue = [2,3] (0-based from values 3,4)")
