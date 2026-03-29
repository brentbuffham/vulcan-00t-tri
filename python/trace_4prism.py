import struct

data = bytes.fromhex('02 40 8f 40 60 16 01 40 59 60 06 03 00 40 b3 88 20 05 20 07 01 92 c0 20 05 20 07 e0 0f 17 00 49 20 1c 20 00'.replace(' ', ''))

def isSep(b):
    return (b & 0x07) == 0x07 and b >= 0x07

prev = [0]*8
hadFull = False
pos = 0

while pos < len(data):
    b = data[pos]
    if b <= 0x06:
        if b == 0 and not hadFull:
            print(f"  +{pos:02x}: ZERO = 0.0")
            pos += 1
            continue
        nb = b + 1
        stored = list(data[pos+1:pos+1+nb])
        result = [0]*8
        isFull = stored[0] in (0x40, 0x41, 0xC0, 0xC1)
        if isFull:
            for i in range(nb): result[i] = stored[i]
            hadFull = True
        else:
            result[0] = prev[0]
            for i in range(nb): result[i+1] = stored[i]
            for i in range(nb+1, 8): result[i] = prev[i]
        val = struct.unpack('>d', bytes(result[:8]))[0]
        prev = result[:]
        print(f"  +{pos:02x}: COUNT({b}) [{' '.join(f'{x:02x}' for x in stored)}] {'FULL' if isFull else 'DELTA'} = {val:.1f}")
        pos += 1 + nb
    elif isSep(b):
        print(f"  +{pos:02x}: SEP(0x{b:02x})")
        pos += 1
    elif b >= 0x60 and pos+1 < len(data):
        print(f"  +{pos:02x}: TAG({b:02x}:{data[pos+1]:02x})")
        pos += 2
    else:
        print(f"  +{pos:02x}: SKIP(0x{b:02x})")
        pos += 1
