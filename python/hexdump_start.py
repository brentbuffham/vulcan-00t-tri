d=open(r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t','rb').read()
for off in range(8326,8500,16):
    print(f'{off:6d}: {d[off:off+16].hex(" ")}')
