import os

base = 'C:/Users/brent/desktop/GIT/vulcan-00t-tri/exampleFiles/'

for name in ['tri-crack-triangle', 'tri-crack', 'tri-crack-solid', 'tri-crack-prism']:
    dxf_path = base + name + '.dxf'
    if not os.path.exists(dxf_path):
        continue
    with open(dxf_path, 'r') as f:
        dxf = f.read()

    faces = dxf.split('3DFACE')
    print(f"\n{name}: {len(faces)-1} 3DFACE entities")
    for fi, face in enumerate(faces[1:]):
        lines = face.strip().split('\n')
        coords = {}
        for j, line in enumerate(lines):
            code = line.strip()
            if code in ('10','11','12','13','20','21','22','23','30','31','32','33'):
                if j+1 < len(lines):
                    coords[int(code)] = float(lines[j+1].strip())
        verts = []
        for vi in range(4):
            x = coords.get(10+vi, 0)
            y = coords.get(20+vi, 0)
            z = coords.get(30+vi, 0)
            verts.append((round(x,1), round(y,1), round(z,1)))
        print(f'  Face {fi}: {verts}')
