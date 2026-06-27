#!/usr/bin/env python3
"""Generate a self-contained Three.js HTML comparing the DXF GT surface (wireframe)
with the decoded OOT points (green=within 1m of GT, red=miss). Data embedded so it
opens with a double-click (no server/CORS)."""
import sys, json
import numpy as np
from scipy.spatial import cKDTree
dxf=sys.argv[1]; xyz=sys.argv[2]; outhtml=sys.argv[3]
# reuse parse_dxf
import importlib.util
spec=importlib.util.spec_from_file_location('pd','python/parse_dxf.py')
# parse inline (avoid running its __main__)
lines=open(dxf,'r',errors='ignore').read().split('\n')
i=0;n=len(lines);tris=[];cur={};in3d=False
def fn(s):
    try:return float(s)
    except:return None
while i<n-1:
    code=lines[i].strip();val=lines[i+1].strip() if i+1<n else ''
    if code=='0':
        if in3d and len(cur)>=9: tris.append(cur.copy())
        in3d=(val.upper()=='3DFACE');cur={}
    elif in3d:
        c=fn(code);f=fn(val)
        if c is not None and f is not None and abs(f)<1e8:
            ci=int(c)
            for k in range(4):
                if ci==10+k:cur[(k,0)]=f
                elif ci==20+k:cur[(k,1)]=f
                elif ci==30+k:cur[(k,2)]=f
    i+=2
if in3d and len(cur)>=9: tris.append(cur.copy())
verts=[];faces=[];vindex={}
def vid(p):
    k=(round(p[0],3),round(p[1],3),round(p[2],3))
    if k not in vindex: vindex[k]=len(verts);verts.append(k)
    return vindex[k]
for t in tris:
    cs=[]
    for k in range(4):
        if (k,0) in t and (k,1) in t and (k,2) in t: cs.append((t[(k,0)],t[(k,1)],t[(k,2)]))
    uq=[]
    for c in cs:
        if c not in uq: uq.append(c)
    if len(uq)>=3: faces.append([vid(c) for c in uq[:3]])
V=np.array(verts)
D=np.loadtxt(xyz,delimiter=',')
c=V.mean(0)
tree=cKDTree(V); dd,_=tree.query(D); match=(dd<1.0)
Vc=(V-c).round(3); Dc=(D-c).round(3)
data=dict(verts=Vc.flatten().tolist(), faces=[x for f in faces for x in f],
          pts=Dc.flatten().tolist(), matched=match.astype(int).tolist(),
          nv=len(V), nf=len(faces), npd=len(D), nmatch=int(match.sum()))
html='''<!DOCTYPE html><html><head><meta charset=utf-8><title>Intercepts: OOT vs DXF</title>
<style>body{margin:0;background:#111;color:#ddd;font:13px sans-serif;overflow:hidden}
#i{position:absolute;top:8px;left:8px;background:#000a;padding:10px;border-radius:6px;line-height:1.6}
button{background:#234;color:#ddd;border:1px solid #456;padding:5px 9px;border-radius:4px;cursor:pointer;margin:2px}</style>
</head><body><div id=i></div>
<script type="importmap">{"imports":{"three":"https://unpkg.com/three@0.164.1/build/three.module.js","three/addons/":"https://unpkg.com/three@0.164.1/examples/jsm/"}}</script>
<script type=module>
import*as THREE from'three';import{OrbitControls}from'three/addons/controls/OrbitControls.js';
const D=__DATA__;
const sc=new THREE.Scene();const cam=new THREE.PerspectiveCamera(60,innerWidth/innerHeight,0.1,1e5);
const r=new THREE.WebGLRenderer({antialias:true});r.setSize(innerWidth,innerHeight);document.body.appendChild(r.domElement);
const ctr=new OrbitControls(cam,r.domElement);
// GT mesh
const g=new THREE.BufferGeometry();g.setAttribute('position',new THREE.Float32BufferAttribute(D.verts,3));g.setIndex(D.faces);g.computeVertexNormals();
const mesh=new THREE.Mesh(g,new THREE.MeshBasicMaterial({color:0x114433,transparent:true,opacity:0.5,side:THREE.DoubleSide}));
const wire=new THREE.LineSegments(new THREE.WireframeGeometry(g),new THREE.LineBasicMaterial({color:0x33cc88,transparent:true,opacity:0.35}));
sc.add(mesh);sc.add(wire);
// decoded points colored by match
const pg=new THREE.BufferGeometry();pg.setAttribute('position',new THREE.Float32BufferAttribute(D.pts,3));
const col=[];for(let k=0;k<D.matched.length;k++){if(D.matched[k]){col.push(0.2,1,0.3)}else{col.push(1,0.2,0.2)}}
pg.setAttribute('color',new THREE.Float32BufferAttribute(col,3));
const pts=new THREE.Points(pg,new THREE.PointsMaterial({size:1.5,vertexColors:true}));sc.add(pts);
// frame camera
g.computeBoundingSphere();const bs=g.boundingSphere;cam.position.set(bs.center.x,bs.center.y-bs.radius*1.5,bs.radius*1.5);ctr.target.copy(bs.center);ctr.update();
document.getElementById('i').innerHTML=`<b>Intercepts: OOT decode vs DXF</b><br>GT: ${D.nv} verts, ${D.nf} tris<br>Decoded pts: ${D.npd} (<span style=color:#3f3>green=match&lt;1m</span> <span style=color:#f55>red=miss</span>)<br>Matched: ${D.nmatch}/${D.npd} (${(100*D.nmatch/D.npd).toFixed(1)}%)<br><button id=bm>GT surface</button><button id=bp>decoded pts</button>`;
document.getElementById('bm').onclick=()=>{mesh.visible=!mesh.visible;wire.visible=!wire.visible};
document.getElementById('bp').onclick=()=>{pts.visible=!pts.visible};
addEventListener('resize',()=>{cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();r.setSize(innerWidth,innerHeight)});
(function loop(){requestAnimationFrame(loop);ctr.update();r.render(sc,cam)})();
</script></body></html>'''
html=html.replace('__DATA__',json.dumps(data))
open(outhtml,'w').write(html)
print(f'wrote {outhtml}  (GT {len(V)}v/{len(faces)}f, decoded {len(D)} pts, matched {int(match.sum())} = {100*match.sum()/len(D):.1f}%)')
