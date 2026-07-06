#!/usr/bin/env python3
"""Generate a self-contained Three.js HTML comparing the DXF GT surface (wireframe)
with the decoded OOT points (green=within 1m of GT, red=miss). Data embedded so it
opens with a double-click (no server/CORS).

USER RULE (2026-07-05, non-negotiable): the points shown MUST come from a
GT-FREE decode of the .00t alone. The DXF is allowed here for SCORING/COLORING
ONLY. Never feed this viewer output from any answer-key-assisted matcher
(closing_solve.py etc.) — that is a lie, not a decode. Pass argv[4] = a
provenance label naming the decoder that produced the points."""
import sys, json
import numpy as np
from scipy.spatial import cKDTree
dxf=sys.argv[1]; xyz=sys.argv[2]; outhtml=sys.argv[3]
prov=sys.argv[4] if len(sys.argv)>4 else 'UNLABELED DECODER'
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
          nv=len(V), nf=len(faces), npd=len(D), nmatch=int(match.sum()),
          prov=prov)
html='''<!DOCTYPE html><html><head><meta charset=utf-8><title>Intercepts: OOT vs DXF</title>
<style>body{margin:0;background:#111;color:#ddd;font:13px sans-serif;overflow:hidden}
#i{position:absolute;top:8px;left:8px;background:#000a;padding:10px;border-radius:6px;line-height:1.6}
button{background:#234;color:#ddd;border:1px solid #456;padding:5px 9px;border-radius:4px;cursor:pointer;margin:2px}</style>
</head><body><div id=i></div>
<script type="importmap">{"imports":{"three":"https://unpkg.com/three@0.164.1/build/three.module.js","three/addons/":"https://unpkg.com/three@0.164.1/examples/jsm/"}}</script>
<script type=module>
import*as THREE from'three';import{OrbitControls}from'three/addons/controls/OrbitControls.js';
const D=__DATA__;
const sc=new THREE.Scene();const _asp=innerWidth/innerHeight;const camO=new THREE.OrthographicCamera(-100*_asp,100*_asp,100,-100,0.1,1e5);const camP=new THREE.PerspectiveCamera(60,_asp,0.1,1e5);let cam=camO;
const r=new THREE.WebGLRenderer({antialias:true});r.setSize(innerWidth,innerHeight);document.body.appendChild(r.domElement);
let ctr=new OrbitControls(cam,r.domElement);let _bsC=new THREE.Vector3(),_bsR=1;
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
// GT vertices as points (a point on every vertex)
const gv=new THREE.BufferGeometry();gv.setAttribute('position',new THREE.Float32BufferAttribute(D.verts,3));
const gpts=new THREE.Points(gv,new THREE.PointsMaterial({color:0x55ddff,size:2.0}));sc.add(gpts);
// frame camera
g.computeBoundingSphere();const bs=g.boundingSphere;_bsC.copy(bs.center);_bsR=bs.radius;const _a=innerWidth/innerHeight,_h=bs.radius*1.2;camO.top=_h;camO.bottom=-_h;camO.left=-_h*_a;camO.right=_h*_a;camO.near=0.1;camO.far=bs.radius*100;camO.updateProjectionMatrix();camP.near=0.1;camP.far=bs.radius*100;camP.updateProjectionMatrix();const _p0=new THREE.Vector3(bs.center.x,bs.center.y-bs.radius*1.5,bs.center.z+bs.radius*1.5);camO.position.copy(_p0);camP.position.copy(_p0);ctr.target.copy(bs.center);ctr.update();
document.getElementById('i').innerHTML=`<b>Intercepts: GT-FREE .00t decode vs DXF</b><br><span style="color:#fa3">Points = ${D.prov} decoding the .00t ALONE.<br>DXF used for the green/red scoring overlay ONLY — never fed to the decoder.</span><br>GT: ${D.nv} verts, ${D.nf} tris<br>Decoded pts: ${D.npd} (<span style=color:#3f3>green=match&lt;1m</span> <span style=color:#f55>red=miss</span>)<br>Matched: ${D.nmatch}/${D.npd} (${(100*D.nmatch/D.npd).toFixed(1)}%)<br><button id=bg>GT points (cyan)</button><button id=bm>GT surface</button><button id=bp>decoded pts</button><br><button id=bo>Ortho [O]</button><button id=bv>Plan view [V]</button>`;
document.getElementById('bg').onclick=()=>{gpts.visible=!gpts.visible};
document.getElementById('bm').onclick=()=>{mesh.visible=!mesh.visible;wire.visible=!wire.visible};
document.getElementById('bp').onclick=()=>{pts.visible=!pts.visible};
function setCam(c){if(c===cam)return;const t=ctr.target.clone(),p=cam.position.clone();ctr.dispose();cam=c;cam.position.copy(p);ctr=new OrbitControls(cam,r.domElement);ctr.target.copy(t);ctr.update();document.getElementById('bo').textContent=(cam===camO?'Ortho [O]':'Persp [P]')}
function planView(){cam.position.set(_bsC.x,_bsC.y,_bsC.z+_bsR*2.5);cam.up.set(0,1,0);ctr.target.copy(_bsC);ctr.update()}
document.getElementById('bo').onclick=()=>setCam(cam===camO?camP:camO);
document.getElementById('bv').onclick=planView;
addEventListener('keydown',e=>{const k=e.key.toLowerCase();if(k==='o')setCam(camO);else if(k==='p')setCam(camP);else if(k==='v')planView()});
addEventListener('resize',()=>{const _a=innerWidth/innerHeight;camO.left=-camO.top*_a;camO.right=camO.top*_a;camO.updateProjectionMatrix();camP.aspect=_a;camP.updateProjectionMatrix();r.setSize(innerWidth,innerHeight)});
(function loop(){requestAnimationFrame(loop);ctr.update();r.render(sc,cam)})();
</script></body></html>'''
html=html.replace('__DATA__',json.dumps(data))
open(outhtml,'w').write(html)
print(f'wrote {outhtml}  (GT {len(V)}v/{len(faces)}f, decoded {len(D)} pts, matched {int(match.sum())} = {100*match.sum()/len(D):.1f}%)')
