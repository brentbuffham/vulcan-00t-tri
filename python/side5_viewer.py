"""Self-contained viewer: GT-FREE decoded FACES (side4) over the GT-free
decoded points (P_v11), with the DXF GT surface as a scoring overlay only.
Decoded faces colored green=GT-correct / red=wrong (connectivity scoring).
TRUTH-ONLY: faces + points are GT-free decode; DXF/map11 used for coloring
ONLY. Labels state provenance + partial coverage.
"""
import json
import numpy as np

P = np.load('P_v11_intercepts.npy')            # slot-ordered decoded xyz (GT-free)
V = np.loadtxt('intercepts_gt.csv', delimiter=',')   # GT verts (scoring only)
Fg = np.load('faces_gt.npy')                   # GT faces (scoring only)
df = json.load(open('decoded_faces.json'))     # GT-free decoded tris (slot idx)
from scipy.spatial import cKDTree

c = V.mean(0)
# point categories vs GT (scoring overlay only)
tree = cKDTree(V); dd, _ = tree.query(P); match = dd < 0.25
treeXY = cKDTree(V[:, :2]); ddxy, _ = treeXY.query(P[:, :2])
cat = np.where(match, 1, np.where((~match) & (ddxy < 0.25), 2, 0))

Pc = (P - c).round(3); Vc = (V - c).round(3)
# decoded faces: flatten slot-index triples; per-tri class:
#   2 = scorable & GT-correct, 1 = scorable & wrong, 0 = unscorable (slot unmapped)
tris = df['tris']; goodf = df['good']; scorf = df['scor']
dfaces = [x for t in tris for x in t]
fclass = [2 if (scorf[i] and goodf[i]) else (1 if scorf[i] else 0)
          for i in range(len(tris))]
nscor = int(np.sum(scorf)); ngood = int(np.sum(np.array(goodf) & np.array(scorf)))

data = dict(
    verts=Vc.flatten().tolist(), faces=[int(x) for f in Fg for x in f],
    pts=Pc.flatten().tolist(), cat=cat.astype(int).tolist(),
    dfaces=dfaces, fclass=fclass,
    nv=len(V), nf=len(Fg), npd=len(P), nmatch=int(match.sum()),
    ntri=len(tris), nscor=nscor, ngood=ngood,
    prov='decode_v11_z (coords) + strip machine w/ GT-free S (side_rule)')

HTML = r'''<!DOCTYPE html><html><head><meta charset=utf-8><title>Intercepts: GT-free decoded FACES</title>
<style>body{margin:0;background:#111;color:#ddd;font:13px sans-serif;overflow:hidden}
#i{position:absolute;top:8px;left:8px;background:#000b;padding:10px;border-radius:6px;line-height:1.6;max-width:44em}
button{background:#234;color:#ddd;border:1px solid #456;padding:5px 9px;border-radius:4px;cursor:pointer;margin:2px}</style>
</head><body><div id=i></div>
<script type="importmap">{"imports":{"three":"https://unpkg.com/three@0.164.1/build/three.module.js","three/addons/":"https://unpkg.com/three@0.164.1/examples/jsm/"}}</script>
<script type=module>
import*as THREE from'three';import{OrbitControls}from'three/addons/controls/OrbitControls.js';
const D=__DATA__;
const sc=new THREE.Scene();const _asp=innerWidth/innerHeight;
const camO=new THREE.OrthographicCamera(-100*_asp,100*_asp,100,-100,0.1,1e5);
const camP=new THREE.PerspectiveCamera(60,_asp,0.1,1e5);let cam=camO;
const r=new THREE.WebGLRenderer({antialias:true});r.setSize(innerWidth,innerHeight);document.body.appendChild(r.domElement);
let ctr=new OrbitControls(cam,r.domElement);let _bsC=new THREE.Vector3(),_bsR=1;
// GT surface (scoring overlay only) - faint
const g=new THREE.BufferGeometry();g.setAttribute('position',new THREE.Float32BufferAttribute(D.verts,3));g.setIndex(D.faces);g.computeVertexNormals();
const wire=new THREE.LineSegments(new THREE.WireframeGeometry(g),new THREE.LineBasicMaterial({color:0x2a6650,transparent:true,opacity:0.25}));
sc.add(wire);
// decoded points (GT-free) colored by score
const posG=[],posZ=[],posR=[];
for(let k=0;k<D.cat.length;k++){const x=D.pts[k*3],y=D.pts[k*3+1],z=D.pts[k*3+2];
  if(D.cat[k]===1)posG.push(x,y,z);else if(D.cat[k]===2)posZ.push(x,y,z);else posR.push(x,y,z);}
function pts(a,col,s){const b=new THREE.BufferGeometry();b.setAttribute('position',new THREE.Float32BufferAttribute(a,3));
  const p=new THREE.Points(b,new THREE.PointsMaterial({color:col,size:s,sizeAttenuation:false}));sc.add(p);return p;}
const ptsG=pts(posG,0x33ff55,4),ptsZ=pts(posZ,0xffcc22,3),ptsR=pts(posR,0xff3333,3);
// GT-FREE DECODED FACES: line segments per triangle. 3 classes:
//   green = correct connectivity, red = wrong, dim grey = unscorable (slot unmapped)
const segG=[],segR=[],segU=[];
for(let i=0;i<D.dfaces.length;i+=3){const a=D.dfaces[i],b=D.dfaces[i+1],cc=D.dfaces[i+2];
  const ax=D.pts[a*3],ay=D.pts[a*3+1],az=D.pts[a*3+2],bx=D.pts[b*3],by=D.pts[b*3+1],bz=D.pts[b*3+2],
        cx=D.pts[cc*3],cy=D.pts[cc*3+1],cz=D.pts[cc*3+2];
  const fc=D.fclass[i/3];const seg=(fc===2)?segG:(fc===1)?segR:segU;
  seg.push(ax,ay,az,bx,by,bz, bx,by,bz,cx,cy,cz, cx,cy,cz,ax,ay,az);}
function lines(a,col,op){const b=new THREE.BufferGeometry();b.setAttribute('position',new THREE.Float32BufferAttribute(a,3));
  const l=new THREE.LineSegments(b,new THREE.LineBasicMaterial({color:col,transparent:true,opacity:op}));sc.add(l);return l;}
const facesG=lines(segG,0x33ff88,0.95),facesR=lines(segR,0xff4444,0.8),facesU=lines(segU,0x777777,0.35);
// frame
g.computeBoundingSphere();const bs=g.boundingSphere;_bsC.copy(bs.center);_bsR=bs.radius;
const _a=innerWidth/innerHeight,_h=bs.radius*1.2;camO.top=_h;camO.bottom=-_h;camO.left=-_h*_a;camO.right=_h*_a;
camO.near=0.1;camO.far=bs.radius*100;camO.updateProjectionMatrix();camP.near=0.1;camP.far=bs.radius*100;camP.updateProjectionMatrix();
const _p0=new THREE.Vector3(bs.center.x,bs.center.y-bs.radius*1.5,bs.center.z+bs.radius*1.5);
camO.position.copy(_p0);camP.position.copy(_p0);ctr.target.copy(bs.center);ctr.update();
document.getElementById('i').innerHTML=`<b>Intercepts: GT-FREE decoded FACES (first look)</b><br>
<span style="color:#fa3">Points AND triangles both decoded from the .00t ALONE (${D.prov}). DXF used for scoring/coloring ONLY — never fed to the decoder.</span><br>
GT surface (faint teal wire): ${D.nv} verts, ${D.nf} tris.<br>
Decoded pts ${D.npd}: <span style=color:#3f3>green match&lt;250mm</span> <span style=color:#fc2>yellow XY-ok</span> <span style=color:#f55>red miss</span> (${(100*D.nmatch/D.npd).toFixed(1)}% placed).<br>
<b>Decoded faces ${D.ntri}</b> (<span style=color:#3f8>green = correct connectivity</span> <span style=color:#f44>red = wrong</span> <span style=color:#999>grey = unscorable slot</span>): <b>${(100*D.ngood/D.nscor).toFixed(1)}%</b> GT-correct on the ${D.nscor} scorable tris. PARTIAL coverage (~149 rails); full mesh needs the exact-cover replay.<br>
<button id=bm>GT surface</button><button id=bp>decoded pts</button><button id=bf>decoded faces</button><button id=bu>unscorable faces</button><button id=bo>Ortho/Persp [O]</button><button id=bv>Plan [V]</button>`;
document.getElementById('bm').onclick=()=>{wire.visible=!wire.visible};
document.getElementById('bp').onclick=()=>{ptsG.visible=!ptsG.visible;ptsZ.visible=!ptsZ.visible;ptsR.visible=!ptsR.visible};
document.getElementById('bf').onclick=()=>{facesG.visible=!facesG.visible;facesR.visible=!facesR.visible};
document.getElementById('bu').onclick=()=>{facesU.visible=!facesU.visible};
facesU.visible=false;
function setCam(cn){if(cn===cam)return;const t=ctr.target.clone(),p=cam.position.clone();ctr.dispose();cam=cn;cam.position.copy(p);ctr=new OrbitControls(cam,r.domElement);ctr.target.copy(t);ctr.update();}
function planView(){cam.position.set(_bsC.x,_bsC.y,_bsC.z+_bsR*2.5);cam.up.set(0,1,0);ctr.target.copy(_bsC);ctr.update();}
document.getElementById('bo').onclick=()=>setCam(cam===camO?camP:camO);
document.getElementById('bv').onclick=planView;
addEventListener('keydown',e=>{const k=e.key.toLowerCase();if(k==='o')setCam(cam===camO?camP:camO);else if(k==='v')planView();});
addEventListener('resize',()=>{const _a=innerWidth/innerHeight;camO.left=-camO.top*_a;camO.right=camO.top*_a;camO.updateProjectionMatrix();camP.aspect=_a;camP.updateProjectionMatrix();r.setSize(innerWidth,innerHeight);});
(function loop(){requestAnimationFrame(loop);ctr.update();r.render(sc,cam);})();
</script></body></html>'''
open('../js/intercepts_faces.html', 'w').write(HTML.replace('__DATA__', json.dumps(data)))
print('wrote js/intercepts_faces.html  (%d decoded tris; %d/%d scorable GT-correct = %.1f%%; %d/%d pts placed)'
      % (data['ntri'], data['ngood'], data['nscor'],
         100*data['ngood']/data['nscor'], data['nmatch'], data['npd']))
