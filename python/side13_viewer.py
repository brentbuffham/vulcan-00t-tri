"""Viewer v2: separate face classes by BOTH connectivity AND vertex placement,
so 'correct topology drawn to a mis-decoded vertex' (the spikes) is not
confused with a true on-surface win.
  class 3 GREEN  = correct connectivity AND all 3 verts placed <0.25m (true win)
  class 2 ORANGE = correct connectivity but >=1 vert NOT decoded (the spikes)
  class 1 RED    = wrong connectivity (scorable)
  class 0 GREY   = unscorable (slot unmapped)
Coords = GT-free P_v11; DXF/map11 = scoring/coloring ONLY.
"""
import json, pickle
import numpy as np
from scipy.spatial import cKDTree

map11, _ = pickle.load(open('map11.pkl', 'rb'))
P = np.load('P_v11_intercepts.npy')
V = np.loadtxt('intercepts_gt.csv', delimiter=',')
Fg = np.load('faces_gt.npy')
df = json.load(open('decoded_faces_ext.json'))
tris = df['tris']; good = np.array(df['good']).astype(bool); scor = np.array(df['scor']).astype(bool)

c = V.mean(0)
tree = cKDTree(V); dd, _ = tree.query(P); placed = dd < 0.25
Pc = (P - c).round(3); Vc = (V - c).round(3)

fclass = []
for t, g, s in zip(tris, good, scor):
    allplaced = all(placed[i] for i in t if 0 <= i < len(placed))
    if s and g and allplaced: fclass.append(3)
    elif s and g:             fclass.append(2)   # correct topo, spike
    elif s:                   fclass.append(1)   # wrong
    else:                     fclass.append(0)   # unscorable
fclass = np.array(fclass)
faceset = {tuple(sorted(f)): i for i, f in enumerate(Fg)}
hit = set()
for t, g in zip(tris, good):
    if g:
        k = tuple(sorted(map11[s] for s in t))
        if k in faceset: hit.add(faceset[k])
ndistinct = len(hit)
n3 = int((fclass == 3).sum()); n2 = int((fclass == 2).sum())
n1 = int((fclass == 1).sum()); n0 = int((fclass == 0).sum())
dfaces = [x for t in tris for x in t]
cat = np.where(placed, 1, 0)

data = dict(verts=Vc.flatten().tolist(), faces=[int(x) for f in Fg for x in f],
            pts=Pc.flatten().tolist(), cat=cat.astype(int).tolist(),
            dfaces=dfaces, fclass=fclass.astype(int).tolist(),
            nv=len(V), nf=len(Fg), npd=len(P), nplaced=int(placed.sum()),
            ntri=len(tris), ndistinct=ndistinct, n3=n3, n2=n2, n1=n1, n0=n0)

HTML = r'''<!DOCTYPE html><html><head><meta charset=utf-8><title>Intercepts: GT-free decoded FACES v2</title>
<style>body{margin:0;background:#111;color:#ddd;font:13px sans-serif;overflow:hidden}
#i{position:absolute;top:8px;left:8px;background:#000b;padding:10px;border-radius:6px;line-height:1.6;max-width:46em}
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
const g=new THREE.BufferGeometry();g.setAttribute('position',new THREE.Float32BufferAttribute(D.verts,3));g.setIndex(D.faces);g.computeVertexNormals();
const wire=new THREE.LineSegments(new THREE.WireframeGeometry(g),new THREE.LineBasicMaterial({color:0x2a6650,transparent:true,opacity:0.22}));sc.add(wire);
// decoded points (green placed / red not)
const posP=[],posN=[];
for(let k=0;k<D.cat.length;k++){const x=D.pts[k*3],y=D.pts[k*3+1],z=D.pts[k*3+2];(D.cat[k]===1?posP:posN).push(x,y,z);}
function pts(a,col,s){const b=new THREE.BufferGeometry();b.setAttribute('position',new THREE.Float32BufferAttribute(a,3));const p=new THREE.Points(b,new THREE.PointsMaterial({color:col,size:s,sizeAttenuation:false}));sc.add(p);return p;}
const ptsP=pts(posP,0x33ff55,3.5),ptsN=pts(posN,0xff3333,3);
// decoded faces, 4 classes
const seg=[[],[],[],[]];
for(let i=0;i<D.dfaces.length;i+=3){const a=D.dfaces[i],b=D.dfaces[i+1],cc=D.dfaces[i+2];
  const A=[D.pts[a*3],D.pts[a*3+1],D.pts[a*3+2]],B=[D.pts[b*3],D.pts[b*3+1],D.pts[b*3+2]],C=[D.pts[cc*3],D.pts[cc*3+1],D.pts[cc*3+2]];
  const s=seg[D.fclass[i/3]];s.push(...A,...B,...B,...C,...C,...A);}
function lines(a,col,op){const b=new THREE.BufferGeometry();b.setAttribute('position',new THREE.Float32BufferAttribute(a,3));const l=new THREE.LineSegments(b,new THREE.LineBasicMaterial({color:col,transparent:true,opacity:op}));sc.add(l);return l;}
const fGood=lines(seg[3],0x33ff88,0.95),fSpike=lines(seg[2],0xffaa22,0.55),fWrong=lines(seg[1],0xff4444,0.6),fUns=lines(seg[0],0x777777,0.3);
fUns.visible=false;
g.computeBoundingSphere();const bs=g.boundingSphere;_bsC.copy(bs.center);_bsR=bs.radius;
const _a=innerWidth/innerHeight,_h=bs.radius*1.2;camO.top=_h;camO.bottom=-_h;camO.left=-_h*_a;camO.right=_h*_a;
camO.near=0.1;camO.far=bs.radius*100;camO.updateProjectionMatrix();camP.near=0.1;camP.far=bs.radius*100;camP.updateProjectionMatrix();
const _p0=new THREE.Vector3(bs.center.x,bs.center.y-bs.radius*1.5,bs.center.z+bs.radius*1.5);camO.position.copy(_p0);camP.position.copy(_p0);ctr.target.copy(bs.center);ctr.update();
document.getElementById('i').innerHTML=`<b>Intercepts: GT-free decoded FACES v2 (connectivity vs vertex placement)</b><br>
<span style="color:#fa3">Faces + points decoded from the .00t ALONE. DXF used for scoring/coloring ONLY.</span><br>
Coord decode places ${D.nplaced}/${D.npd} verts (${(100*D.nplaced/D.npd).toFixed(0)}%) &lt;250mm — the rest are the SPIKES.<br>
Decoded faces ${D.ntri}: <span style="color:#3f8">■ ${D.n3} fully correct (topology + all verts placed)</span> · <span style="color:#fa2">■ ${D.n2} correct topology, ≥1 vert NOT decoded (spikes)</span> · <span style="color:#f44">■ ${D.n1} wrong topology</span> · <span style="color:#999">${D.n0} unscorable</span>.<br>
<b>${D.ndistinct} distinct GT faces correct = ${(100*D.ndistinct/D.nf).toFixed(1)}% of the ${D.nf}-face mesh decoded.</b> The spikes are a COORD problem (verts), not a faces problem.<br>
<button id=b3>fully-correct faces</button><button id=b2>spikes (topo-ok)</button><button id=b1>wrong faces</button><button id=bp>points</button><button id=bm>GT surface</button><button id=bo>Ortho/Persp</button><button id=bv>Plan [V]</button>`;
document.getElementById('b3').onclick=()=>{fGood.visible=!fGood.visible};
document.getElementById('b2').onclick=()=>{fSpike.visible=!fSpike.visible};
document.getElementById('b1').onclick=()=>{fWrong.visible=!fWrong.visible};
document.getElementById('bp').onclick=()=>{ptsP.visible=!ptsP.visible;ptsN.visible=!ptsN.visible};
document.getElementById('bm').onclick=()=>{wire.visible=!wire.visible};
function setCam(cn){if(cn===cam)return;const t=ctr.target.clone(),p=cam.position.clone();ctr.dispose();cam=cn;cam.position.copy(p);ctr=new OrbitControls(cam,r.domElement);ctr.target.copy(t);ctr.update();}
function planView(){cam.position.set(_bsC.x,_bsC.y,_bsC.z+_bsR*2.5);cam.up.set(0,1,0);ctr.target.copy(_bsC);ctr.update();}
document.getElementById('bo').onclick=()=>setCam(cam===camO?camP:camO);
document.getElementById('bv').onclick=planView;
addEventListener('keydown',e=>{const k=e.key.toLowerCase();if(k==='v')planView();else if(k==='o')setCam(cam===camO?camP:camO);});
addEventListener('resize',()=>{const _a=innerWidth/innerHeight;camO.left=-camO.top*_a;camO.right=camO.top*_a;camO.updateProjectionMatrix();camP.aspect=_a;camP.updateProjectionMatrix();r.setSize(innerWidth,innerHeight);});
(function loop(){requestAnimationFrame(loop);ctr.update();r.render(sc,cam);})();
</script></body></html>'''
open('../js/intercepts_faces.html', 'w', encoding='utf-8').write(HTML.replace('__DATA__', json.dumps(data)))
print('wrote js/intercepts_faces.html')
print('  fully correct (topo+verts): %d' % n3)
print('  correct topo, vert spike:   %d' % n2)
print('  wrong topo:                 %d' % n1)
print('  distinct GT faces: %d = %.1f%% of mesh; verts placed %d/%d'
      % (ndistinct, 100*ndistinct/len(Fg), int(placed.sum()), len(P)))
