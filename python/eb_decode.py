#!/usr/bin/env python3
"""STATEFUL EdgeBreaker-style decoder (prototype) running the topology traversal
in lockstep with the coord stream.

Model (boundary-growth): maintain an active boundary loop (doubly-linked list) with
a gate edge (a,b). Per topology record:
  C  (0xE0): new vertex -> pull next COORD GROUP; triangle (a,b,vnew); insert vnew.
  R/L/E/S  : connect gate to an existing boundary vertex (no coord pull).
Each record's payload + opcode is reported. The decoder is INSTRUMENTED: it tracks
payload-size-by-opcode, boundary size, and exactly where/why the traversal breaks.

This is a scaffold: the opcode MAP and the per-op boundary surgery are the tunable
unknowns. Run it to see how far a given hypothesis gets and where it fails."""
import sys, struct
from collections import Counter, deque
oot=sys.argv[1]
TOPO=int(sys.argv[2]) if len(sys.argv)>2 else 25_300_000
LIMIT=int(sys.argv[3]) if len(sys.argv)>3 else 2_000_000
d=open(oot,'rb').read(); geo_end=struct.unpack('<15i',d[0:60])[11]
TAG=(0x20,0x40,0x60,0x80,0xA0,0xC0,0xE0)
def is_sep(b): return (b&7)==7 and b>=7

# ---- opcode iterator over topology records ----
def topo_records(start,end):
    pos=start; cur=None
    while pos<end:
        b=d[pos]
        if b<=0x06:
            nb=b+1; pl=d[pos+1:pos+1+nb]; rec=(cur,nb,pl,pos); pos+=1+nb; cur=None
            yield rec
        elif is_sep(b): pos+=1
        elif (b&0xE0) in TAG: cur=b; pos+=1
        else: pos+=1

def opcode(tag):
    if tag is None: return 'N'
    hi=tag&0xF0
    if hi==0xE0: return 'C'
    if hi==0x20: return 'R'
    if hi==0x40: return 'L'
    if hi==0xF0: return 'E'
    if hi==0xC0: return 'S'
    return 'X'  # other -> unknown

# ---- payload-size-by-opcode diagnostic ----
sz=Counter(); opc=Counter()
n=0
for (tag,nb,pl,pos) in topo_records(TOPO,geo_end):
    op=opcode(tag); opc[op]+=1; sz[(op,nb)]+=1; n+=1
    if n>=LIMIT: break
print(f'sampled {n:,} topology records')
print('opcode counts:', opc.most_common())
print('payload nb by opcode (top):')
for op in ['C','R','L','E','S','N','X']:
    items=sorted(((k[1],v) for k,v in sz.items() if k[0]==op), key=lambda t:-t[1])[:5]
    if items: print(f'  {op}: '+', '.join(f'nb{nb}:{v}' for nb,v in items))

# ---- boundary-growth traversal (instrumented) ----
# Linked list arrays: each boundary node has nxt/prv and a vertex id.
nxt={}; prv={}; vtx={}; free=0
def newnode(v):
    global free
    i=free; free+=1; vtx[i]=v; return i
def insert_after(a,node):
    b=nxt[a]; nxt[a]=node; prv[node]=a; nxt[node]=b; prv[b]=node

faces=[]; nverts=0; coord_pulls=0
# seed: vertex 0 plus first two from initial — EB needs an initial triangle.
# We don't know the seed yet; start the boundary as a triangle of the first 3 C verts.
gate=None; boundary_loops=[]; broke=None; t=0
seed=[]
records=topo_records(TOPO,geo_end)
for (tag,nb,pl,pos) in records:
    op=opcode(tag); t+=1
    if op=='C':
        v=nverts; nverts+=1; coord_pulls+=1
        if gate is None:
            seed.append(v)
            if len(seed)==3:
                a=newnode(seed[0]); b=newnode(seed[1]); c=newnode(seed[2])
                nxt[a]=b;prv[a]=c;nxt[b]=c;prv[b]=a;nxt[c]=a;prv[c]=b
                gate=a; faces.append(tuple(seed))
            continue
        a=gate; b=nxt[gate]
        node=newnode(v); insert_after(a,node)
        faces.append((vtx[a],vtx[b],v)); gate=node  # advance gate to (vnew,b)
    else:
        if gate is None: continue
        a=gate; b=nxt[gate]; c=nxt[b]; p=prv[a]
        if op=='R':       # close right: triangle (a,b,c); remove b
            if c==a: broke=('R-degenerate',t,pos); break
            faces.append((vtx[a],vtx[b],vtx[c]))
            nxt[a]=c; prv[c]=a; # gate stays (a,c)
        elif op=='L':     # close left: triangle (p,a,b); remove a
            if p==b: broke=('L-degenerate',t,pos); break
            faces.append((vtx[p],vtx[a],vtx[b]))
            nxt[p]=b; prv[b]=p; gate=p
        elif op=='E':     # end: triangle (a,b,c) closes loop
            faces.append((vtx[a],vtx[b],vtx[c]))
            gate=None  # loop closed; need stack to resume (not modeled yet)
        elif op=='S':     # split (not modeled) -> treat as R for now
            faces.append((vtx[a],vtx[b],vtx[c])); nxt[a]=c; prv[c]=a
        else:  # 'N' or 'X'
            # unknown: try R-like
            if c==a: broke=('X-degenerate',t,pos); break
            faces.append((vtx[a],vtx[b],vtx[c])); nxt[a]=c; prv[c]=a
    if t>=LIMIT: break

print(f'\ntraversal: processed {t:,} records, built {len(faces):,} faces, '
      f'{nverts:,} vertices ({coord_pulls:,} coord pulls)')
print('break:', broke if broke else 'reached limit / end cleanly')
print(f'GT: triangles=3,232,402  verts=1,212,272')
