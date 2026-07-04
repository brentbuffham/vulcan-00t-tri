"""Instrumented v5b: classify EVERY break site (phase slip / value miss /
unlabeled-token / cascade), then annotated dumps. GT used for diagnosis only."""
import struct, json
import numpy as np
from scipy.spatial import cKDTree
from collections import Counter
oot=r'C:/Users/brent/Downloads/ac-653-221-intecepts.00t'
sp=r'C:\Users\brent\AppData\Local\Temp\claude\C--Users-brent-desktop-git-vulcan-00t-tri\6045a728-103e-40d9-818d-ffe48c95ac26\scratchpad'
d=open(oot,'rb').read()
def be(b): return struct.unpack('>d',bytes(b))[0]
def sane(v):
    a=abs(v); return (500<a<1000) or (50000<a<60000) or (160000<a<166000)
def band(v):
    x=abs(v)
    if 500<x<1000: return 2
    if 50000<x<60000: return 0
    if 160000<x<166000: return 1
    return -1
occ=[i for i in range(8326,len(d)-2) if d[i]==0xE0 and d[i+1]==0x03]
face_start=len(d)
for k in range(len(occ)-3):
    if occ[k+3]-occ[k]<90: face_start=occ[k]; break
def full_at(pos):
    if pos+8<=face_start and d[pos] in (0x40,0x41,0xC0,0xC1):
        v=be(d[pos:pos+8])
        if sane(v): return v
    return None
toks=[];pos=8350;lastT=None
while pos<face_start:
    b=d[pos]
    if b==0 and pos+6<=face_start and d[pos:pos+6]==b'\x00'*6:
        while pos<face_start and d[pos]==0: pos+=1
        continue
    if full_at(pos) is not None:
        toks.append(('F',d[pos:pos+8],lastT,None,pos)); lastT=None; pos+=8; continue
    if b>=0x20 and full_at(pos+1) is not None:
        toks.append(('Fe',d[pos+1:pos+9],lastT,None,pos)); lastT=None; pos+=10; continue
    if b<0x20:
        nb=(b&7)+1
        end=pos+1+nb
        for j in range(pos+1,min(end,face_start)):
            if full_at(j) is not None: end=j; break
        if end>face_start: end=face_start
        toks.append(('V',d[pos+1:end],lastT,b,pos)); lastT=None; pos=end; continue
    if 0xe0<=b<=0xff and pos+3<=face_start: lastT=None; pos+=3; continue
    if pos+2<=face_start: lastT=(d[pos],d[pos+1]); pos+=2; continue
    pos+=1
def tok_old():
    o=[];p=8350
    while p<face_start:
        b=d[p]
        if b==0 and p+6<=face_start and d[p:p+6]==b'\x00'*6:
            while p<face_start and d[p]==0: p+=1
            continue
        if b in (0x40,0x41,0xC0,0xC1) and p+8<=face_start and sane(be(d[p:p+8])):
            o.append(p); p+=8; continue
        if b<0x20 and p+1+(b&7)+1<=face_start:
            o.append(p); p+=1+(b&7)+1; continue
        if 0xe0<=b<=0xff and p+3<=face_start: p+=3; continue
        if b>=0x20 and p+2<=face_start: p+=2; continue
        p+=1
    return o
oldpos=tok_old()
L=json.load(open(sp+r'\commit_labels.json'))
lab_by_pos={oldpos[l['tok']]:l for l in L if l['tok']<len(oldpos)}
def k0_rule(T,nb):
    if T is not None:
        T1,T2=T
        if 0x21<=T1<=0x3F: return 2
        if 0x40<=T1<=0x5F: return 3
        if T1==0x20: return 3 if T2<0x60 else 2
    return {4:3,5:3,6:2}.get(nb,max(0,8-nb))
def strict_val(R,payload,T,a):
    nb=len(payload)
    if nb==0 or nb>8: return None
    def spl(k0,c=0):
        end=k0+nb
        if k0<0 or end>8: return None
        bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
        if c!=0:
            kk=k0-1
            if kk<0: return None
            nv=bb[kk]+c
            if not(0<=nv<=255): return None
            bb[kk]=nv
        return bytes(bb)
    k0r=k0_rule(T,nb)
    if k0r+nb>8: k0r=8-nb
    vb=spl(k0r)
    if vb is not None and band(be(vb))==a: return vb
    for c in (-1,1,-2,2,-3,3,-4,4):
        vb=spl(k0r,c)
        if vb is not None and band(be(vb))==a: return vb
    return None
segs=[]; cur=[]
for gi,t in enumerate(toks):
    if t[0] in ('F','Fe'):
        if cur: segs.append(('V',cur)); cur=[]
        segs.append(('F',[(gi,t)]))
    else: cur.append((gi,t))
if cur: segs.append(('V',cur))
regs=[bytearray(d[8326:8334]),bytearray(d[8334:8342]),bytearray(d[8342:8350])]
ph=0
pts=[(be(regs[0]),be(regs[1]),be(regs[2]))]; meta=[-1]
tokinfo={}
for kind,ts in segs:
    if kind=='F':
        gi,t=ts[0]; v=be(t[1]); a=band(v)
        if a>=0:
            regs[a][:]=t[1]; ph=(a+1)%3
            tokinfo[gi]=('F',a,v)
        continue
    best=None
    for off in range(3):
        rr=[bytearray(r) for r in regs]
        rec=[]; viol=0
        phx=(ph+off)%3
        for gi,t in ts:
            payload=t[1]
            if len(payload)==0: continue
            a=phx
            vb=strict_val(bytes(rr[a]),payload,t[2],a)
            if vb is not None: rr[a][:]=vb; rec.append((gi,a,be(vb)))
            else: viol+=1; rec.append((gi,a,None))
            if a==2: rec.append(('EMIT',(be(rr[0]),be(rr[1]),be(rr[2])),gi))
            phx=(phx+1)%3
        key=(viol,off!=0)
        if best is None or key<best[0]: best=(key,off,rr,rec,phx)
    _,off,rr,rec,phx=best
    for r in rec:
        if r[0]=='EMIT': pts.append(r[1]); meta.append(r[2])
        else: tokinfo[r[0]]=('V',r[1],r[2])
    for a in range(3): regs[a][:]=rr[a]
    ph=phx
P=np.array(pts)
G=np.loadtxt(sp+r'\intercepts_gt.csv',delimiter=',')
Gu=np.unique(G,axis=0)
dist,_=cKDTree(Gu).query(P)
good=dist<0.002
print(f"{len(P)} pts, good {good.sum()} ({good.mean()*100:.1f}%)")
breaks=[i for i in range(1,len(P)) if good[i-1] and not good[i]]
print(f"breaks: {len(breaks)}")
cls=Counter(); dumps={}
for bidx in breaks:
    z_bad=meta[bidx]; z_prev=meta[bidx-1]
    if z_bad<0: cls['full_emit']+=1; continue
    lo = z_prev+1 if z_prev>=0 else max(0,z_bad-9)
    first=None
    for gi in range(lo,z_bad+1):
        t=toks[gi]
        info=tokinfo.get(gi)
        if t[0]!='V' or info is None: continue
        l=lab_by_pos.get(t[4])
        if l is None:
            first=('unlabeled_token',gi); break
        aph=info[1]; vv=info[2]
        if l['axis']!=aph: first=('phase_slip',gi); break
        if l.get('fb'):
            fv=be(bytes.fromhex(l['fb']))
            if vv is None or abs(vv-fv)>1e-3:
                first=('value_miss',gi); break
    if first is None: cls['unexplained']+=1; continue
    cls[first[0]]+=1
    dumps.setdefault(first[0],[]).append((bidx,first[1]))
print()
print("break classes:",dict(cls.most_common()))
def dump_site(gi0):
    out=[]
    for gi in range(max(0,gi0-3),min(len(toks),gi0+4)):
        t=toks[gi]
        l=lab_by_pos.get(t[4])
        info=tokinfo.get(gi)
        if l:
            lab="ax%d %s/%s"%(l['axis'],l['role'],l['flag'])
            if l.get('fb'): lab+=" ->%.3f"%be(bytes.fromhex(l['fb']))
        else: lab='NO-LABEL'
        if info and info[0]=='V':
            act="ph%d ->%.3f"%(info[1],info[2]) if info[2] is not None else "ph%d VIOL"%info[1]
        elif info:
            act="FULL b%d %.3f"%(info[1],info[2])
        else: act='-'
        mark='>>' if gi==gi0 else '  '
        if t[0]=='V':
            Ts='%02x%02x'%t[2] if t[2] else '----'
            out.append("   %s tok%d @%d V p=%02x T=%s pay=%-14s | %s | %s"%(mark,gi,t[4],t[3],Ts,bytes(t[1]).hex(),act,lab))
        else:
            out.append("   %s tok%d @%d %s %.3f | %s | %s"%(mark,gi,t[4],t[0],be(t[1]),act,lab))
    return "\n".join(out)
for c,sites in dumps.items():
    print()
    print("=== class %s (%d breaks) — first 3 sites ==="%(c,len(sites)))
    for bidx,gi in sites[:3]:
        print(" break at emit#%d, token %d, filepos %d:"%(bidx,gi,toks[gi][4]))
        print(dump_site(gi))

# ---- subclassify value_miss: cascade victim vs genuine rule failure ----
print()
print("---- value_miss subclassification ----")
sub=Counter(); genuine=[]
for bidx,gi in dumps.get('value_miss',[]):
    t=toks[gi]; l=lab_by_pos[t[4]]
    fv=be(bytes.fromhex(l['fb']))
    ref=bytes.fromhex(l['ref'])       # label's own pre-commit register = true prev
    a=l['axis']
    vb=strict_val(ref,t[1],t[2],a)
    if vb is not None and abs(be(vb)-fv)<=1e-3:
        sub['cascade_victim']+=1      # rule fine; upstream poisoned register
    else:
        # genuine: is truth reachable at another k0 on true prev?
        nb=len(t[1]); hit=None
        for k0 in range(0,8-nb+1):
            end=k0+nb
            cand=bytes(ref[:k0])+bytes(t[1])+bytes(ref[end:])
            if abs(be(cand)-fv)<=1e-3: hit=k0; break
        if hit is not None:
            sub['genuine_altk0=%d'%hit]+=1
            genuine.append((gi,t,l,hit))
        else:
            sub['genuine_other']+=1
            genuine.append((gi,t,l,None))
print("subclasses:",dict(sub.most_common()))
print()
print("genuine failures (T1,T2,p,nb,payload[0], k0r vs true k0):")
for gi,t,l,hit in genuine[:20]:
    nb=len(t[1]); k0r=k0_rule(t[2],nb)
    print("  tok%d T=(%s) p=%02x nb=%d pay0=%02x  k0r=%d true_k0=%s flag=%s"%(
        gi,'%02x,%02x'%t[2] if t[2] else '--,--',t[3],nb,t[1][0],k0r,hit,l['flag']))

print()
print("---- genuine failures: label matches + verified ----")
mstat=Counter()
for gi,t,l,hit in genuine:
    key=('matches' if l['matches'] else 'NO-matches', l['verified'], l['flag'])
    mstat[key]+=1
for k,v in mstat.most_common(): print("  ",k,v)
print()
print("matches-nonempty genuine failures detail:")
shown=0
for gi,t,l,hit in genuine:
    if not l['matches'] or shown>=12: continue
    shown+=1
    nb=len(t[1])
    print("  tok%d nb=%d T=(%s) matches=%s ref=%s fb=%s pay=%s"%(
        gi,nb,'%02x,%02x'%t[2] if t[2] else '--',l['matches'],l['ref'][:8],l['fb'][:8],bytes(t[1]).hex()))

print()
print("---- wide mechanism search on NO-matches genuine failures ----")
# rebuild true label-stream register history per axis (fb sequence in tok order)
hist={0:[],1:[],2:[]}
lab_sorted=sorted([l for l in L if l.get('fb')],key=lambda l:l['tok'])
fulls_old={}
# old-token FULL positions: map old index -> bytes
oldidx_full={}
p_=8350; oi=0
# easier: walk oldpos; a FULL old-token starts with 0x40/41/C0/C1
for oi,po in enumerate(oldpos):
    b=d[po]
    if b in (0x40,0x41,0xC0,0xC1): oldidx_full[oi]=d[po:po+8]
TOLv=1e-3
mech=Counter(); un=[]
gset={}
for gi,t,l,hit in genuine:
    if not l['matches']: gset[l['tok']]=(gi,t,l)
prev=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev+1,i):
        if j in oldidx_full:
            fbF=oldidx_full[j]; hist[band(be(fbF))].append(bytes(fbF))
    prev=i
    a=l['axis']; fb=bytes.fromhex(l['fb']); fv=be(fb)
    if i in gset:
        gi,t,_=gset[i]
        payload=t[1]; nb=len(payload)
        found=None
        refs=[('prev%d'%(k+1),hist[a][-(k+1)]) for k in range(min(8,len(hist[a])))]
        refs+= [('xax%d_last'%aa,hist[aa][-1]) for aa in (0,1,2) if aa!=a and hist[aa]]
        # 1) splice any ref, any k0, carry -8..8 at k0-1
        for rn,R in refs:
            for k0 in range(0,8-nb+1):
                end=k0+nb
                base=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
                for c in range(-8,9):
                    bb=bytearray(base)
                    if c!=0:
                        kk=k0-1
                        if kk<0: continue
                        nv=bb[kk]+c
                        if not(0<=nv<=255): continue
                        bb[kk]=nv
                    if abs(be(bytes(bb))-fv)<=TOLv:
                        found='%s_k0=%d_c=%+d'%(rn,k0,c) if (c or rn!='prev1') else 'prev1_k0=%d'%k0
                        break
                if found: break
            if found: break
        # 2) r-strip 1..2 leading payload bytes, splice rest on prev1
        if not found:
            R=hist[a][-1] if hist[a] else None
            if R is not None:
                for r in (1,2):
                    if nb-r<1: continue
                    pl=payload[r:]
                    for k0 in range(0,8-(nb-r)+1):
                        end=k0+len(pl)
                        bb=bytes(R[:k0])+bytes(pl)+bytes(R[end:])
                        if abs(be(bb)-fv)<=TOLv: found='strip%d_k0=%d'%(r,k0); break
                    if found: break
        # 3) T-literal: T bytes + payload compose the double (tok58 style)
        if not found and t[2] is not None:
            T1,T2=t[2]
            # try [40/41][T1][T2][...payload...] style: hi from band, T at [2,4)
            for hb in ((0x40,),(0x41,),(0xc0,),(0xc1,)):
                pass
            # generic: does fb contain T1T2 contiguously?
            fbb=fb
            if bytes([T1,T2]) in fbb: found='T_literal_in_value'
        if not found:
            # 4) pure GT-only (no byte path) — count separately
            found=None
        mech[found or 'UNSOLVED']+=1
        if found is None and len(un)<10:
            un.append((gi,l['tok'],nb,'%02x%02x'%t[2] if t[2] else '----',bytes(payload).hex(),l['ref'],l['fb'],l['flag']))
    hist[a].append(fb)
for k,v in mech.most_common(): print("  %s: %d"%(k,v))
print()
print("UNSOLVED samples:")
for u in un: print("  gi%d oldtok%d nb=%d T=%s pay=%s flag=%s"%(u[0],u[1],u[2],u[3],u[4],u[7]))
print("    ref",un[0][5] if un else '', " fb",un[0][6] if un else '')

print()
print("---- carry c vs token byte fields ----")
# redo mechanism search but capture (c, T1, T2, p, nb, payload[0]) pairs
hist2={0:[],1:[],2:[]}
pairs=[]
prev=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev+1,i):
        if j in oldidx_full:
            fbF=oldidx_full[j]; hist2[band(be(fbF))].append(bytes(fbF))
    prev=i
    a=l['axis']; fb=bytes.fromhex(l['fb']); fv=be(fb)
    if i in gset:
        gi,t,_=gset[i]
        payload=t[1]; nb=len(payload)
        if hist2[a]:
            R=hist2[a][-1]
            for c in range(-8,9):
                if c==0: continue
                k0=3; end=k0+nb
                if end>8: continue
                bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
                nv=bb[2]+c
                if not(0<=nv<=255): continue
                bb[2]=nv
                if abs(be(bytes(bb))-fv)<=TOLv:
                    T1,T2=t[2] if t[2] else (-1,-1)
                    pairs.append((c,T1,T2,t[3],nb,payload[0]))
                    break
    hist2[a].append(fb)
print("carry events with T:", len(pairs))
print(" c vs T2>>3:")
tt=Counter((c,T2>>3 if T2>=0 else -1) for c,T1,T2,p,nb,p0 in pairs)
for k,v in sorted(tt.items()): print("   c=%+d T2hi=%d : %d"%(k[0],k[1],v))
print(" c vs T1&0x1F:")
tt=Counter((c,T1&0x1f if T1>=0 else -1) for c,T1,T2,p,nb,p0 in pairs)
for k,v in sorted(tt.items())[:30]: print("   c=%+d T1lo5=%d : %d"%(k[0],k[1],v))

print()
print("---- c vs p-hi and payload[0] ----")
tt=Counter((c,p>>3) for c,T1,T2,p,nb,p0 in pairs)
print(" c vs p>>3:")
for k,v in sorted(tt.items()): print("   c=%+d phi=%d : %d"%(k[0],k[1],v))
print(" c vs payload[0]>>4:")
tt=Counter((c,p0>>4) for c,T1,T2,p,nb,p0 in pairs)
for k,v in sorted(tt.items()): print("   c=%+d p0hi=%d : %d"%(k[0],k[1],v))

print()
print("---- combined rule R3: {(k0r,c0)} U {(3,c=+-1..+-8)} pick min |v-prev| ----")
hist3={0:None,1:None,2:None}
res=Counter()
prev=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev+1,i):
        if j in oldidx_full:
            fbF=oldidx_full[j]; hist3[band(be(fbF))]=bytes(fbF)
    prev=i
    a=l['axis']; fb=bytes.fromhex(l['fb']); fv=be(fb)
    t=None
    # map old tok -> new token by position
    po=oldpos[l['tok']] if l['tok']<len(oldpos) else None
    tt_=[x for x in toks if x[0]=='V' and x[4]==po]
    if tt_: t=tt_[0]
    if t is not None and l['role']=='val' and hist3[a] is not None:
        payload=t[1]; nb=len(payload)
        if 1<=nb<=8:
            R=hist3[a]; pv=be(R)
            k0r=k0_rule(t[2],nb)
            if k0r+nb>8: k0r=8-nb
            cands=[]
            def add(k0,c):
                end=k0+nb
                if k0<0 or end>8: return
                bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
                if c!=0:
                    kk=k0-1
                    if kk<0: return
                    nv=bb[kk]+c
                    if not(0<=nv<=255): return
                    bb[kk]=nv
                v=be(bytes(bb))
                if band(v)==a: cands.append((abs(v-pv),v))
            add(k0r,0)
            if 3+nb<=8 or nb<=5:
                for c in (-1,1,-2,2,-3,3,-4,4,-5,5,-6,6,-7,7,-8,8):
                    add(3,c)
            if cands:
                v=min(cands)[1]
                cls_='plain' if l['matches'] else 'event'
                res[(cls_, abs(v-fv)<=1e-3)]+=1
    hist3[a]=fb
print(res)
pt=res[('plain',True)]+res[('plain',False)]
ev=res[('event',True)]+res[('event',False)]
if pt: print("plain: %d/%d = %.2f%%"%(res[('plain',True)],pt,res[('plain',True)]/pt*100))
if ev: print("event: %d/%d = %.2f%%"%(res[('event',True)],ev,res[('event',True)]/ev*100))

print()
print("---- re-mine placement vs T fields (r=0 only, unique) ----")
from collections import defaultdict
tab=defaultdict(Counter)
tabp=defaultdict(Counter)
for l in L:
    if l['role']!='val' or not l['matches'] or l['T1']<0: continue
    nb=l['nb']
    r0=[(end) for r,end in l['matches'] if r==0]
    if len(set(r0))!=1 or len(l['matches'])!=len(r0): continue
    end=r0[0]; k0=end-nb
    T1c = 'T20' if l['T1']==0x20 else ('T21-3F' if l['T1']<=0x3f else 'T40+')
    tab[(T1c,nb)][(k0,end)]+=1
    tabp[(T1c,nb,l['T2']&0x08, (l['T2']>>4)&1)][(k0,end)]+=1
print("by (T1class, nb):")
for k in sorted(tab):
    print("  %s nb=%d: %s"%(k[0],k[1],dict(tab[k].most_common(4))))
print()
print("split rows by T2 bit3 / bit4:")
for k in sorted(tabp):
    v=tabp[k]
    if len(v)>1:
        print("  %s nb=%d T2b3=%d T2b4=%d: %s"%(k[0],k[1],k[2]//8,k[3],dict(v.most_common(3))))

print()
print("---- guarded hybrid: reconsider (3,c) only when plain delta > TH(axis) ----")
UNIT={0:8.0,1:32.0,2:0.125}
def hybrid_val(R,payload,T,a,zon=True):
    nb=len(payload)
    if nb==0 or nb>8: return None
    def spl(k0,c=0):
        end=k0+nb
        if k0<0 or end>8: return None
        bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
        if c!=0:
            kk=k0-1
            if kk<0: return None
            nv=bb[kk]+c
            if not(0<=nv<=255): return None
            bb[kk]=nv
        return bytes(bb)
    k0r=k0_rule(T,nb)
    if k0r+nb>8: k0r=8-nb
    pv=be(R)
    vb0=spl(k0r)
    v0=be(vb0) if vb0 is not None else None
    ok0 = v0 is not None and band(v0)==a
    if ok0 and abs(v0-pv)<=UNIT[a]/2: return vb0
    # event reconsideration
    best=None
    if a!=2 or zon:
        for c in range(-8,9):
            if c==0: continue
            vb=spl(3,c)
            if vb is None: continue
            v=be(vb)
            if band(v)!=a: continue
            dv=abs(v-pv)
            if best is None or dv<best[0]: best=(dv,vb)
    if ok0:
        if best is not None and best[0]<abs(v0-pv): return best[1]
        return vb0
    if best is not None: return best[1]
    # out-of-band fallback chain (original R2)
    for c in (-1,1,-2,2,-3,3,-4,4):
        vb=spl(k0r,c)
        if vb is not None and band(be(vb))==a: return vb
    return None
for zon in (True,False):
    hist4={0:None,1:None,2:None}
    res=Counter()
    prev=-1
    for l in lab_sorted:
        i=l['tok']
        for j in range(prev+1,i):
            if j in oldidx_full:
                fbF=oldidx_full[j]; hist4[band(be(fbF))]=bytes(fbF)
        prev=i
        a=l['axis']; fb=bytes.fromhex(l['fb']); fv=be(fb)
        po=oldpos[l['tok']] if l['tok']<len(oldpos) else None
        tt_=[x for x in toks if x[0]=='V' and x[4]==po]
        t=tt_[0] if tt_ else None
        if t is not None and l['role']=='val' and hist4[a] is not None:
            payload=t[1]; nb=len(payload)
            if 1<=nb<=8:
                vb=hybrid_val(hist4[a],payload,t[2],a,zon)
                if vb is not None:
                    cls_='plain' if l['matches'] else 'event'
                    res[(cls_,abs(be(vb)-fv)<=1e-3)]+=1
        hist4[a]=fb
    pt=res[('plain',True)]+res[('plain',False)]
    ev=res[('event',True)]+res[('event',False)]
    print(" zon=%s plain %d/%d=%.2f%%  event %d/%d=%.2f%%"%(zon,
        res[('plain',True)],pt,res[('plain',True)]/pt*100,
        res[('event',True)],ev,res[('event',True)]/ev*100))

print()
print("---- ADD-model test on event tokens: fb == ref + signext(payload)<<shift ? ----")
def u64(b): return int.from_bytes(b,'big')
addhit=Counter(); addex=[]
hist5={0:None,1:None,2:None}
prev=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev+1,i):
        if j in oldidx_full:
            fbF=oldidx_full[j]; hist5[band(be(fbF))]=bytes(fbF)
    prev=i
    a=l['axis']; fb=bytes.fromhex(l['fb']); fv=be(fb)
    if i in gset:
        gi,t,_=gset[i]
        payload=t[1]; nb=len(payload)
        R=hist5[a]
        if R is not None and 1<=nb<=8:
            pu=int.from_bytes(payload,'big')
            found=None
            for sgn in (1,-1):
                pv_=pu if sgn>0 else pu-(1<<(8*nb))   # unsigned vs two's complement
                for end in (8,7,6):
                    sh=8*(8-end)
                    cand=u64(R)+pv_*(1<<sh)
                    if 0<=cand<(1<<64):
                        v=be(cand.to_bytes(8,'big'))
                        if abs(v-fv)<=1e-3:
                            found='add_end%d_%s'%(end,'2c' if sgn<0 else 'u')
                            break
                if found: break
            addhit[found or 'no']+=1
            if found and len(addex)<6:
                addex.append((gi,nb,found,be(R),fv))
    hist5[a]=fb
print(dict(addhit.most_common()))
for e in addex: print("  gi%d nb=%d %s  prev=%.4f -> %.4f"%e)

print()
print("---- event carry vs ADJACENT context (Fe trailing, neighbor T2/p, hi-T1) ----")
# rebuild events with their global token index and c
hist6={0:None,1:None,2:None}
events=[]  # (gi, c)
prev=-1
for l in lab_sorted:
    i=l['tok']
    for j in range(prev+1,i):
        if j in oldidx_full:
            fbF=oldidx_full[j]; hist6[band(be(fbF))]=bytes(fbF)
    prev=i
    a=l['axis']; fb=bytes.fromhex(l['fb']); fv=be(fb)
    if i in gset:
        gi,t,_=gset[i]
        payload=t[1]; nb=len(payload)
        R=hist6[a]
        if R is not None and 3+nb<=8+1:
            for c in range(-8,9):
                if c==0: continue
                k0=3; end=k0+nb
                if end>8: continue
                bb=bytearray(R[:k0])+bytearray(payload)+bytearray(R[end:])
                nv=bb[2]+c
                if not(0<=nv<=255): continue
                bb[2]=nv
                if abs(be(bytes(bb))-fv)<=1e-3:
                    events.append((gi,c,bb[2])); break
    hist6[a]=fb
print("events located:",len(events))
# Fe trailing byte: need Fe positions + trailing byte value
fe_trail={}
for gi,t in enumerate(toks):
    if t[0]=='Fe':
        tp=t[4]+9   # trailing byte position (esc at t[4], full 8, trail at +9)
        fe_trail[gi]=d[tp]
cors=Counter()
det=[]
for gi,c,b2new in events:
    # nearest Fe within +-6 tokens
    near=[(abs(g-gi),g) for g in fe_trail if abs(g-gi)<=6]
    ftb=fe_trail[min(near)[1]] if near else None
    tprev=toks[gi-1] if gi>0 else None
    tnext=toks[gi+1] if gi+1<len(toks) else None
    T2n = tnext[2][1] if (tnext and tnext[0]=='V' and tnext[2]) else None
    T2p = tprev[2][1] if (tprev and tprev[0]=='V' and tprev[2]) else None
    det.append((c,b2new,ftb,T2n,T2p))
# does Fe trailing byte equal new byte2? or encode c?
eq=sum(1 for c,b2,f,_,_ in det if f is not None and f==b2)
have=sum(1 for c,b2,f,_,_ in det if f is not None)
print("Fe-trailing == new byte2: %d/%d"%(eq,have))
# c vs Fe trailing low bits
tt=Counter((c,f&0x0f) for c,b2,f,_,_ in det if f is not None)
print("c vs FeTrail&0x0f (top):",tt.most_common(10))
# c vs next token T2>>3
tt=Counter((c,t2>>3) for c,b2,f,t2,_ in det if t2 is not None)
print("c vs nextT2>>3 (top):",tt.most_common(10))
# c vs prev token T2>>3
tt=Counter((c,t2>>3) for c,b2,f,_,t2 in det if t2 is not None)
print("c vs prevT2>>3 (top):",tt.most_common(10))
# does the EVENT token's own T2 hi5 == new byte2 low5? or c+8?
own=Counter()
for gi,c,b2new in events:
    t=toks[gi]
    if t[0]=='V' and t[2]:
        T2=t[2][1]
        own[('T2hi5==c+8',(T2>>3)==(c+8))]+=1
        own[('T2hi5==b2lo5',(T2>>3)==(b2new&0x1f))]+=1
print("own-token checks:",dict(own))

print()
print("---- is the event's new byte2 literally the T2 byte? ----")
hit=Counter()
for gi,c,b2new in events:
    t=toks[gi]
    if t[0]=='V' and t[2]:
        T1,T2=t[2]
        hit['T2==b2new',T2==b2new]+=1
        hit['T1==b2new',T1==b2new]+=1
print(dict(hit))

print()
print("---- event leading bytes from NEXT same-axis FULL/Fe lookahead? ----")
# for each event: find next F/Fe token of same axis in the NEW token stream
res2=Counter(); dists=[]
hist7={0:None,1:None,2:None}
prev=-1
ev_fb={}
for l in lab_sorted:
    i=l['tok']
    prev=i
    if i in gset:
        gi,t,_=gset[i]
        ev_fb[gi]=(l['axis'],bytes.fromhex(l['fb']))
for gi,c,b2new in events:
    a,fb=ev_fb[gi]
    nxt=None
    for gj in range(gi+1,min(gi+80,len(toks))):
        t=toks[gj]
        if t[0] in ('F','Fe') and band(be(t[1]))==a:
            nxt=(gj,bytes(t[1])); break
    if nxt is None: res2['noFULL']+=1; continue
    gj,F=nxt
    dists.append(gj-gi)
    res2['hi3_match',F[:3]==fb[:3]]+=1
    res2['hi2_match',F[:2]==fb[:2]]+=1
    if F[:3]!=fb[:3]:
        # off by how much at byte2?
        res2['b2diff_%+d'%(fb[2]-F[2])]+=1
print(dict(res2.most_common()))
import statistics
if dists: print("lookahead distance tokens: median %d, max %d"%(statistics.median(dists),max(dists)))

print()
print("---- c vs T2hi5 at token offsets -4..+4 (mutual-information sweep) ----")
import math
def mi(pairs):
    n=len(pairs)
    if n<30: return 0.0
    from collections import Counter as C
    jx=C(); jy=C(); jj=C()
    for x,y in pairs: jx[x]+=1; jy[y]+=1; jj[(x,y)]+=1
    s=0.0
    for (x,y),c_ in jj.items():
        px=jx[x]/n; py=jy[y]/n; pxy=c_/n
        s+=pxy*math.log(pxy/(px*py)+1e-12)
    return s
for off in range(-4,5):
    if off==0: continue
    pairs=[]
    for gi,c,b2new in events:
        gj=gi+off
        if 0<=gj<len(toks):
            t=toks[gj]
            if t[0]=='V' and t[2] is not None:
                pairs.append((c,t[2][1]>>3))
    print("  offset %+d: n=%d MI=%.3f nats"%(off,len(pairs),mi(pairs)))
# baseline MI between c and a random field (own payload[1] hi):
pairs=[(c,toks[gi][1][1]>>4) for gi,c,b2 in events if len(toks[gi][1])>1]
print("  baseline (own pay[1]hi): n=%d MI=%.3f"%(len(pairs),mi(pairs)))
