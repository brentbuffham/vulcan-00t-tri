/**
 * Vulcan .00t Triangulation Parser
 * Extracts vertices, face indices, and metadata from Maptek Vulcan .00t binary files.
 * 
 * Author: Brent Buffham / blastingapps.com + Claude (reverse-engineering collaboration)
 * 
 * ENCODING SUMMARY:
 *   - File: header (60B) → page chain → "Created External" + "Variant" → data stream → attributes → padding
 *   - Coordinates: delta-compressed truncated big-endian IEEE 754 doubles
 *     - Count byte (0x00–0x07): read count+1 data bytes
 *     - FULL value: first data byte is 0x40/0x41/0xC0/0xC1 → MSB bytes + zero padding
 *     - DELTA value: keep byte[0] from previous, insert new bytes, trailing from prev (old) or zeros (new)
 *     - Escape prefix: new-format files may have 0xFC/0xFE/0xFF before FULL values
 *     - Signed integer delta: fallback for large DELTA values in new-format files
 *   - Separator bytes: any byte where (b & 0x07) === 0x07 AND b >= 0x07 → skip 1
 *   - Tag pairs: all other bytes >= 0x08 → skip 2 (metadata/topology/vertex assignments)
 *   - Vertex assignments: C0/80/60/A0/20 tags with hi_nib>0 assign coord to vertex slot
 *   - Face section: EdgeBreaker topology with 40/C0 class tags
 *
 * @module oot-parser
 */

function isSeparator(b) { return (b & 0x07) === 0x07 && b >= 0x07; }

function readBEDouble(bytes) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  for (let i = 0; i < 8; i++) view.setUint8(i, bytes[i] || 0);
  return view.getFloat64(0, false);
}

function findBytes(data, needle, start = 0) {
  outer:
  for (let i = start; i <= data.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (data[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export function parseOOT(arrayBuffer) {
  const data = new Uint8Array(arrayBuffer);
  const warnings = [];
  const isSep = isSeparator;
  const readBE64 = readBEDouble;

  if (data.length < 64) return { vertices:[], faces:[], coordValues:[], faceVertexIndices:[], header:{}, metadata:{}, warnings:['File too small'] };
  const magic = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3];
  if ((magic >>> 0) !== 0xEAFBA78A) warnings.push('Bad magic');

  const header = { magic: `0x${(magic>>>0).toString(16).toUpperCase()}`, signature: String.fromCharCode(data[4],data[5],data[6],data[7]) };

  // Find Variant
  const vNeedle = [0x56,0x61,0x72,0x69,0x61,0x6E,0x74];
  const vi = findBytes(data, vNeedle);
  if (vi < 0) return { vertices:[], faces:[], coordValues:[], faceVertexIndices:[], header, metadata:{}, warnings:['No Variant marker'] };

  const variantLen = data[vi - 1];
  const ds = vi + variantLen;
  const isNewFormat = variantLen > 8;

  // Find anchor
  let anchor = -1;
  for (let i = ds; i < ds + 20 && i + 2 < data.length; i++) {
    if (data[i] === 0x43 && data[i+1] === 0xE0 && data[i+2] === 0x0E) { anchor = i; break; }
  }
  if (anchor < 0) return { vertices:[], faces:[], coordValues:[], faceVertexIndices:[], header, metadata:{}, warnings:['No anchor'] };

  const nVertsHeader = data[anchor + 7];
  const nFacesHeader = data[anchor + 14];
  header.vertexCount = nVertsHeader;
  header.faceCount = nFacesHeader;

  // Find coord_start
  let coordStart = -1;
  for (let off = 15; off < 25; off++) {
    const pos = anchor + off;
    if (pos + 2 < data.length && data[pos] === 0xE0 && data[pos + 2] === 0x14) { coordStart = pos + 3; break; }
  }
  if (coordStart < 0) {
    for (let off = 15; off < 25; off++) {
      const pos = anchor + off;
      if (pos < data.length && data[pos] <= 0x06) { coordStart = pos; break; }
    }
  }
  if (coordStart < 0) coordStart = anchor + 18;

  // Find boundaries
  const shadedNeedle = [0x53,0x48,0x41,0x44,0x45,0x44];
  let shadedPos = findBytes(data, shadedNeedle, ds);
  if (shadedPos < 0) shadedPos = data.length;

  let faceMarker = -1;
  for (let i = shadedPos - 2; i > coordStart; i--) {
    if (data[i] === 0x20 && data[i + 1] === 0x00) { faceMarker = i; break; }
  }
  const coordEnd = faceMarker > 0 ? faceMarker : shadedPos;

  // Parse coord elements
  const coordRegion = data.slice(coordStart, coordEnd);
  const prev = new Uint8Array(8);
  let pos = 0;
  const elements = [];
  const coordValues = [];

  function readUint64BE(bytes) {
    let hi = 0, lo = 0;
    for (let i = 0; i < 4; i++) hi = (hi * 256) + (bytes[i] || 0);
    for (let i = 4; i < 8; i++) lo = (lo * 256) + (bytes[i] || 0);
    return [hi, lo];
  }

  function addDeltaToUint64(prevHiLo, deltaBytes, nBytes) {
    let prevBig = BigInt(prevHiLo[0]) * BigInt(0x100000000) + BigInt(prevHiLo[1]);
    let dVal = 0;
    for (let i = 0; i < nBytes; i++) dVal = dVal * 256 + deltaBytes[i];
    let deltaBig = BigInt(dVal);
    if (deltaBytes[0] >= 0x80) deltaBig -= (BigInt(1) << BigInt(nBytes * 8));
    let resultBig = (prevBig + deltaBig) & BigInt("0xFFFFFFFFFFFFFFFF");
    const result = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) { result[i] = Number(resultBig & BigInt(0xFF)); resultBig >>= BigInt(8); }
    return result;
  }

  while (pos < coordRegion.length) {
    const b = coordRegion[pos];
    if (b <= 0x06 || (isNewFormat && b === 0x07)) {
      let nb = b + 1;
      const rawNb = nb;
      if (pos + 1 + nb > coordRegion.length) break;
      let stored = Array.from(coordRegion.slice(pos + 1, pos + 1 + nb));

      if (isNewFormat && stored.length > 1) {
        let stripped = stored.slice();
        while (stripped.length > 1 && (stripped[0] >= 0xFC || stripped[0] === 0x00)) {
          const candidate = stripped.slice(1);
          if ([0x40,0x41,0xC0,0xC1].includes(candidate[0])) { stored = candidate; nb = stored.length; break; }
          else if (candidate[0] >= 0xFC || candidate[0] === 0x00) { stripped = candidate; continue; }
          else break;
        }
      }

      let r, kind;
      if ([0x40,0x41,0xC0,0xC1].includes(stored[0])) {
        r = new Uint8Array(8);
        for (let i = 0; i < nb && i < 8; i++) r[i] = stored[i];
        kind = 'FULL';
      } else {
        r = new Uint8Array(8);
        r[0] = prev[0];
        for (let i = 0; i < nb && i + 1 < 8; i++) r[i + 1] = stored[i];
        if (!isNewFormat) { for (let i = nb + 1; i < 8; i++) r[i] = prev[i]; }
        kind = 'DELTA';
        if (isNewFormat) {
          const testVal = readBE64(r);
          if (Math.abs(testVal) > 10000) {
            r = addDeltaToUint64(readUint64BE(prev), stored.slice(0, rawNb), rawNb);
            kind = 'IDELTA';
          }
        }
      }

      const r8 = new Uint8Array(8);
      for (let i = 0; i < 8; i++) r8[i] = r[i] || 0;
      const val = readBE64(r8);
      for (let i = 0; i < 8; i++) prev[i] = r8[i];
      elements.push({ etype:'COORD', value:val, kind, nBytes:nb });
      coordValues.push(val);
      pos += 1 + rawNb;
    } else if (isSep(b)) {
      elements.push({ etype:'SEP', sepByte:b });
      pos += 1;
    } else if (pos + 1 < coordRegion.length) {
      const b2 = coordRegion[pos + 1];
      const cls = {0x20:'20',0x40:'40',0x60:'60',0x80:'80',0xA0:'A0',0xC0:'C0',0xE0:'E0'}[b & 0xE0] || '??';
      elements.push({ etype:'TAG', cls, byte2:b2, loNib:b2&0xF, hiNib:(b2>>4)&0xF });
      pos += 2;
    } else break;
  }

  // Group, assign axes, extract assignments, trim, build vertices
  const groups = [];
  let cg = null;
  for (const el of elements) {
    if (el.etype === 'COORD') { if (cg) groups.push(cg); cg = { value:el.value, kind:el.kind, tags:[], seps:[], axis:-1, c0:[]}; }
    else if (cg) { if (el.etype === 'TAG') cg.tags.push(el); else if (el.etype === 'SEP') cg.seps.push(el.sepByte); }
  }
  if (cg) groups.push(cg);

  // Axis assignment
  if (groups.length >= 3) {
    groups[0].axis=0; groups[1].axis=1; groups[2].axis=2;
    const cur = [groups[0].value, groups[1].value, groups[2].value];
    for (let i = 3; i < groups.length; i++) {
      let best=0, bd=Math.abs(groups[i].value-cur[0]);
      for (let a=1;a<3;a++){const d=Math.abs(groups[i].value-cur[a]);if(d<bd){bd=d;best=a;}}
      groups[i].axis=best; cur[best]=groups[i].value;
    }
  } else { for (let i=0;i<groups.length;i++) groups[i].axis=i; }

  // Extract assignments
  const aCls = new Set(['C0','80','60','A0','20']);
  for (const g of groups) for (const t of g.tags) if (aCls.has(t.cls)&&t.hiNib>0) g.c0.push([t.hiNib,t.loNib]);

  // Trim
  let tg = groups;
  if (groups.length >= 3 && groups[0].value >= 0 && groups[1].value >= 0 && groups[2].value >= 0) {
    for (let i=3;i<groups.length;i++) if (groups[i].value<0){tg=groups.slice(0,i);break;}
  }

  // Build vertices
  const vertices = [];
  if (tg.length >= 3) {
    const base=[tg[0].value,tg[1].value,tg[2].value];
    const zv=[]; for(const g of tg)if(g.axis===2&&Math.abs(g.value)>1&&!zv.includes(g.value))zv.push(g.value);
    const bz=zv[0]||base[2], az=zv[1]||bz;
    const mv=nFacesHeader>0?Math.max(nFacesHeader+2,3):100;
    const ss={};
    vertices.push([...base]);
    const run=[...base];
    for(let i=3;i<tg.length;i++){
      const g=tg[i],ax=g.axis;if(ax<0||ax>2)continue;if(vertices.length>=mv)break;
      run[ax]=g.value;
      if(g.c0.length>0){for(const[s,lo]of g.c0){if(vertices.length>=mv)break;if(!ss[s])ss[s]={};ss[s][ax]=g.value;
        const vx=ss[s][0]!==undefined?ss[s][0]:base[0],vy=ss[s][1]!==undefined?ss[s][1]:base[1];
        let vz=ss[s][2]!==undefined?ss[s][2]:base[2];if(lo===0x7)vz=bz;else if(lo===0xF)vz=az;
        vertices.push([vx,vy,vz]);}}
      else vertices.push([...run]);
    }
  }

  const metadata = { coordCount: coordValues.length, dataStart: `0x${coordStart.toString(16)}` };

  return { vertices, faces: [], coordValues, faceVertexIndices: [], header, metadata, warnings };
}

export function toOBJ(result) {
  const lines = ['# Vulcan .00t export', `# Vertices: ${result.vertices.length}`, `# Faces: ${result.faces.length}`, ''];
  for (const [x,y,z] of result.vertices) lines.push(`v ${x} ${y} ${z}`);
  lines.push('');
  for (const [v0,v1,v2] of result.faces) lines.push(`f ${v0+1} ${v1+1} ${v2+1}`);
  return lines.join('\n');
}

export function toCSV(result) {
  let vertexCSV = 'Index,X,Y,Z\n';
  result.vertices.forEach((v,i) => { vertexCSV += `${i},${v[0]},${v[1]},${v[2]}\n`; });
  let faceCSV = 'Index,V0,V1,V2\n';
  result.faces.forEach((f,i) => { faceCSV += `${i},${f[0]},${f[1]},${f[2]}\n`; });
  return { vertexCSV, faceCSV };
}
