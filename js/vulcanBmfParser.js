/**
 * vulcanBmfParser.js — Maptek Vulcan .bmf/.bdf block model parser (TBMS2.0).
 *
 * JS port of the reference decoder ROSETTA/bmf.rs. A .bmf file is an
 * UNcompressed, 0x808-byte-paged container (NOT vulZ, unlike .00t/.dgd.isis):
 *
 *   0x800-byte file header ("TBMS2.0\0"); LE u64 primary page-table pointer @0x18
 *   pages of stride 0x808 = 8-byte header + 0x800 payload
 *   metadata pages (kind 00 02) carry a brace/`=` text object (dims, origin,
 *     orientation, bounds, schemas, variables)
 *   value pages hold each variable's column, addressed through one- or
 *     two-level page tables (kinds 01 01 / 02 01)
 *
 * Metadata text is ASCII; value-page numbers are little-endian. Vectors are
 * [x,y,z]; the rotation is a row-major 3x3 array. No dependencies.
 *
 * Reference (source of truth): ROSETTA/bmf.rs. Sibling: 00T_FORMAT.md.
 * @module vulcanBmfParser
 */

const FILE_HEADER_LEN = 0x800;
const PAGE_STRIDE = 0x808;
const PAGE_HEADER_LEN = 8;
const PAGE_PAYLOAD_LEN = 0x800;
const PAGE_TABLE_SLOTS = PAGE_PAYLOAD_LEN / 8;         // 256
const TWO_LEVEL_PAGE_TABLE_SLOTS = PAGE_TABLE_SLOTS * PAGE_TABLE_SLOTS;
const HEADER_PRIMARY_TABLE_POINTER = 0x18;

const NUMERIC_TYPES = new Set(['float', 'short', 'int', 'longlong', 'double']);
const NAMED_TYPES = new Set(['namedbyte', 'namedshort']);
const NUMERIC_VPP = { float: 512, short: 1024, int: 512, longlong: 256, double: 256 };
const NAMED_VPP = { namedbyte: 2048, namedshort: 1024 };
const EMPTY_LABELS = new Set(['air', 'delete', 'deleted', 'void', 'empty', 'null']);
const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

class BmfError extends Error {}

// ---- byte helpers ------------------------------------------------------------
const dv = u8 => new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
function le16(u8, o) { return dv(u8).getUint16(o, true); }
function le32(u8, o) { return dv(u8).getUint32(o, true); }
function le64(u8, o) { return Number(dv(u8).getBigUint64(o, true)); }

// ---- rotation (row-major 3x3) ------------------------------------------------
function matMul(a, b) {
  const out = [[0, 0, 0], [0, 0, 0], [0, 0, 0]];
  for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++)
    out[r][c] = a[r][0] * b[0][c] + a[r][1] * b[1][c] + a[r][2] * b[2][c];
  return out;
}
const rotZ = a => { const c = Math.cos(a), s = Math.sin(a); return [[c, -s, 0], [s, c, 0], [0, 0, 1]]; };
const rotX = a => { const c = Math.cos(a), s = Math.sin(a); return [[1, 0, 0], [0, c, -s], [0, s, c]]; };
const rotY = a => { const c = Math.cos(a), s = Math.sin(a); return [[c, 0, s], [0, 1, 0], [-s, 0, c]]; };
const deg2rad = d => d * Math.PI / 180;

/** bearing/dip/plunge (orientation[2],[0],[1]) -> row-major 3x3. */
function computeRotationMatrix(orientation) {
  return matMul(matMul(rotZ(deg2rad(90 - orientation[2])), rotX(deg2rad(orientation[0]))),
    rotY(deg2rad(orientation[1])));
}

// ---- metadata text object ----------------------------------------------------
function tokenize(text) {
  const tokens = [];
  let i = 0; const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '{') { tokens.push(['open']); i++; }
    else if (ch === '}') { tokens.push(['close']); i++; }
    else if (ch === '=') { tokens.push(['eq']); i++; }
    else if (ch === ',') { tokens.push(['comma']); i++; }
    else if (ch === '"') {
      i++; let buf = '';
      while (i < n) {
        const c = text[i];
        if (c === '"') { i++; break; }
        if (c === '\\') { i++; if (i < n) { buf += text[i]; i++; } }
        else { buf += c; i++; }
      }
      tokens.push(['val', buf]);
    } else if (/\s/.test(ch)) { i++; }
    else {
      let buf = ch; i++;
      while (i < n && !/\s/.test(text[i]) && !'{}=,'.includes(text[i])) { buf += text[i]; i++; }
      tokens.push(['val', buf]);
    }
  }
  return tokens;
}

class MetaObject {
  constructor() { this.map = new Map(); }
  get(k) { return this.map.get(k); }
  has(k) { return this.map.has(k); }
  keys() { return this.map.keys(); }
  entries() { return this.map.entries(); }
  string(k) { const v = this.map.get(k); return typeof v === 'string' ? v : null; }
  f64(k) { const v = this.string(k); if (v === null) return null; const f = parseFloat(v.trim()); return Number.isNaN(f) ? null : f; }
  usize(k) { const v = this.string(k); if (v === null) return null; const s = v.trim(); return /^-?\d+$/.test(s) ? parseInt(s, 10) : null; }
}

function parseObject(tokens, startPos) {
  let pos = startPos;
  const peek = () => tokens[pos];
  if (!peek() || peek()[0] !== 'open') throw new BmfError("expected '{'");
  pos++;
  const obj = new MetaObject();
  for (;;) {
    while (peek() && peek()[0] === 'comma') pos++;
    const p = peek();
    if (p && p[0] === 'close') { pos++; break; }
    if (!p || p[0] !== 'val') throw new BmfError('expected metadata key');
    const key = p[1]; pos++;
    if (!peek() || peek()[0] !== 'eq') throw new BmfError("expected '='");
    pos++;
    const vp = peek();
    let value;
    if (vp && vp[0] === 'open') { const r = parseObject(tokens, pos); value = r.node; pos = r.pos; }
    else if (vp && vp[0] === 'val') { value = vp[1]; pos++; }
    else throw new BmfError('expected metadata value');
    obj.map.set(key, value);
    while (peek() && peek()[0] === 'comma') pos++;
  }
  return { node: obj, pos };
}

const isMetadataRoot = o => o instanceof MetaObject &&
  (o.has('n_blocks') || (o.has('dim_x') && o.has('dim_y') && o.has('dim_z')));

function metadataRootScore(o) {
  if (!(o instanceof MetaObject)) return 0;
  let variables = 0, schemas = 0;
  for (const k of o.keys()) {
    if (k.startsWith('var_') || k.startsWith('special_')) variables++;
    else if (k.startsWith('schema_')) schemas++;
  }
  return variables * 10 + schemas * 3 + (o.has('n_blocks') ? 1 : 0) + (o.has('dim_x') ? 1 : 0);
}

function parseMetadataRoot(text) {
  const tokens = tokenize(text);
  let best = null, bestScore = 0;
  for (let idx = 0; idx < tokens.length; idx++) {
    if (tokens[idx][0] !== 'open') continue;
    let node;
    try { node = parseObject(tokens, idx).node; } catch { continue; }
    if (isMetadataRoot(node)) {
      const score = metadataRootScore(node);
      if (best === null || score > bestScore) { best = node; bestScore = score; }
    }
  }
  if (best === null) throw new BmfError('could not parse BMF metadata root');
  return best;
}

// ---- metadata page collection / candidates -----------------------------------
const DEC = new TextDecoder('latin1');

function collectMetadataPages(u8) {
  const pages = [];
  let offset = FILE_HEADER_LEN + PAGE_HEADER_LEN;
  let prev = null;
  while (offset + PAGE_STRIDE <= u8.length) {
    if (u8[offset] === 0x00 && u8[offset + 1] === 0x02) {
      let payloadLen = le16(u8, offset + 2);
      payloadLen = Math.min(Math.max(payloadLen, 1), PAGE_PAYLOAD_LEN);
      const text = DEC.decode(u8.subarray(offset + PAGE_HEADER_LEN, offset + PAGE_HEADER_LEN + payloadLen)).replace(/\0/g, '');
      pages.push({ text, offset, startsRoot: text.trimStart().startsWith('{'), contiguous: prev !== null && prev + PAGE_STRIDE === offset });
      prev = offset;
    }
    offset += PAGE_STRIDE;
  }
  return pages;
}

const isMetadataCandidate = t => t.includes('"n_blocks"') ||
  (t.includes('"dim_x"') && t.includes('"dim_y"') && t.includes('"dim_z"'));

class BraceScanner {
  constructor() { this.depth = 0; this.inString = false; this.escaped = false; }
  feed(text) {
    let closed = false;
    for (const ch of text) {
      if (this.inString) {
        if (this.escaped) this.escaped = false;
        else if (ch === '\\') this.escaped = true;
        else if (ch === '"') this.inString = false;
        continue;
      }
      if (ch === '"') this.inString = true;
      else if (ch === '{') this.depth++;
      else if (ch === '}') { this.depth = Math.max(0, this.depth - 1); if (this.depth === 0) closed = true; }
    }
    return closed;
  }
}

function extractMetadataCandidates(u8) {
  const pages = collectMetadataPages(u8);
  const candidates = [];
  const flush = run => {
    if (!run.length) return;
    const maxOff = run[run.length - 1].offset;
    const fwd = run.map(p => p.text).join('');
    if (fwd.trim()) candidates.push([fwd, maxOff]);
    if (run.length > 1) {
      const rev = run.slice().reverse().map(p => p.text).join('');
      if (rev.trim()) candidates.push([rev, maxOff]);
    }
  };
  let run = [];
  for (const p of pages) {
    if (p.contiguous) run.push(p);
    else { flush(run); run = [p]; }
  }
  flush(run);

  for (let i = 0; i < pages.length; i++) {
    const page = pages[i];
    if (!page.startsRoot) continue;
    let text = page.text, maxOff = page.offset;
    const scanner = new BraceScanner();
    scanner.feed(page.text);
    candidates.push([text, maxOff]);
    let pushed = true;
    for (let j = i + 1; j < pages.length; j++) {
      const cont = pages[j];
      if (cont.startsRoot) continue;
      text += cont.text; maxOff = Math.max(maxOff, cont.offset); pushed = false;
      if (scanner.feed(cont.text)) { candidates.push([text, maxOff]); pushed = true; }
    }
    if (!pushed) candidates.push([text, maxOff]);
  }

  const seen = new Set();
  const uniq = [];
  for (const [text, off] of candidates) {
    if (!isMetadataCandidate(text) || seen.has(text)) continue;
    seen.add(text); uniq.push([text, off]);
  }
  if (!uniq.length) throw new BmfError('BMF metadata pages were not found');
  return uniq;
}

function headerPrimaryTablePointer(u8) {
  if (HEADER_PRIMARY_TABLE_POINTER + 8 > u8.length) return null;
  const pointer = le64(u8, HEADER_PRIMARY_TABLE_POINTER);
  if (pointer % PAGE_STRIDE !== 0 || pointer < PAGE_STRIDE || pointer + PAGE_STRIDE > u8.length) return null;
  const k0 = u8[pointer], k1 = u8[pointer + 1];
  return ((k0 === 0x01 && k1 === 0x01) || (k0 === 0x02 && k1 === 0x01)) ? pointer : null;
}

function parseBmfMetadataRoot(u8) {
  const candidates = extractMetadataCandidates(u8);
  const pointer = headerPrimaryTablePointer(u8);
  let anchor = null, best = null, bestScore = 0;
  for (const [text, maxOff] of candidates) {
    let node;
    try { node = parseMetadataRoot(text); } catch { continue; }
    if (pointer !== null && maxOff < pointer) {
      const gap = pointer - maxOff;
      if (gap % PAGE_STRIDE === 0 && (anchor === null || gap < anchor.gap)) anchor = { gap, node };
    }
    const score = metadataRootScore(node);
    if (best === null || score > bestScore) { best = node; bestScore = score; }
  }
  if (anchor !== null) return anchor.node;
  if (best === null) throw new BmfError('could not parse BMF metadata root');
  return best;
}

// ---- metadata assembly -------------------------------------------------------
const vec3 = (o, kx, ky, kz) => [o.f64(kx) || 0, o.f64(ky) || 0, o.f64(kz) || 0];

function schemaFrom(node) {
  if (!(node instanceof MetaObject)) return null;
  return {
    name: node.string('description') || '',
    lower: vec3(node, 'lower_x', 'lower_y', 'lower_z'),
    upper: vec3(node, 'upper_x', 'upper_y', 'upper_z'),
    dims: [node.usize('dim_x') || 0, node.usize('dim_y') || 0, node.usize('dim_z') || 0],
    minSize: vec3(node, 'min_size_x', 'min_size_y', 'min_size_z'),
    maxSize: vec3(node, 'max_size_x', 'max_size_y', 'max_size_z'),
  };
}

function variableFrom(node) {
  if (!(node instanceof MetaObject)) return null;
  const strings = new Map();
  for (const [key, value] of node.entries()) {
    if (key.startsWith('string_') && typeof value === 'string') {
      const idx = parseInt(key.slice('string_'.length), 10);
      if (!Number.isNaN(idx)) strings.set(idx, value);
    }
  }
  const locStr = node.string('location');
  const location = locStr !== null && /^-?\d+$/.test(locStr.trim()) ? parseInt(locStr.trim(), 10) : 0;
  return {
    name: (node.string('name') || '').trim(),
    physicalType: (node.string('type') || '').trim().toLowerCase(),
    description: node.string('description') || '',
    location,
    default: node.string('default') || '',
    global: node.string('global') || '',
    strings,
    special: false,
  };
}

function metadataFromNode(node) {
  if (!(node instanceof MetaObject)) throw new BmfError('BMF metadata root is not an object');
  const dims = [node.usize('dim_x') || 0, node.usize('dim_y') || 0, node.usize('dim_z') || 0];
  const inferred = dims.includes(0) ? 0 : dims[0] * dims[1] * dims[2];
  const meta = {
    nBlocks: node.usize('n_blocks') !== null ? node.usize('n_blocks') : inferred,
    origin: vec3(node, 'origin_x', 'origin_y', 'origin_z'),
    orientation: vec3(node, 'orientation_1', 'orientation_2', 'orientation_3'),
    lower: vec3(node, 'lower_x', 'lower_y', 'lower_z'),
    upper: vec3(node, 'upper_x', 'upper_y', 'upper_z'),
    dims,
    isIrregular: (node.usize('is_irregular') || 0) !== 0,
    schemas: [],
    variables: [],
    rawTopLevel: new Map(),
  };
  for (const [key, value] of node.entries()) {
    if (typeof value === 'string') meta.rawTopLevel.set(key, value);
    if (key.startsWith('schema_')) { const s = schemaFrom(value); if (s) meta.schemas.push(s); }
    else if (key.startsWith('var_') || key.startsWith('special_')) {
      const v = variableFrom(value);
      if (v) { v.special = key.startsWith('special_'); meta.variables.push(v); }
    }
  }
  return meta;
}

function parseDefaultF64(v) {
  for (const c of [v.global.trim(), v.default.trim()]) {
    const f = parseFloat(c);
    if (!Number.isNaN(f) && /^[-+]?[\d.eE+]+$/.test(c)) return f;
  }
  return 0.0;
}
function parseDefaultCode(v) {
  const text = v.global.trim() === '' ? v.default.trim() : v.global.trim();
  if (/^\d+$/.test(text)) return parseInt(text, 10);
  for (const [code, label] of v.strings.entries()) if (label.toLowerCase() === text.toLowerCase()) return code;
  return 0;
}
const isEmptyBlockLabel = l => EMPTY_LABELS.has(l.trim().toLowerCase());

// bisect_left over sorted numbers
function partitionPoint(arr, value) {
  let lo = 0, hi = arr.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] < value) lo = mid + 1; else hi = mid; }
  return lo;
}

// ---- model -------------------------------------------------------------------
class BmfModel {
  constructor(input) {
    const u8 = input instanceof Uint8Array ? input : new Uint8Array(input);
    const magic = [0x54, 0x42, 0x4d, 0x53, 0x32, 0x2e, 0x30, 0x00]; // "TBMS2.0\0"
    if (u8.length < FILE_HEADER_LEN || !magic.every((m, i) => u8[i] === m))
      throw new BmfError('not a Vulcan TBMS2.0 block model');
    this.bytes = u8;
    this.metadata = metadataFromNode(parseBmfMetadataRoot(u8));
    this.rotation = computeRotationMatrix(this.metadata.orientation);
  }

  variable(name) { return this.metadata.variables.find(v => v.name === name) || null; }
  numericVariables() { return this.metadata.variables.filter(v => NUMERIC_TYPES.has(v.physicalType)); }
  unsupportedVariables() {
    return this.metadata.variables.filter(v => !NUMERIC_TYPES.has(v.physicalType) && !NAMED_TYPES.has(v.physicalType));
  }

  page(offset) {
    if (offset < PAGE_STRIDE || offset % PAGE_STRIDE !== 0) throw new BmfError(`BMF page offset ${offset} is not page-aligned`);
    if (offset + PAGE_STRIDE > this.bytes.length) throw new BmfError(`BMF page offset ${offset} is outside file`);
    return this.bytes.subarray(offset, offset + PAGE_STRIDE);
  }
  pagePayload(offset) { return this.page(offset).subarray(PAGE_HEADER_LEN, PAGE_HEADER_LEN + PAGE_PAYLOAD_LEN); }

  readU64Slot(payload, slot) {
    const start = slot * 8;
    if (start + 8 > payload.length) throw new BmfError(`BMF page table is missing slot ${slot}`);
    return le64(payload, start);
  }

  valuePageOffsets(tableOffset, first, last) {
    if (first > last) throw new BmfError(`invalid BMF value-page range ${first}..${last}`);
    const page = this.page(tableOffset);
    const kind0 = page[0], kind1 = page[1];
    const payload = page.subarray(PAGE_HEADER_LEN, PAGE_HEADER_LEN + PAGE_PAYLOAD_LEN);
    const offsets = [];
    if (kind0 === 0x01 && kind1 === 0x01) {
      if (last > PAGE_TABLE_SLOTS) throw new BmfError('BMF leaf page table slot out of range');
      for (let slot = first; slot < last; slot++) offsets.push(this.readU64Slot(payload, slot));
      return offsets;
    }
    if (kind0 === 0x02 && kind1 === 0x01) {
      if (last > TWO_LEVEL_PAGE_TABLE_SLOTS) throw new BmfError('BMF two-level page table slot out of range');
      if (first === last) return offsets;
      const firstChild = Math.floor(first / PAGE_TABLE_SLOTS);
      const lastChild = Math.floor((last - 1) / PAGE_TABLE_SLOTS);
      for (let childIndex = firstChild; childIndex <= lastChild; childIndex++) {
        const childPageStart = childIndex * PAGE_TABLE_SLOTS;
        const reqStart = Math.max(first, childPageStart) - childPageStart;
        const reqEnd = Math.min(last, childPageStart + PAGE_TABLE_SLOTS) - childPageStart;
        const childOffset = this.readU64Slot(payload, childIndex);
        if (childOffset === 0) { for (let k = reqStart; k < reqEnd; k++) offsets.push(0); continue; }
        const child = this.page(childOffset);
        if (!(child[0] === 0x01 && child[1] === 0x01)) throw new BmfError(`expected BMF leaf page table at offset ${childOffset}`);
        const childPayload = child.subarray(PAGE_HEADER_LEN, PAGE_HEADER_LEN + PAGE_PAYLOAD_LEN);
        for (let slot = reqStart; slot < reqEnd; slot++) offsets.push(this.readU64Slot(childPayload, slot));
      }
      return offsets;
    }
    throw new BmfError(`expected page table at offset ${tableOffset}`);
  }

  numericValues(name) { return this.numericValuesRange(name, 0, this.metadata.nBlocks); }

  numericValuesRange(name, start, end) {
    const v = this.variable(name);
    if (!v) throw new BmfError(`unknown block variable '${name}'`);
    if (!NUMERIC_TYPES.has(v.physicalType)) throw new BmfError(`variable '${name}' is not numeric (${v.physicalType})`);
    if (start > end || end > this.metadata.nBlocks) throw new BmfError(`variable '${name}' invalid range ${start}..${end}`);
    const requested = end - start;
    if (v.location === 0) return new Array(requested).fill(parseDefaultF64(v));
    const vpp = NUMERIC_VPP[v.physicalType];
    const firstPage = Math.floor(start / vpp);
    const lastPage = Math.ceil(end / vpp);
    const offsets = this.valuePageOffsets(v.location, firstPage, lastPage);
    const values = [];
    for (let rel = 0; rel < offsets.length; rel++) {
      const offset = offsets[rel];
      const pageIndex = firstPage + rel;
      const pageStart = pageIndex * vpp;
      const pageEnd = pageStart + vpp;
      const valueStart = Math.max(0, start - pageStart);
      const valueEnd = Math.min(end, pageEnd) - pageStart;
      const count = valueEnd - valueStart;
      if (offset === 0) { for (let k = 0; k < count; k++) values.push(parseDefaultF64(v)); continue; }
      const payload = this.pagePayload(offset);
      const view = dv(payload);
      for (let k = 0; k < count; k++) {
        const idx = valueStart + k;
        switch (v.physicalType) {
          case 'float': values.push(view.getFloat32(idx * 4, true)); break;
          case 'short': values.push(view.getInt16(idx * 2, true)); break;
          case 'int': values.push(view.getInt32(idx * 4, true)); break;
          case 'longlong': values.push(Number(view.getBigInt64(idx * 8, true))); break;
          case 'double': values.push(view.getFloat64(idx * 8, true)); break;
          default: break;
        }
      }
    }
    return values;
  }

  namedCodeValues(name) {
    const v = this.variable(name);
    if (!v) throw new BmfError(`unknown block variable '${name}'`);
    if (!NAMED_TYPES.has(v.physicalType)) throw new BmfError(`variable '${name}' is not named (${v.physicalType})`);
    if (v.location === 0) return new Array(this.metadata.nBlocks).fill(parseDefaultCode(v));
    const vpp = NAMED_VPP[v.physicalType];
    const requiredPages = Math.ceil(this.metadata.nBlocks / vpp);
    const offsets = this.valuePageOffsets(v.location, 0, requiredPages);
    const values = [];
    for (let pageIndex = 0; pageIndex < offsets.length; pageIndex++) {
      const offset = offsets[pageIndex];
      const pageStart = pageIndex * vpp;
      const count = Math.min(this.metadata.nBlocks - pageStart, vpp);
      if (offset === 0) { for (let k = 0; k < count; k++) values.push(parseDefaultCode(v)); continue; }
      const payload = this.pagePayload(offset);
      if (v.physicalType === 'namedbyte') { for (let k = 0; k < count; k++) values.push(payload[k]); }
      else { const view = dv(payload); for (let k = 0; k < count; k++) values.push(view.getUint16(k * 2, true)); }
    }
    return values;
  }

  emptyMarkerVariable() {
    const cands = this.metadata.variables.filter(v => NAMED_TYPES.has(v.physicalType)
      && [...v.strings.values()].some(isEmptyBlockLabel));
    if (!cands.length) return null;
    return cands.reduce((best, v) => {
      const rank = ['geology', 'rock', 'material'].includes(v.name.toLowerCase()) ? 1 : 0;
      const bestRank = ['geology', 'rock', 'material'].includes(best.name.toLowerCase()) ? 1 : 0;
      return rank > bestRank ? v : best;
    });
  }

  renderableBlockIndices() {
    const v = this.emptyMarkerVariable();
    if (!v) return Array.from({ length: this.metadata.nBlocks }, (_, i) => i);
    const emptyCodes = new Set([...v.strings.entries()].filter(([, l]) => isEmptyBlockLabel(l)).map(([c]) => c));
    if (!emptyCodes.size) return Array.from({ length: this.metadata.nBlocks }, (_, i) => i);
    const codes = this.namedCodeValues(v.name);
    const out = [];
    for (let i = 0; i < codes.length; i++) if (!emptyCodes.has(codes[i])) out.push(i);
    return out;
  }

  blockBounds() {
    const names = ['__lower_x', '__lower_y', '__lower_z', '__upper_x', '__upper_y', '__upper_z'];
    if (!names.every(n => this.variable(n))) {
      if (this.metadata.isIrregular) throw new BmfError('BMF is sub-blocked but missing explicit __lower/__upper bounds');
      return this.regularBlockBounds();
    }
    const cols = names.map(n => this.numericValues(n));
    const out = [];
    for (let i = 0; i < this.metadata.nBlocks; i++)
      out.push({ lower: [cols[0][i], cols[1][i], cols[2][i]], upper: [cols[3][i], cols[4][i], cols[5][i]] });
    return out;
  }

  regularBlockBounds() {
    const [dx, dy, dz] = this.metadata.dims;
    if (dx === 0 || dy === 0 || dz === 0) throw new BmfError('BMF has no block-bound variables or grid dimensions');
    if (dx * dy * dz !== this.metadata.nBlocks) throw new BmfError('BMF regular-grid dimensions disagree with nBlocks');
    const lo = this.metadata.lower, up = this.metadata.upper;
    const cell = [(up[0] - lo[0]) / dx, (up[1] - lo[1]) / dy, (up[2] - lo[2]) / dz];
    const out = [];
    for (let z = 0; z < dz; z++) for (let y = 0; y < dy; y++) for (let x = 0; x < dx; x++) {
      const lower = [lo[0] + x * cell[0], lo[1] + y * cell[1], lo[2] + z * cell[2]];
      out.push({ lower, upper: [lower[0] + cell[0], lower[1] + cell[1], lower[2] + cell[2]] });
    }
    return out;
  }

  localToWorld(local) {
    const r = this.rotation, o = this.metadata.origin;
    return [
      o[0] + r[0][0] * local[0] + r[0][1] * local[1] + r[0][2] * local[2],
      o[1] + r[1][0] * local[0] + r[1][1] * local[1] + r[1][2] * local[2],
      o[2] + r[2][0] * local[0] + r[2][1] * local[1] + r[2][2] * local[2],
    ];
  }

  hasVerifiedRotation() {
    const eps = 1e-6;
    return Math.abs(this.metadata.orientation[0]) < eps && Math.abs(this.metadata.orientation[1]) < eps;
  }
}

/** Parse a .bdf definition sidecar into [{ name, fields:Map }]. */
function parseBdf(text) {
  const sections = [];
  let current = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('*')) continue;
    if (line.startsWith('BEGIN$DEF')) current = { name: line.slice('BEGIN$DEF'.length).trim(), fields: new Map() };
    else if (line.startsWith('END$DEF')) { if (current) { sections.push(current); current = null; } }
    else if (current) {
      const eq = line.indexOf('=');
      if (eq >= 0) current.fields.set(line.slice(0, eq).trim(), line.slice(eq + 1).trim().replace(/^'|'$/g, ''));
      else current.fields.set(line, '');
    }
  }
  return sections;
}

function parseBmf(input) { return new BmfModel(input); }

export { BmfModel, parseBmf, parseBdf, computeRotationMatrix, BmfError };
