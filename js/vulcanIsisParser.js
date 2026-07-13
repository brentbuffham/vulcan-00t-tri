/**
 * vulcanIsisParser.js — Maptek Vulcan .dgd.isis / .dgd.isix design database
 * parser. JS port of the reference decoder ROSETTA/isis.rs.
 *
 * A .dgd.isis file is a vulZ FastLZ-compressed container (the SAME container as
 * .00t — it reuses decodeVulz from vulcan00TParser.js). Decompressed, it is a
 * stream of 117-byte fixed records:
 *
 *   type 01 = layer header   type 03 = POLY   type 04 = TEXT
 *   type 05 = coordinate      type 06 = text line
 *   type 09 = layer save      type 0a = 3DTEXT
 *
 * Coordinate records carry big-endian f64 X/Y/Z + space-padded ASCII name and
 * segment fields. The .isix sidecar is a page-indexed table of layer pointers.
 *
 * NOTE: vulcan00TParser's decodeVulz does not currently return the auxiliary
 * (PNG-gallery) stream, so the embedded-gallery layer-name scan falls back to
 * the main data image here (matching isis.rs's `aux.is_empty()` fallback).
 * Layer names still resolve from type-01/09 records. The Rust reference reads
 * aux; port that into decodeVulz if the gallery names are needed.
 *
 * Reference (source of truth): ROSETTA/isis.rs.
 * @module vulcanIsisParser
 */

import { decodeVulz, MAGIC } from './vulcan00TParser.js';

const DGD_COORD_RECORD_LEN = 117;
const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];

class IsisError extends Error {}

const dv = u8 => new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

// ---- container ---------------------------------------------------------------
function decompressIfVulz(u8) {
  const isVulz = MAGIC.every((m, i) => u8[i] === m);
  if (isVulz) {
    let out;
    try { out = decodeVulz(u8); } catch (e) { throw new IsisError(`vulZ decompression failed: ${e.message}`); }
    return { data: out.data, aux: out.aux || new Uint8Array(0) };
  }
  return { data: u8, aux: new Uint8Array(0) };
}

// ---- byte helpers ------------------------------------------------------------
function tryReadXyz(data, offset) {
  if (offset + 24 > data.length) return null;
  const view = dv(data);
  const x = view.getFloat64(offset, false);
  const y = view.getFloat64(offset + 8, false);
  const z = view.getFloat64(offset + 16, false);
  if ([x, y, z].every(Number.isFinite)) return [x, y, z];
  return null;
}
const isPlausibleCoord = (x, y, z) => Math.abs(x) < 1e8 && Math.abs(y) < 1e8 && Math.abs(z) < 50000;

function decodeName(bs) {
  let out = '';
  for (const b of bs) {
    if (b === 0) break;
    out += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '?';
  }
  return out.replace(/\s+$/, '');
}
function decodeAsciiName(bs) {
  let out = '';
  for (const b of bs) {
    if (b === 0) break;
    if (!(b >= 0x20 && b < 0x7f)) return null;
    out += String.fromCharCode(b);
  }
  const name = out.trim();
  return name || null;
}
const isDigit = b => b >= 0x30 && b <= 0x39;

function parseSegField(bs) {
  if (!bs.every(b => b === 0x20 || isDigit(b)) || !bs.some(isDigit)) return null;
  let digits = '';
  for (const b of bs) if (isDigit(b)) digits += String.fromCharCode(b);
  const n = parseInt(digits, 10);
  return Number.isNaN(n) ? null : Math.min(n, 255);
}

function findBytes(hay, needle, from = 0, to = hay.length) {
  outer: for (let i = from; i <= to - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}
function rfind(hay, needle, from, to) {
  outer: for (let i = to - needle.length; i >= from; i--) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function partitionPoint(arr, value) {
  let lo = 0, hi = arr.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (arr[mid] < value) lo = mid + 1; else hi = mid; }
  return lo;
}

// ---- coordinate points -------------------------------------------------------
function inferGeometryKind(data, coordOffset) {
  const start = Math.max(0, coordOffset - 2048);
  const window = data.subarray(start, coordOffset);
  let best = [-1, 'unknown'];
  for (const [tokStr, kind] of [['POLYPOINT', 'point'], ['POLYLINE', 'line'], ['LINE', 'line']]) {
    const token = Uint8Array.from(tokStr, c => c.charCodeAt(0));
    const pos = rfind(window, token, 0, window.length);
    if (pos > best[0]) best = [pos, kind];
  }
  return best[1];
}

function scanPoints(data) {
  const MIN_SCAN = 0x1000, COORD_OFF = 5, NAME_OFF = 37, SECOND_OFF = 77, NAME_LEN = 40;
  const out = [];
  const limit = data.length - DGD_COORD_RECORD_LEN;
  let i = MIN_SCAN;
  while (i <= limit) {
    if (data[i] === 0x05 && data[i + 1] === 0x20) {
      const seg = parseSegField(data.subarray(i + 2, i + 5));
      const xyz = seg !== null ? tryReadXyz(data, i + COORD_OFF) : null;
      if (seg !== null && xyz && isPlausibleCoord(xyz[0], xyz[1], xyz[2])) {
        out.push({
          offset: i,
          name: decodeName(data.subarray(i + NAME_OFF, i + NAME_OFF + NAME_LEN)),
          secondaryName: decodeName(data.subarray(i + SECOND_OFF, i + SECOND_OFF + NAME_LEN)),
          layerName: null,
          segType: seg,
          geometryKind: inferGeometryKind(data, i),
          closed: false,
          colorIndex: null,
          x: xyz[0], y: xyz[1], z: xyz[2],
        });
        i += DGD_COORD_RECORD_LEN;
        continue;
      }
    }
    i += 1;
  }
  return out;
}

// ---- layer headers / saves ---------------------------------------------------
function isLayerHeaderStamp(stamp) {
  const upper = stamp.toUpperCase();
  const hasMonth = MONTHS.some(m => upper.includes(m));
  return stamp.includes(':') && (upper.includes('DGEDIT') || hasMonth);
}

function scanLayerHeaders(data) {
  const NAME_LEN = 40, STAMP_LEN = 40, NAME_OFF = 2;
  const STAMP_OFF = NAME_OFF + NAME_LEN, TAIL_OFF = STAMP_OFF + STAMP_LEN;
  const headers = [];
  let i = 0;
  while (i + DGD_COORD_RECORD_LEN <= data.length) {
    if (data[i] !== 0x01 || ![0x20, 0x44, 0x24].includes(data[i + 1])) { i++; continue; }
    const name = decodeAsciiName(data.subarray(i + NAME_OFF, i + NAME_OFF + NAME_LEN));
    const stamp = decodeAsciiName(data.subarray(i + STAMP_OFF, i + STAMP_OFF + STAMP_LEN));
    let tailOk = true;
    for (let k = i + TAIL_OFF; k < i + DGD_COORD_RECORD_LEN; k++) {
      const b = data[k];
      if (!(b === 0 || b === 0x20 || isDigit(b))) { tailOk = false; break; }
    }
    if (name === null || stamp === null || !isLayerHeaderStamp(stamp) || !tailOk) { i++; continue; }
    headers.push({ offset: i, flag: data[i + 1], name });
    i += DGD_COORD_RECORD_LEN;
  }
  return headers;
}

function scanLayerSaves(data) {
  const NAME_LEN = 40;
  const saves = [];
  let i = 0;
  while (i + DGD_COORD_RECORD_LEN <= data.length) {
    if (data[i] !== 0x09 || ![0x20, 0x44, 0x24].includes(data[i + 1])) { i++; continue; }
    const name = decodeAsciiName(data.subarray(i + 2, i + 2 + NAME_LEN));
    let restOk = true;
    for (let k = i + 2 + NAME_LEN; k < i + DGD_COORD_RECORD_LEN; k++) {
      const b = data[k];
      if (!(b === 0x20 || isDigit(b))) { restOk = false; break; }
    }
    if (name === null || !restOk) { i++; continue; }
    saves.push({ offset: i, name, deleted: data[i + 1] === 0x44 });
    i += DGD_COORD_RECORD_LEN;
  }
  return saves;
}

const isLiveLayerHeader = h => h.flag === 0x20 && isMeaningfulLayerName(h.name) && !h.name.startsWith('DIG$');

function attributeLayers(points, texts, headers, saves) {
  let resolve;
  if (headers.some(isLiveLayerHeader)) {
    const offsets = headers.map(h => h.offset);
    resolve = off => {
      const idx = partitionPoint(offsets, off) - 1;
      if (idx < 0) return ['keep', null];
      const h = headers[idx];
      return isLiveLayerHeader(h) ? ['live', h.name] : ['drop', null];
    };
  } else {
    const saveOffsets = saves.map(s => s.offset);
    const lastSave = new Map();
    for (const s of saves) lastSave.set(s.name, s.offset);
    resolve = off => {
      const idx = partitionPoint(saveOffsets, off);
      if (idx >= saves.length) return ['keep', null];
      const s = saves[idx];
      if (s.deleted || s.name.startsWith('DIG$') || lastSave.get(s.name) !== s.offset) return ['drop', null];
      return ['live', s.name];
    };
  }
  const apply = items => items.filter(item => {
    const [action, name] = resolve(item.offset);
    if (action === 'drop') return false;
    if (action === 'live') item.layerName = name;
    return true;
  });
  return [apply(points), apply(texts)];
}

// ---- objects -----------------------------------------------------------------
function untilNul(bs) { const idx = bs.indexOf(0); return idx < 0 ? bs : bs.subarray(0, idx); }

function scanObjects(data) {
  const NAME_LEN = 40, ZEROS_LEN = 8, CLOSED_FLAG_OFF = 76, COLOR_OFF = 60, COLOR_LEN = 2;
  const out = [];
  let i = 0;
  while (i + DGD_COORD_RECORD_LEN <= data.length) {
    const kind = { 0x03: 'poly', 0x04: 'text', 0x0a: 'text3d' }[data[i]];
    if (kind === undefined) { i++; continue; }
    const nameField = data.subarray(i + 2, i + 2 + NAME_LEN);
    const nameOk = [...untilNul(nameField)].every(b => b >= 0x20 && b < 0x7f);
    const flagOk = [0x20, 0x44, 0x24].includes(data[i + 1]);
    let attrsOk;
    if (kind === 'poly') {
      let numOk = true;
      for (let k = i + COLOR_OFF; k < i + CLOSED_FLAG_OFF; k++) if (!(data[k] === 0x20 || isDigit(data[k]))) { numOk = false; break; }
      attrsOk = numOk && (data[i + CLOSED_FLAG_OFF] === 0x30 || data[i + CLOSED_FLAG_OFF] === 0x31);
    } else {
      let zerosOk = true;
      for (let k = i + 2 + NAME_LEN; k < i + 2 + NAME_LEN + ZEROS_LEN; k++) if (data[k] !== 0) { zerosOk = false; break; }
      let tailOk = true;
      for (let k = i + 2 + NAME_LEN + ZEROS_LEN; k < i + DGD_COORD_RECORD_LEN; k++) if (!(data[k] === 0x20 || isDigit(data[k]))) { tailOk = false; break; }
      attrsOk = decodeAsciiName(nameField) !== null && zerosOk && tailOk;
    }
    if (!(flagOk && nameOk && attrsOk)) { i++; continue; }
    let colorIndex = null;
    const colStr = decodeName(data.subarray(i + COLOR_OFF, i + COLOR_OFF + COLOR_LEN)).trim();
    if (/^\d+$/.test(colStr)) { const n = parseInt(colStr, 10); if (n >= 0 && n <= 255) colorIndex = n; }
    out.push({ offset: i, kind, closed: data[i + CLOSED_FLAG_OFF] === 0x31, colorIndex });
    i += DGD_COORD_RECORD_LEN;
  }
  return out;
}

function owningPolyIndex(objects, offsets, offset) {
  const idx = partitionPoint(offsets, offset) - 1;
  if (idx < 0) return null;
  return objects[idx].kind === 'poly' ? idx : null;
}

function attributeClosed(points, objects) {
  const offsets = objects.map(o => o.offset);
  const segHeaders = new Map();
  for (const p of points) {
    if (p.segType === 0) {
      const idx = owningPolyIndex(objects, offsets, p.offset);
      if (idx !== null) segHeaders.set(idx, (segHeaders.get(idx) || 0) + 1);
    }
  }
  for (const p of points) {
    const idx = owningPolyIndex(objects, offsets, p.offset);
    if (idx !== null) {
      const obj = objects[idx];
      const single = (segHeaders.get(idx) || 0) <= 1;
      p.closed = obj.closed && single;
      p.colorIndex = obj.colorIndex;
    }
  }
}

function reconnectClosedMultistring(points, objects) {
  const offsets = objects.map(o => o.offset);
  let start = 0;
  while (start < points.length) {
    const oi = owningPolyIndex(objects, offsets, points[start].offset);
    if (oi === null) { start++; continue; }
    let end = start;
    while (end < points.length && owningPolyIndex(objects, offsets, points[end].offset) === oi) end++;
    const block = points.slice(start, end);
    const segCount = block.filter(p => p.segType === 0).length;
    if (objects[oi].closed && segCount > 1) {
      reconnectClosedObject(block);
      for (let k = 0; k < block.length; k++) points[start + k] = block[k];
    }
    start = end;
  }
}

function reconnectClosedObject(block) {
  const strings = [];
  for (const p of block) {
    if (!strings.length || p.segType === 0) strings.push([]);
    strings[strings.length - 1].push(p);
  }
  if (strings.length < 2) return;
  const blockOffsets = block.map(p => p.offset).sort((a, b) => a - b);
  const last = strings.pop();
  const merged = last.concat(strings[0]);
  const ordered = [merged, ...strings.slice(1)];
  let out = 0;
  for (const string of ordered) {
    string.forEach((p, within) => {
      p.segType = within === 0 ? 0 : 1;
      p.closed = false;
      p.offset = blockOffsets[out];
      block[out] = p;
      out++;
    });
  }
}

// ---- text objects ------------------------------------------------------------
function decodeTextLine(bs) {
  const pos = bs.indexOf(1);
  if (pos >= 0) return { text: decodeName(bs.subarray(0, pos)), continues: true };
  return { text: decodeName(bs), continues: false };
}
function joinTextLines(lines) {
  let content = '';
  lines.forEach((line, idx) => {
    content += line.text;
    if (!line.continues && idx + 1 < lines.length) content += '\n';
  });
  content = content.replace(/\s+$/, '');
  return content || null;
}
function parseMapScale(bs) {
  const name = decodeName(bs);
  if (!name.startsWith('1:')) return null;
  const val = parseFloat(name.slice(2).trim());
  return (!Number.isNaN(val) && val > 0) ? val : null;
}
const normalizeDegrees = d => ((d % 360) + 360) % 360;

function extractTexts(data, objects, textCoordOffsets) {
  const CONTENT_LEN = 80, MAX_RECORDS = 512, COORD_NAME_OFF = 37, COORD_NAME_LEN = 40;
  const out = [];
  for (const obj of objects) {
    if (obj.kind === 'poly') continue;
    const coords = [];
    const lines = [];
    let mapScale = null;
    let i = obj.offset + DGD_COORD_RECORD_LEN;
    for (let r = 0; r < MAX_RECORDS; r++) {
      if (i + DGD_COORD_RECORD_LEN > data.length) break;
      const t = data[i];
      if (t === 0x02 || t === 0x07) { /* skip */ }
      else if (t === 0x05) {
        const xyz = tryReadXyz(data, i + 5);
        if (!xyz) break;
        if (mapScale === null) mapScale = parseMapScale(data.subarray(i + COORD_NAME_OFF, i + COORD_NAME_OFF + COORD_NAME_LEN));
        coords.push([i, xyz[0], xyz[1], xyz[2]]);
      } else if (t === 0x06) {
        lines.push(decodeTextLine(data.subarray(i + 2, i + 2 + CONTENT_LEN)));
      } else break;
      i += DGD_COORD_RECORD_LEN;
    }
    const parsed = obj.kind === 'text' ? parseText(coords, lines) : parseText3d(coords, lines, mapScale);
    if (!parsed) continue;
    const [[ox, oy, oz], height, rotation, content] = parsed;
    for (const c of coords) textCoordOffsets.add(c[0]);
    out.push({ offset: obj.offset, layerName: null, content, x: ox, y: oy, z: oz, height, rotationDegrees: rotation, colorIndex: obj.colorIndex });
  }
  return out;
}

function parseText(coords, lines) {
  if (coords.length < 2) return null;
  const [, x, y, z] = coords[0];
  const [, height, , angleRadians] = coords[1];
  const content = joinTextLines(lines);
  if (content === null) return null;
  return [[x, y, z], height, normalizeDegrees(angleRadians * 180 / Math.PI), content];
}
function parseText3d(coords, lines, mapScale) {
  if (coords.length < 4) return null;
  const [, x, y, z] = coords[0];
  const [, dirX, dirY] = coords[1];
  const [, , charSize] = coords[3];
  const height = charSize * (mapScale !== null ? mapScale : 100) / 100;
  if (lines.length < 1) return null;
  const content = joinTextLines(lines.slice(1));
  if (content === null) return null;
  return [[x, y, z], height, normalizeDegrees(Math.atan2(dirY, dirX) * 180 / Math.PI), content];
}

// ---- colour table ------------------------------------------------------------
function parseColorIndex(bs) {
  let digits = '';
  for (const b of bs) if (isDigit(b)) digits += String.fromCharCode(b);
  const index = parseInt(digits, 10);
  return (!Number.isNaN(index) && index >= 1 && index <= 256) ? index : null;
}
function scanColorTable(data, headers, layerName) {
  const header = headers.find(h => h.name.toUpperCase() === layerName.toUpperCase());
  if (!header) return null;
  const raw = [];
  let i = header.offset + DGD_COORD_RECORD_LEN;
  while (i + DGD_COORD_RECORD_LEN <= data.length && data[i] === 0x05) {
    const index = parseColorIndex(data.subarray(i + 2, i + 5));
    const xyz = tryReadXyz(data, i + 5);
    if (index !== null && xyz) { const [red, blue, green] = xyz; raw.push([index, [red, green, blue]]); }
    i += DGD_COORD_RECORD_LEN;
  }
  if (!raw.length) return null;
  const fourBit = raw.every(([, rgb]) => rgb.every(ch => ch >= 0 && ch <= 15));
  const scale = fourBit ? 17 : 1;
  const maxIndex = Math.max(...raw.map(([index]) => index));
  const entries = new Array(maxIndex).fill(null);
  const channel = v => Math.min(Math.max(Math.round(v * scale), 0), 255);
  for (const [index, rgb] of raw) entries[index - 1] = [channel(rgb[0]), channel(rgb[1]), channel(rgb[2])];
  return {
    entries,
    rgb(index) { const i0 = index - 1; return (i0 >= 0 && i0 < entries.length) ? entries[i0] : null; },
  };
}

// ---- embedded layer names ----------------------------------------------------
function scanEmbeddedLayerNames(data) {
  const PNG_SIG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const PNG_IEND = Uint8Array.from([0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
  const NAME_LEN = 40, MAX_GAP = 160;
  const names = [];

  const FIRST_NAME_OFF = 16;
  if (data.length > FIRST_NAME_OFF + NAME_LEN) {
    const to = Math.min(FIRST_NAME_OFF + MAX_GAP, data.length);
    const pngAt = findBytes(data, PNG_SIG, FIRST_NAME_OFF, to);
    if (pngAt >= 0 && pngAt - FIRST_NAME_OFF >= NAME_LEN) {
      const name = decodeAsciiName(data.subarray(FIRST_NAME_OFF, FIRST_NAME_OFF + NAME_LEN));
      if (name && isMeaningfulLayerName(name)) pushUnique(names, name);
    }
  }

  let offset = 0;
  for (;;) {
    const rel = findBytes(data, PNG_IEND, offset);
    if (rel < 0) break;
    const nameOff = rel + PNG_IEND.length;
    const limit = Math.min(nameOff + MAX_GAP, data.length);
    const nextPng = findBytes(data, PNG_SIG, nameOff, limit);
    if (nextPng >= 0 && nextPng - nameOff >= NAME_LEN) {
      const name = decodeAsciiName(data.subarray(nameOff, nameOff + NAME_LEN));
      if (name && isMeaningfulLayerName(name)) pushUnique(names, name);
    }
    offset = nameOff;
  }
  return names;
}

function isMeaningfulLayerName(name) {
  name = name.trim();
  return isIndexLayerName(name) && !isGeneratedPointName(name) && !isScaleLabel(name)
    && !isDeletedLayerName(name) && /[a-zA-Z]/.test(name);
}
function isIndexLayerName(name) {
  name = name.trim();
  return name.length > 0 && !(name.startsWith('$') || name.toUpperCase().startsWith('DIG$'))
    && !isObjectDescriptor(name) && !name.includes('?')
    && [...name].every(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) < 0x7f);
}
function isObjectDescriptor(name) {
  return ['LINE', 'POLY', 'POLYLINE', 'POLYPOINT', 'TEXT', 'TXT_3D', 'TXT_NEW'].includes(name.toUpperCase())
    || name.toLowerCase() === 'imported from autocad';
}
function isGeneratedPointName(name) {
  if (!name.startsWith('POINT_')) return false;
  const suffix = name.slice('POINT_'.length);
  return suffix.length > 0 && /^\d+$/.test(suffix);
}
function isScaleLabel(name) {
  const idx = name.indexOf(':');
  if (idx < 0) return false;
  const left = name.slice(0, idx), right = name.slice(idx + 1);
  return left.length > 0 && right.length > 0 && /^\d+$/.test(left) && /^\d+$/.test(right);
}
function isDeletedLayerName(name) {
  if (!name.startsWith('D')) return false;
  const rest = name.slice(1);
  return rest.length > 0 && isDigit(rest.charCodeAt(0)) && rest.includes('_20');
}
function pushUnique(names, name) { if (!names.includes(name)) names.push(name); }

// ---- .isix index sidecar -----------------------------------------------------
const DGD_INDEX_START = 0x400;
const DGD_INDEX_PAGE_LEN = 0x400;
const DGD_INDEX_ENTRY_LEN = 48;
const DGD_INDEX_NAME_OFFSET = 8;
const DGD_INDEX_NAME_LEN = 40;

function markerOk(data, offset) {
  return data[offset + 4] === 0xff && data[offset + 5] === 0xff && data[offset + 6] === 0xff && data[offset + 7] === 0xff;
}
function decodeIndexEntry(data, offset) {
  if (offset + DGD_INDEX_ENTRY_LEN > data.length || !markerOk(data, offset)) return null;
  const name = decodeName(data.subarray(offset + DGD_INDEX_NAME_OFFSET, offset + DGD_INDEX_NAME_OFFSET + DGD_INDEX_NAME_LEN));
  if (!isIndexLayerName(name)) return null;
  const pointer = dv(data).getUint32(offset, false);
  return { offset: pointer, name };
}
function scanIndexCurrentPage(data) {
  let pageStart = DGD_INDEX_START;
  while (pageStart + DGD_INDEX_ENTRY_LEN <= data.length) {
    if (decodeIndexEntry(data, pageStart) !== null) {
      const pageEnd = Math.min(pageStart + DGD_INDEX_PAGE_LEN, data.length);
      const entries = [];
      let offset = pageStart;
      while (offset + DGD_INDEX_ENTRY_LEN <= pageEnd) {
        if (!markerOk(data, offset)) break;
        const e = decodeIndexEntry(data, offset);
        if (e) entries.push(e);
        offset += DGD_INDEX_ENTRY_LEN;
      }
      const deduped = [];
      for (const e of entries) if (!deduped.some(x => x.offset === e.offset && x.name === e.name)) deduped.push(e);
      return deduped;
    }
    pageStart += DGD_INDEX_PAGE_LEN;
  }
  return [];
}
function scanIndexUnaligned(data) {
  const entries = [];
  let offset = Math.min(DGD_INDEX_START, data.length);
  while (offset + DGD_INDEX_ENTRY_LEN <= data.length) {
    const e = decodeIndexEntry(data, offset);
    if (e) { entries.push(e); offset += DGD_INDEX_ENTRY_LEN; continue; }
    offset += 1;
  }
  entries.sort((a, b) => a.offset - b.offset || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const out = [];
  for (const e of entries) if (!out.length || out[out.length - 1].offset !== e.offset || out[out.length - 1].name !== e.name) out.push(e);
  return out;
}
function scanIndex(data) {
  const current = scanIndexCurrentPage(data);
  return current.length ? current : scanIndexUnaligned(data);
}

// ---- public API --------------------------------------------------------------
function readDgdDesign(input) {
  const u8 = input instanceof Uint8Array ? input : new Uint8Array(input);
  const { data, aux } = decompressIfVulz(u8);
  const gallery = aux.length ? aux : data;
  const layerNames = scanEmbeddedLayerNames(gallery);
  const headers = scanLayerHeaders(data);
  const saves = scanLayerSaves(data);
  const objects = scanObjects(data);
  const textCoordOffsets = new Set();
  let texts = extractTexts(data, objects, textCoordOffsets);
  let points = scanPoints(data);
  if (!headers.length && !saves.length && !objects.length && !points.length && !texts.length)
    throw new IsisError('stream contains no recognizable layer/object/text/coordinate records');
  points = points.filter(p => !textCoordOffsets.has(p.offset));
  attributeClosed(points, objects);
  [points, texts] = attributeLayers(points, texts, headers, saves);
  reconnectClosedMultistring(points, objects);
  for (const p of points) if (p.layerName) pushUnique(layerNames, p.layerName);
  for (const t of texts) if (t.layerName) pushUnique(layerNames, t.layerName);
  const palette = scanColorTable(data, headers, 'DIG$COLOUR256');
  return { points, texts, layerNames, palette };
}
const readDgdPoints = input => readDgdDesign(input).points;
const readDgdIndex = input => scanIndex(input instanceof Uint8Array ? input : new Uint8Array(input));

export { readDgdDesign, readDgdPoints, readDgdIndex, IsisError };
