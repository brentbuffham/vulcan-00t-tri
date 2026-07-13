#!/usr/bin/env python3
"""
vulcan_isis_parser.py - Maptek Vulcan .dgd.isis / .dgd.isix design database
parser. Python port of the reference decoder ``ROSETTA/isis.rs``.

A .dgd.isis file is a ``vulZ`` FastLZ-compressed container (the SAME container
as .00t - it reuses ``vulcan00t_parser.decode_vulz_archive``). Decompressed, it
is a stream of 117-byte fixed records:

    type 01 = layer header      type 03 = POLY object header
    type 04 = TEXT              type 05 = coordinate (SEGCRD)
    type 06 = text line         type 09 = layer save
    type 0a = 3DTEXT

Coordinate records carry big-endian f64 X/Y/Z plus space-padded ASCII name and
segment fields. The .isix sidecar is a page-indexed table of named layer
pointers. Depends only on the standard library + vulcan00t_parser.

All pre-2026-07-13 parser work is retired; see ``RETIRED.md``. Reference:
``ROSETTA/isis.rs`` (source of truth).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from vulcan00t_parser import VULZ_MAGIC, decode_vulz_archive, ReadError

DGD_COORD_RECORD_LEN = 117

KIND_UNKNOWN, KIND_LINE, KIND_POINT = "unknown", "line", "point"


class IsisError(Exception):
    """Any failure decoding a DGD ISIS design database."""


@dataclass
class DesignPoint:
    offset: int
    name: str
    secondary_name: str
    seg_type: int
    geometry_kind: str
    closed: bool
    x: float
    y: float
    z: float
    layer_name: Optional[str] = None
    color_index: Optional[int] = None


@dataclass
class DesignText:
    offset: int
    content: str
    x: float
    y: float
    z: float
    height: float
    rotation_degrees: float
    layer_name: Optional[str] = None
    color_index: Optional[int] = None


@dataclass
class DesignIndexEntry:
    offset: int
    name: str


@dataclass
class DgdColorTable:
    entries: List[Optional[Tuple[int, int, int]]]

    def rgb(self, index: int) -> Optional[Tuple[int, int, int]]:
        i = index - 1
        if 0 <= i < len(self.entries):
            return self.entries[i]
        return None


@dataclass
class DgdDesignData:
    points: List[DesignPoint] = field(default_factory=list)
    texts: List[DesignText] = field(default_factory=list)
    layer_names: List[str] = field(default_factory=list)
    palette: Optional[DgdColorTable] = None


# ── public API ───────────────────────────────────────────────────────────────
def read_dgd_design(path: str) -> DgdDesignData:
    with open(path, "rb") as fh:
        return read_dgd_design_bytes(fh.read())


def read_dgd_points(path: str) -> List[DesignPoint]:
    return read_dgd_design(path).points


def read_dgd_design_bytes(data_in: bytes) -> DgdDesignData:
    data, aux = _decompress_if_vulz(data_in)
    gallery = data if not aux else aux
    layer_names = _scan_embedded_layer_names(gallery)
    headers = _scan_layer_headers(data)
    saves = _scan_layer_saves(data)
    objects = _scan_objects(data)
    text_coord_offsets: set = set()
    texts = _extract_texts(data, objects, text_coord_offsets)
    points = _scan_points(data)
    if not headers and not saves and not objects and not points and not texts:
        raise IsisError("stream contains no recognizable layer/object/text/coordinate records")
    points = [p for p in points if p.offset not in text_coord_offsets]
    _attribute_closed(points, objects)
    points, texts = _attribute_layers(points, texts, headers, saves)
    _reconnect_closed_multistring(points, objects)
    for name in ([p.layer_name for p in points if p.layer_name]
                 + [t.layer_name for t in texts if t.layer_name]):
        _push_unique(layer_names, name)
    palette = _scan_color_table(data, headers, "DIG$COLOUR256")
    return DgdDesignData(points=points, texts=texts, layer_names=layer_names, palette=palette)


def read_dgd_index(path: str) -> List[DesignIndexEntry]:
    with open(path, "rb") as fh:
        return _scan_index(fh.read())


def read_dgd_index_bytes(data: bytes) -> List[DesignIndexEntry]:
    return _scan_index(data)


def same_stem_isix_path(isis_path: str) -> Optional[str]:
    base = os.path.splitext(isis_path)[0] + ".isix"
    if os.path.isfile(base):
        return base
    parent = os.path.dirname(base) or "."
    want = os.path.basename(base).lower()
    try:
        for entry in os.listdir(parent):
            if entry.lower() == want and os.path.isfile(os.path.join(parent, entry)):
                return os.path.join(parent, entry)
    except OSError:
        pass
    return None


# ── container ────────────────────────────────────────────────────────────────
def _decompress_if_vulz(data: bytes) -> Tuple[bytes, bytes]:
    if data[:8] == VULZ_MAGIC:
        try:
            archive = decode_vulz_archive(data)
        except ReadError as exc:
            raise IsisError(f"vulZ decompression failed: {exc}")
        return archive.data, archive.aux
    return data, b""


# ── coordinate records ──────────────────────────────────────────────────────
def _try_read_xyz(data: bytes, offset: int) -> Optional[Tuple[float, float, float]]:
    if offset + 24 > len(data):
        return None
    x, y, z = struct.unpack_from(">ddd", data, offset)
    if all(map(_finite, (x, y, z))):
        return (x, y, z)
    return None


def _finite(v: float) -> bool:
    return v == v and v not in (float("inf"), float("-inf"))


def _is_plausible_coord(x: float, y: float, z: float) -> bool:
    return abs(x) < 1e8 and abs(y) < 1e8 and abs(z) < 50_000.0


def _decode_name(bs: bytes) -> str:
    out = []
    for b in bs:
        if b == 0:
            break
        out.append(chr(b) if 0x20 <= b < 0x7F else "?")
    return "".join(out).rstrip()


def _decode_ascii_name(bs: bytes) -> Optional[str]:
    out = []
    for b in bs:
        if b == 0:
            break
        if not (0x20 <= b < 0x7F):
            return None
        out.append(chr(b))
    name = "".join(out).strip()
    return name or None


def _parse_seg_field(field_bytes: bytes) -> Optional[int]:
    if not all(b == 0x20 or (0x30 <= b <= 0x39) for b in field_bytes) \
            or not any(0x30 <= b <= 0x39 for b in field_bytes):
        return None
    digits = "".join(chr(b) for b in field_bytes if 0x30 <= b <= 0x39)
    try:
        return min(int(digits), 255)
    except ValueError:
        return None


def _infer_geometry_kind(data: bytes, coord_offset: int) -> str:
    lookback = 2048
    start = max(0, coord_offset - lookback)
    window = data[start:coord_offset]
    best = (-1, KIND_UNKNOWN)
    for token, kind in ((b"POLYPOINT", KIND_POINT), (b"POLYLINE", KIND_LINE), (b"LINE", KIND_LINE)):
        pos = window.rfind(token)
        if pos > best[0]:
            best = (pos, kind)
    return best[1]


def _scan_points(data: bytes) -> List[DesignPoint]:
    MIN_SCAN = 0x1000
    COORD_OFF, NAME_OFF, SECOND_OFF, NAME_LEN = 5, 37, 77, 40
    out: List[DesignPoint] = []
    limit = len(data) - DGD_COORD_RECORD_LEN
    i = MIN_SCAN
    while i <= limit:
        if data[i] == 0x05 and data[i + 1] == 0x20:
            seg = _parse_seg_field(data[i + 2:i + 5])
            xyz = _try_read_xyz(data, i + COORD_OFF) if seg is not None else None
            if seg is not None and xyz is not None and _is_plausible_coord(*xyz):
                out.append(DesignPoint(
                    offset=i,
                    name=_decode_name(data[i + NAME_OFF:i + NAME_OFF + NAME_LEN]),
                    secondary_name=_decode_name(data[i + SECOND_OFF:i + SECOND_OFF + NAME_LEN]),
                    seg_type=seg,
                    geometry_kind=_infer_geometry_kind(data, i),
                    closed=False,
                    x=xyz[0], y=xyz[1], z=xyz[2],
                ))
                i += DGD_COORD_RECORD_LEN
                continue
        i += 1
    return out


# ── layer headers / saves ────────────────────────────────────────────────────
@dataclass
class _LayerHeader:
    offset: int
    flag: int
    name: str


@dataclass
class _LayerSave:
    offset: int
    name: str
    deleted: bool


_MONTHS = ("JAN", "FEB", "MAR", "APR", "MAY", "JUN",
           "JUL", "AUG", "SEP", "OCT", "NOV", "DEC")


def _is_layer_header_stamp(stamp: str) -> bool:
    upper = stamp.upper()
    has_month = any(m in upper for m in _MONTHS)
    return ":" in stamp and ("DGEDIT" in upper or has_month)


def _scan_layer_headers(data: bytes) -> List[_LayerHeader]:
    NAME_LEN = STAMP_LEN = 40
    NAME_OFF = 2
    STAMP_OFF = NAME_OFF + NAME_LEN
    TAIL_OFF = STAMP_OFF + STAMP_LEN
    headers: List[_LayerHeader] = []
    i = 0
    while i + DGD_COORD_RECORD_LEN <= len(data):
        if data[i] != 0x01 or data[i + 1] not in (0x20, ord("D"), ord("$")):
            i += 1
            continue
        name = _decode_ascii_name(data[i + NAME_OFF:i + NAME_OFF + NAME_LEN])
        stamp = _decode_ascii_name(data[i + STAMP_OFF:i + STAMP_OFF + STAMP_LEN])
        tail_ok = all(b in (0, 0x20) or (0x30 <= b <= 0x39)
                      for b in data[i + TAIL_OFF:i + DGD_COORD_RECORD_LEN])
        if name is None or stamp is None or not _is_layer_header_stamp(stamp) or not tail_ok:
            i += 1
            continue
        headers.append(_LayerHeader(offset=i, flag=data[i + 1], name=name))
        i += DGD_COORD_RECORD_LEN
    return headers


def _scan_layer_saves(data: bytes) -> List[_LayerSave]:
    NAME_LEN = 40
    saves: List[_LayerSave] = []
    i = 0
    while i + DGD_COORD_RECORD_LEN <= len(data):
        if data[i] != 0x09 or data[i + 1] not in (0x20, ord("D"), ord("$")):
            i += 1
            continue
        name = _decode_ascii_name(data[i + 2:i + 2 + NAME_LEN])
        rest = data[i + 2 + NAME_LEN:i + DGD_COORD_RECORD_LEN]
        if name is None or not all(b == 0x20 or (0x30 <= b <= 0x39) for b in rest):
            i += 1
            continue
        saves.append(_LayerSave(offset=i, name=name, deleted=data[i + 1] == ord("D")))
        i += DGD_COORD_RECORD_LEN
    return saves


def _is_live_layer_header(h: _LayerHeader) -> bool:
    return h.flag == 0x20 and _is_meaningful_layer_name(h.name) and not h.name.startswith("DIG$")


def _attribute_layers(points, texts, headers, saves):
    if any(_is_live_layer_header(h) for h in headers):
        offsets = [h.offset for h in headers]

        def resolve(off):
            idx = _partition_point(offsets, off) - 1
            if idx < 0:
                return ("keep", None)
            h = headers[idx]
            return ("live", h.name) if _is_live_layer_header(h) else ("drop", None)
    else:
        save_offsets = [s.offset for s in saves]
        last_save: Dict[str, int] = {}
        for s in saves:
            last_save[s.name] = s.offset

        def resolve(off):
            idx = _partition_point(save_offsets, off)
            if idx >= len(saves):
                return ("keep", None)
            s = saves[idx]
            if s.deleted or s.name.startswith("DIG$") or last_save[s.name] != s.offset:
                return ("drop", None)
            return ("live", s.name)

    def apply(items):
        kept = []
        for item in items:
            action, name = resolve(item.offset)
            if action == "drop":
                continue
            if action == "live":
                item.layer_name = name
            kept.append(item)
        return kept

    return apply(points), apply(texts)


def _partition_point(sorted_offsets: List[int], value: int) -> int:
    """Count of offsets strictly less than value (bisect_left)."""
    lo, hi = 0, len(sorted_offsets)
    while lo < hi:
        mid = (lo + hi) // 2
        if sorted_offsets[mid] < value:
            lo = mid + 1
        else:
            hi = mid
    return lo


# ── objects (POLY / TEXT / 3DTEXT) ───────────────────────────────────────────
@dataclass
class _ObjectHeader:
    offset: int
    kind: str          # "poly" | "text" | "text3d"
    closed: bool
    color_index: Optional[int]


def _scan_objects(data: bytes) -> List[_ObjectHeader]:
    NAME_LEN, ZEROS_LEN = 40, 8
    CLOSED_FLAG_OFF = 76
    COLOR_OFF, COLOR_LEN = 60, 2
    out: List[_ObjectHeader] = []
    i = 0
    while i + DGD_COORD_RECORD_LEN <= len(data):
        kind = {0x03: "poly", 0x04: "text", 0x0a: "text3d"}.get(data[i])
        if kind is None:
            i += 1
            continue
        name_field = data[i + 2:i + 2 + NAME_LEN]
        name_ok = all((0x20 <= b < 0x7F) for b in _until_nul(name_field))
        flag_ok = data[i + 1] in (0x20, ord("D"), ord("$"))
        if kind == "poly":
            attrs_ok = (all(b == 0x20 or (0x30 <= b <= 0x39)
                            for b in data[i + COLOR_OFF:i + CLOSED_FLAG_OFF])
                        and data[i + CLOSED_FLAG_OFF] in (ord("0"), ord("1")))
        else:
            attrs_ok = (_decode_ascii_name(name_field) is not None
                        and all(b == 0 for b in data[i + 2 + NAME_LEN:i + 2 + NAME_LEN + ZEROS_LEN])
                        and all(b == 0x20 or (0x30 <= b <= 0x39)
                                for b in data[i + 2 + NAME_LEN + ZEROS_LEN:i + DGD_COORD_RECORD_LEN]))
        if not (flag_ok and name_ok and attrs_ok):
            i += 1
            continue
        try:
            color_index = int(data[i + COLOR_OFF:i + COLOR_OFF + COLOR_LEN].decode("ascii").strip())
            if not (0 <= color_index <= 255):
                color_index = None
        except (ValueError, UnicodeDecodeError):
            color_index = None
        out.append(_ObjectHeader(offset=i, kind=kind,
                                 closed=(data[i + CLOSED_FLAG_OFF] == ord("1")),
                                 color_index=color_index))
        i += DGD_COORD_RECORD_LEN
    return out


def _until_nul(bs: bytes) -> bytes:
    idx = bs.find(0)
    return bs if idx < 0 else bs[:idx]


def _owning_poly_index(objects: List[_ObjectHeader], offset: int) -> Optional[int]:
    offs = [o.offset for o in objects]
    idx = _partition_point(offs, offset) - 1
    if idx < 0:
        return None
    return idx if objects[idx].kind == "poly" else None


def _attribute_closed(points: List[DesignPoint], objects: List[_ObjectHeader]) -> None:
    seg_headers: Dict[int, int] = {}
    for p in points:
        if p.seg_type == 0:
            idx = _owning_poly_index(objects, p.offset)
            if idx is not None:
                seg_headers[idx] = seg_headers.get(idx, 0) + 1
    for p in points:
        idx = _owning_poly_index(objects, p.offset)
        if idx is not None:
            obj = objects[idx]
            single = seg_headers.get(idx, 0) <= 1
            p.closed = obj.closed and single
            p.color_index = obj.color_index


def _reconnect_closed_multistring(points: List[DesignPoint], objects: List[_ObjectHeader]) -> None:
    start = 0
    n = len(points)
    while start < n:
        oi = _owning_poly_index(objects, points[start].offset)
        if oi is None:
            start += 1
            continue
        end = start
        while end < n and _owning_poly_index(objects, points[end].offset) == oi:
            end += 1
        block = points[start:end]
        seg_count = sum(1 for p in block if p.seg_type == 0)
        if objects[oi].closed and seg_count > 1:
            _reconnect_closed_object(block)
            points[start:end] = block
        start = end


def _reconnect_closed_object(block: List[DesignPoint]) -> None:
    strings: List[List[DesignPoint]] = []
    for p in block:
        if not strings or p.seg_type == 0:
            strings.append([])
        strings[-1].append(p)
    if len(strings) < 2:
        return
    offsets = sorted(p.offset for p in block)
    last = strings.pop()
    merged = last + strings[0]
    ordered = [merged] + strings[1:]
    out = 0
    for string in ordered:
        for within, p in enumerate(string):
            p.seg_type = 0 if within == 0 else 1
            p.closed = False
            p.offset = offsets[out]
            block[out] = p
            out += 1


# ── text objects ─────────────────────────────────────────────────────────────
def _decode_text_line(bs: bytes) -> Tuple[str, bool]:
    pos = bs.find(1)
    if pos >= 0:
        return _decode_name(bs[:pos]), True
    return _decode_name(bs), False


def _join_text_lines(lines: List[Tuple[str, bool]]) -> Optional[str]:
    content = []
    for idx, (text, continues) in enumerate(lines):
        content.append(text)
        if not continues and idx + 1 < len(lines):
            content.append("\n")
    joined = "".join(content).rstrip()
    return joined or None


def _parse_map_scale(bs: bytes) -> Optional[float]:
    name = _decode_name(bs)
    if not name.startswith("1:"):
        return None
    try:
        val = float(name[2:].strip())
        return val if val > 0.0 else None
    except ValueError:
        return None


def _normalize_degrees(deg: float) -> float:
    return deg % 360.0


def _extract_texts(data, objects, text_coord_offsets) -> List[DesignText]:
    import math
    CONTENT_LEN, MAX_RECORDS = 80, 512
    COORD_NAME_OFF, COORD_NAME_LEN = 37, 40
    out: List[DesignText] = []
    for obj in objects:
        if obj.kind == "poly":
            continue
        coords: List[Tuple[int, float, float, float]] = []
        lines: List[Tuple[str, bool]] = []
        map_scale: Optional[float] = None
        i = obj.offset + DGD_COORD_RECORD_LEN
        for _ in range(MAX_RECORDS):
            if i + DGD_COORD_RECORD_LEN > len(data):
                break
            t = data[i]
            if t in (0x02, 0x07):
                pass
            elif t == 0x05:
                xyz = _try_read_xyz(data, i + 5)
                if xyz is None:
                    break
                if map_scale is None:
                    map_scale = _parse_map_scale(
                        data[i + COORD_NAME_OFF:i + COORD_NAME_OFF + COORD_NAME_LEN])
                coords.append((i, xyz[0], xyz[1], xyz[2]))
            elif t == 0x06:
                lines.append(_decode_text_line(data[i + 2:i + 2 + CONTENT_LEN]))
            else:
                break
            i += DGD_COORD_RECORD_LEN

        if obj.kind == "text":
            parsed = _parse_text(coords, lines)
        else:
            parsed = _parse_text3d(coords, lines, map_scale)
        if parsed is None:
            continue
        (ox, oy, oz), height, rotation, content = parsed
        for c in coords:
            text_coord_offsets.add(c[0])
        out.append(DesignText(offset=obj.offset, content=content, x=ox, y=oy, z=oz,
                              height=height, rotation_degrees=rotation,
                              color_index=obj.color_index))
    return out


def _parse_text(coords, lines):
    import math
    if len(coords) < 2:
        return None
    _, x, y, z = coords[0]
    _, height, _, angle_radians = coords[1]
    content = _join_text_lines(lines)
    if content is None:
        return None
    return ((x, y, z), height, _normalize_degrees(math.degrees(angle_radians)), content)


def _parse_text3d(coords, lines, map_scale):
    import math
    if len(coords) < 4:
        return None
    _, x, y, z = coords[0]
    _, dir_x, dir_y, _ = coords[1]
    _, _, char_size, _ = coords[3]
    height = char_size * (map_scale if map_scale is not None else 100.0) / 100.0
    if len(lines) < 1:
        return None
    content = _join_text_lines(lines[1:])
    if content is None:
        return None
    return ((x, y, z), height, _normalize_degrees(math.degrees(math.atan2(dir_y, dir_x))), content)


# ── colour table ─────────────────────────────────────────────────────────────
def _parse_color_index(field_bytes: bytes) -> Optional[int]:
    digits = "".join(chr(b) for b in field_bytes if 0x30 <= b <= 0x39)
    try:
        index = int(digits)
    except ValueError:
        return None
    return index if 1 <= index <= 256 else None


def _scan_color_table(data, headers, layer_name) -> Optional[DgdColorTable]:
    header = next((h for h in headers if h.name.upper() == layer_name.upper()), None)
    if header is None:
        return None
    raw: List[Tuple[int, Tuple[float, float, float]]] = []
    i = header.offset + DGD_COORD_RECORD_LEN
    while i + DGD_COORD_RECORD_LEN <= len(data) and data[i] == 0x05:
        index = _parse_color_index(data[i + 2:i + 5])
        xyz = _try_read_xyz(data, i + 5)
        if index is not None and xyz is not None:
            red, blue, green = xyz  # stored R,B,G -> reorder to R,G,B
            raw.append((index, (red, green, blue)))
        i += DGD_COORD_RECORD_LEN
    if not raw:
        return None
    four_bit = all(0.0 <= ch <= 15.0 for _, rgb in raw for ch in rgb)
    scale = 17.0 if four_bit else 1.0
    max_index = max(index for index, _ in raw)
    entries: List[Optional[Tuple[int, int, int]]] = [None] * max_index

    def channel(v):
        return int(min(max(round(v * scale), 0), 255))

    for index, rgb in raw:
        entries[index - 1] = (channel(rgb[0]), channel(rgb[1]), channel(rgb[2]))
    return DgdColorTable(entries=entries)


# ── embedded layer names (PNG gallery) ───────────────────────────────────────
def _scan_embedded_layer_names(data: bytes) -> List[str]:
    PNG_SIG = b"\x89PNG\x0d\x0a\x1a\x0a"
    PNG_IEND = b"IEND\xaeB`\x82"
    NAME_LEN = 40
    MAX_GAP = 160
    names: List[str] = []

    FIRST_NAME_OFF = 16
    if len(data) > FIRST_NAME_OFF + NAME_LEN:
        window = data[FIRST_NAME_OFF:min(FIRST_NAME_OFF + MAX_GAP, len(data))]
        png_at = window.find(PNG_SIG)
        if png_at >= NAME_LEN:
            name = _decode_ascii_name(data[FIRST_NAME_OFF:FIRST_NAME_OFF + NAME_LEN])
            if name and _is_meaningful_layer_name(name):
                _push_unique(names, name)

    offset = 0
    while True:
        rel = data.find(PNG_IEND, offset)
        if rel < 0:
            break
        name_off = rel + len(PNG_IEND)
        limit = min(name_off + MAX_GAP, len(data))
        next_png = data.find(PNG_SIG, name_off, limit)
        if next_png >= 0 and (next_png - name_off) >= NAME_LEN:
            name = _decode_ascii_name(data[name_off:name_off + NAME_LEN])
            if name and _is_meaningful_layer_name(name):
                _push_unique(names, name)
        offset = name_off
    return names


def _is_meaningful_layer_name(name: str) -> bool:
    name = name.strip()
    return (_is_index_layer_name(name)
            and not _is_generated_point_name(name)
            and not _is_scale_label(name)
            and not _is_deleted_layer_name(name)
            and any(c.isalpha() for c in name))


def _is_index_layer_name(name: str) -> bool:
    name = name.strip()
    return (bool(name)
            and not (name.startswith("$") or name.upper().startswith("DIG$"))
            and not _is_object_descriptor(name)
            and "?" not in name
            and all(0x20 <= ord(c) < 0x7F for c in name))


def _is_object_descriptor(name: str) -> bool:
    return name.upper() in ("LINE", "POLY", "POLYLINE", "POLYPOINT", "TEXT", "TXT_3D", "TXT_NEW") \
        or name.lower() == "imported from autocad"


def _is_generated_point_name(name: str) -> bool:
    if not name.startswith("POINT_"):
        return False
    suffix = name[len("POINT_"):]
    return bool(suffix) and suffix.isdigit()


def _is_scale_label(name: str) -> bool:
    if ":" not in name:
        return False
    left, right = name.split(":", 1)
    return bool(left) and bool(right) and left.isdigit() and right.isdigit()


def _is_deleted_layer_name(name: str) -> bool:
    if not name.startswith("D"):
        return False
    rest = name[1:]
    return bool(rest) and rest[0:1].isdigit() and "_20" in rest


def _push_unique(names: List[str], name: str) -> None:
    if name not in names:
        names.append(name)


# ── .isix index sidecar ──────────────────────────────────────────────────────
DGD_INDEX_START = 0x400
DGD_INDEX_PAGE_LEN = 0x400
DGD_INDEX_ENTRY_LEN = 48
DGD_INDEX_NAME_OFFSET = 8
DGD_INDEX_NAME_LEN = 40
DGD_INDEX_MARKER = b"\xff\xff\xff\xff"


def _decode_index_entry(data: bytes, offset: int) -> Optional[DesignIndexEntry]:
    if offset + DGD_INDEX_ENTRY_LEN > len(data) or data[offset + 4:offset + 8] != DGD_INDEX_MARKER:
        return None
    name = _decode_name(data[offset + DGD_INDEX_NAME_OFFSET:
                             offset + DGD_INDEX_NAME_OFFSET + DGD_INDEX_NAME_LEN])
    if not _is_index_layer_name(name):
        return None
    pointer = struct.unpack_from(">I", data, offset)[0]
    return DesignIndexEntry(offset=pointer, name=name)


def _scan_index(data: bytes) -> List[DesignIndexEntry]:
    current = _scan_index_current_page(data)
    if current:
        return current
    return _scan_index_unaligned(data)


def _scan_index_current_page(data: bytes) -> List[DesignIndexEntry]:
    page_start = DGD_INDEX_START
    while page_start + DGD_INDEX_ENTRY_LEN <= len(data):
        if _decode_index_entry(data, page_start) is not None:
            page_end = min(page_start + DGD_INDEX_PAGE_LEN, len(data))
            entries: List[DesignIndexEntry] = []
            offset = page_start
            while offset + DGD_INDEX_ENTRY_LEN <= page_end:
                if data[offset + 4:offset + 8] != DGD_INDEX_MARKER:
                    break
                entry = _decode_index_entry(data, offset)
                if entry is not None:
                    entries.append(entry)
                offset += DGD_INDEX_ENTRY_LEN
            deduped: List[DesignIndexEntry] = []
            for e in entries:
                if e not in deduped:
                    deduped.append(e)
            return deduped
        page_start += DGD_INDEX_PAGE_LEN
    return []


def _scan_index_unaligned(data: bytes) -> List[DesignIndexEntry]:
    entries: List[DesignIndexEntry] = []
    offset = min(DGD_INDEX_START, len(data))
    while offset + DGD_INDEX_ENTRY_LEN <= len(data):
        entry = _decode_index_entry(data, offset)
        if entry is not None:
            entries.append(entry)
            offset += DGD_INDEX_ENTRY_LEN
            continue
        offset += 1
    entries.sort(key=lambda e: (e.offset, e.name))
    out: List[DesignIndexEntry] = []
    for e in entries:
        if not out or out[-1] != e:
            out.append(e)
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python vulcan_isis_parser.py <file.dgd.isis> [...]")
        raise SystemExit(2)
    for p in sys.argv[1:]:
        try:
            d = read_dgd_design(p)
            print(f"{p}: {len(d.points)} points, {len(d.texts)} texts, "
                  f"{len(d.layer_names)} layers, palette={'yes' if d.palette else 'no'}")
        except (OSError, IsisError) as exc:
            print(f"{p}: ERROR {exc}")
