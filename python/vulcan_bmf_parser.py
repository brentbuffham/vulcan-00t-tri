#!/usr/bin/env python3
"""
vulcan_bmf_parser.py - Maptek Vulcan .bmf/.bdf block model parser (TBMS2.0).

Python port of the reference decoder ``ROSETTA/bmf.rs``. A .bmf file is an
UNcompressed, 0x808-byte-paged container (NOT vulZ, unlike .00t/.dgd.isis):

    0x800-byte file header (starts with "TBMS2.0\\0"); LE u64 primary
        page-table pointer at 0x18
    pages of stride 0x808 = 8-byte header + 0x800 payload
    metadata pages (kind 00 02) carry a brace/`=` text object describing
        dims, origin, orientation, bounds, schemas, and variables
    value pages hold each variable's column, addressed through one- or
        two-level page tables (kinds 01 01 / 02 01)

Coordinates/counts in the metadata text are ASCII; value-page numbers are
little-endian. glam's DVec3/DMat3 are represented here as plain 3-tuples and a
3x3 row-major matrix. Depends only on the standard library.

All pre-2026-07-13 parser work is retired; see ``RETIRED.md``. Reference:
``ROSETTA/bmf.rs`` (source of truth) and ``00T_FORMAT.md`` for the sibling .00t.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

Vec3 = Tuple[float, float, float]

FILE_HEADER_LEN = 0x800
PAGE_STRIDE = 0x808
PAGE_HEADER_LEN = 8
PAGE_PAYLOAD_LEN = 0x800
METADATA_PAGE_KIND = b"\x00\x02"
PAGE_TABLE_SLOTS = PAGE_PAYLOAD_LEN // 8
TWO_LEVEL_PAGE_TABLE_SLOTS = PAGE_TABLE_SLOTS * PAGE_TABLE_SLOTS
HEADER_PRIMARY_TABLE_POINTER = 0x18

_MONTHS = ("JAN", "FEB", "MAR", "APR", "MAY", "JUN",
           "JUL", "AUG", "SEP", "OCT", "NOV", "DEC")


class BmfError(Exception):
    """Any structural failure decoding a BMF container or its metadata."""


@dataclass
class BmfSchema:
    name: str = ""
    lower: Vec3 = (0.0, 0.0, 0.0)
    upper: Vec3 = (0.0, 0.0, 0.0)
    dims: Tuple[int, int, int] = (0, 0, 0)
    min_size: Vec3 = (0.0, 0.0, 0.0)
    max_size: Vec3 = (0.0, 0.0, 0.0)


@dataclass
class BmfVariable:
    name: str = ""
    physical_type: str = ""
    description: str = ""
    location: int = 0
    default: str = ""
    global_: str = ""
    strings: Dict[int, str] = field(default_factory=dict)
    special: bool = False


@dataclass
class BmfMetadata:
    n_blocks: int = 0
    origin: Vec3 = (0.0, 0.0, 0.0)
    orientation: Vec3 = (0.0, 0.0, 0.0)
    lower: Vec3 = (0.0, 0.0, 0.0)
    upper: Vec3 = (0.0, 0.0, 0.0)
    dims: Tuple[int, int, int] = (0, 0, 0)
    is_irregular: bool = False
    schemas: List[BmfSchema] = field(default_factory=list)
    variables: List[BmfVariable] = field(default_factory=list)
    raw_top_level: Dict[str, str] = field(default_factory=dict)


@dataclass
class BlockBounds:
    lower: Vec3
    upper: Vec3


NUMERIC_TYPES = {"float", "short", "int", "longlong", "double"}
NAMED_TYPES = {"namedbyte", "namedshort"}
NUMERIC_VALUES_PER_PAGE = {"float": 512, "short": 1024, "int": 512,
                           "longlong": 256, "double": 256}
NAMED_VALUES_PER_PAGE = {"namedbyte": 2048, "namedshort": 1024}
_EMPTY_LABELS = {"air", "delete", "deleted", "void", "empty", "null"}


def _is_numeric_type(t: str) -> bool:
    return t in NUMERIC_TYPES


def _is_empty_block_label(label: str) -> bool:
    return label.strip().lower() in _EMPTY_LABELS


# ── rotation (row-major 3x3) ────────────────────────────────────────────────
def _mat_mul(a, b):
    return [[sum(a[r][k] * b[k][c] for k in range(3)) for c in range(3)] for r in range(3)]


def _rot_z(rad):
    c, s = math.cos(rad), math.sin(rad)
    return [[c, -s, 0.0], [s, c, 0.0], [0.0, 0.0, 1.0]]


def _rot_x(rad):
    c, s = math.cos(rad), math.sin(rad)
    return [[1.0, 0.0, 0.0], [0.0, c, -s], [0.0, s, c]]


def _rot_y(rad):
    c, s = math.cos(rad), math.sin(rad)
    return [[c, 0.0, s], [0.0, 1.0, 0.0], [-s, 0.0, c]]


def compute_rotation_matrix(orientation: Vec3):
    """bearing/dip/plunge -> row-major 3x3. See ROSETTA/bmf.rs for the
    convention (bearing = orientation[2], dip = [0], plunge = [1])."""
    bearing = math.radians(90.0 - orientation[2])
    dip = math.radians(orientation[0])
    plunge = math.radians(orientation[1])
    return _mat_mul(_mat_mul(_rot_z(bearing), _rot_x(dip)), _rot_y(plunge))


# ── metadata text object ─────────────────────────────────────────────────────
class _MetaObject(dict):
    """Parsed brace/`=` object: str -> (_MetaObject | str)."""

    def string(self, key) -> Optional[str]:
        v = self.get(key)
        return v if isinstance(v, str) else None

    def f64(self, key) -> Optional[float]:
        v = self.string(key)
        if v is None:
            return None
        try:
            return float(v.strip())
        except ValueError:
            return None

    def usize(self, key) -> Optional[int]:
        v = self.string(key)
        if v is None:
            return None
        try:
            return int(v.strip())
        except ValueError:
            return None


def _tokenize(text: str):
    tokens = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            tokens.append(("open", None)); i += 1
        elif ch == "}":
            tokens.append(("close", None)); i += 1
        elif ch == "=":
            tokens.append(("eq", None)); i += 1
        elif ch == ",":
            tokens.append(("comma", None)); i += 1
        elif ch == '"':
            i += 1
            buf = []
            while i < n:
                c = text[i]
                if c == '"':
                    i += 1
                    break
                if c == "\\":
                    i += 1
                    if i < n:
                        buf.append(text[i]); i += 1
                else:
                    buf.append(c); i += 1
            tokens.append(("val", "".join(buf)))
        elif ch.isspace():
            i += 1
        else:
            buf = [ch]; i += 1
            while i < n and not text[i].isspace() and text[i] not in "{}=,":
                buf.append(text[i]); i += 1
            tokens.append(("val", "".join(buf)))
    return tokens


class _Parser:
    def __init__(self, tokens, pos=0):
        self.tokens = tokens
        self.pos = pos

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def parse_object(self):
        if not self._peek() or self._peek()[0] != "open":
            raise BmfError("expected '{'")
        self.pos += 1
        obj = _MetaObject()
        while True:
            while self._peek() and self._peek()[0] == "comma":
                self.pos += 1
            p = self._peek()
            if p and p[0] == "close":
                self.pos += 1
                break
            if not p or p[0] != "val":
                raise BmfError("expected metadata key")
            key = p[1]; self.pos += 1
            if not self._peek() or self._peek()[0] != "eq":
                raise BmfError("expected '='")
            self.pos += 1
            obj[key] = self.parse_value()
            while self._peek() and self._peek()[0] == "comma":
                self.pos += 1
        return obj

    def parse_value(self):
        p = self._peek()
        if p and p[0] == "open":
            return self.parse_object()
        if p and p[0] == "val":
            self.pos += 1
            return p[1]
        raise BmfError("expected metadata value")


def _is_metadata_root(obj) -> bool:
    return isinstance(obj, _MetaObject) and (
        "n_blocks" in obj or ("dim_x" in obj and "dim_y" in obj and "dim_z" in obj))


def _metadata_root_score(obj) -> int:
    if not isinstance(obj, _MetaObject):
        return 0
    variables = sum(1 for k in obj if k.startswith("var_") or k.startswith("special_"))
    schemas = sum(1 for k in obj if k.startswith("schema_"))
    return (variables * 10 + schemas * 3
            + (1 if "n_blocks" in obj else 0) + (1 if "dim_x" in obj else 0))


def _parse_metadata_root(text: str):
    tokens = _tokenize(text)
    best, best_score = None, 0
    for idx, tok in enumerate(tokens):
        if tok[0] != "open":
            continue
        try:
            node = _Parser(tokens, idx).parse_object()
        except BmfError:
            continue
        if _is_metadata_root(node):
            score = _metadata_root_score(node)
            if best is None or score > best_score:
                best, best_score = node, score
    if best is None:
        raise BmfError("could not parse BMF metadata root")
    return best


# ── metadata page collection / candidate extraction ─────────────────────────
@dataclass
class _MetaPage:
    text: str
    offset: int
    starts_root: bool
    contiguous: bool


def _collect_metadata_pages(data: bytes) -> List[_MetaPage]:
    pages: List[_MetaPage] = []
    offset = FILE_HEADER_LEN + PAGE_HEADER_LEN
    prev = None
    while offset + PAGE_STRIDE <= len(data):
        page = data[offset:offset + PAGE_STRIDE]
        if page[:2] == METADATA_PAGE_KIND:
            payload_len = min(max(struct.unpack_from("<H", page, 2)[0], 1), PAGE_PAYLOAD_LEN)
            payload = page[PAGE_HEADER_LEN:PAGE_HEADER_LEN + payload_len]
            text = payload.decode("latin-1").replace("\x00", "")
            starts_root = text.lstrip().startswith("{")
            contiguous = prev is not None and prev + PAGE_STRIDE == offset
            pages.append(_MetaPage(text, offset, starts_root, contiguous))
            prev = offset
        offset += PAGE_STRIDE
    return pages


def _is_metadata_candidate(text: str) -> bool:
    return ('"n_blocks"' in text
            or ('"dim_x"' in text and '"dim_y"' in text and '"dim_z"' in text))


class _BraceScanner:
    def __init__(self):
        self.depth = 0
        self.in_string = False
        self.escaped = False

    def feed(self, text: str) -> bool:
        closed_root = False
        for ch in text:
            if self.in_string:
                if self.escaped:
                    self.escaped = False
                elif ch == "\\":
                    self.escaped = True
                elif ch == '"':
                    self.in_string = False
                continue
            if ch == '"':
                self.in_string = True
            elif ch == "{":
                self.depth += 1
            elif ch == "}":
                self.depth = max(0, self.depth - 1)
                if self.depth == 0:
                    closed_root = True
        return closed_root


def _extract_metadata_candidates(data: bytes) -> List[Tuple[str, int]]:
    """Returns list of (candidate text, max_page_offset)."""
    pages = _collect_metadata_pages(data)
    candidates: List[Tuple[str, int]] = []

    # contiguous runs (forward + reverse)
    run: List[_MetaPage] = []

    def flush(r):
        if not r:
            return
        max_off = r[-1].offset
        fwd = "".join(p.text for p in r)
        if fwd.strip():
            candidates.append((fwd, max_off))
        if len(r) > 1:
            rev = "".join(p.text for p in reversed(r))
            if rev.strip():
                candidates.append((rev, max_off))

    for p in pages:
        if p.contiguous:
            run.append(p)
        else:
            flush(run)
            run = [p]
    flush(run)

    # threaded: each root-start page + continuations, materialized where a
    # root closes (brace balance back to zero) plus the full thread.
    for i, page in enumerate(pages):
        if not page.starts_root:
            continue
        text = page.text
        max_off = page.offset
        scanner = _BraceScanner()
        scanner.feed(page.text)
        candidates.append((text, max_off))
        pushed = True
        for cont in pages[i + 1:]:
            if cont.starts_root:
                continue
            text += cont.text
            max_off = max(max_off, cont.offset)
            pushed = False
            if scanner.feed(cont.text):
                candidates.append((text, max_off))
                pushed = True
        if not pushed:
            candidates.append((text, max_off))

    candidates = [c for c in candidates if _is_metadata_candidate(c[0])]
    # de-dup preserving order
    seen = set()
    uniq = []
    for text, off in candidates:
        if text not in seen:
            seen.add(text)
            uniq.append((text, off))
    if not uniq:
        raise BmfError("BMF metadata pages were not found")
    return uniq


def _header_primary_table_pointer(data: bytes) -> Optional[int]:
    if HEADER_PRIMARY_TABLE_POINTER + 8 > len(data):
        return None
    pointer = struct.unpack_from("<Q", data, HEADER_PRIMARY_TABLE_POINTER)[0]
    if pointer % PAGE_STRIDE != 0 or pointer < PAGE_STRIDE or pointer + PAGE_STRIDE > len(data):
        return None
    kind = data[pointer:pointer + 2]
    return pointer if kind in (b"\x01\x01", b"\x02\x01") else None


def _parse_bmf_metadata_root(data: bytes):
    candidates = _extract_metadata_candidates(data)
    pointer = _header_primary_table_pointer(data)
    anchor = None      # (gap, node)
    best = None
    best_score = 0
    for text, max_off in candidates:
        try:
            node = _parse_metadata_root(text)
        except BmfError:
            continue
        if pointer is not None and max_off < pointer:
            gap = pointer - max_off
            if gap % PAGE_STRIDE == 0 and (anchor is None or gap < anchor[0]):
                anchor = (gap, node)
        score = _metadata_root_score(node)
        if best is None or score > best_score:
            best, best_score = node, score
    if anchor is not None:
        return anchor[1]
    if best is None:
        raise BmfError("could not parse BMF metadata root")
    return best


def _vec3(obj, kx, ky, kz) -> Vec3:
    return (obj.f64(kx) or 0.0, obj.f64(ky) or 0.0, obj.f64(kz) or 0.0)


def _schema_from(node) -> Optional[BmfSchema]:
    if not isinstance(node, _MetaObject):
        return None
    return BmfSchema(
        name=node.string("description") or "",
        lower=_vec3(node, "lower_x", "lower_y", "lower_z"),
        upper=_vec3(node, "upper_x", "upper_y", "upper_z"),
        dims=(node.usize("dim_x") or 0, node.usize("dim_y") or 0, node.usize("dim_z") or 0),
        min_size=_vec3(node, "min_size_x", "min_size_y", "min_size_z"),
        max_size=_vec3(node, "max_size_x", "max_size_y", "max_size_z"),
    )


def _variable_from(node) -> Optional[BmfVariable]:
    if not isinstance(node, _MetaObject):
        return None
    strings: Dict[int, str] = {}
    for key, value in node.items():
        if key.startswith("string_") and isinstance(value, str):
            try:
                strings[int(key[len("string_"):])] = value
            except ValueError:
                pass
    loc = node.string("location")
    try:
        location = int(loc.strip()) if loc is not None else 0
    except ValueError:
        location = 0
    return BmfVariable(
        name=(node.string("name") or "").strip(),
        physical_type=(node.string("type") or "").strip().lower(),
        description=node.string("description") or "",
        location=location,
        default=node.string("default") or "",
        global_=node.string("global") or "",
        strings=strings,
    )


def _metadata_from_node(node) -> BmfMetadata:
    if not isinstance(node, _MetaObject):
        raise BmfError("BMF metadata root is not an object")
    dims = (node.usize("dim_x") or 0, node.usize("dim_y") or 0, node.usize("dim_z") or 0)
    inferred = 0 if 0 in dims else dims[0] * dims[1] * dims[2]
    meta = BmfMetadata(
        n_blocks=node.usize("n_blocks") if node.usize("n_blocks") is not None else inferred,
        origin=_vec3(node, "origin_x", "origin_y", "origin_z"),
        orientation=_vec3(node, "orientation_1", "orientation_2", "orientation_3"),
        lower=_vec3(node, "lower_x", "lower_y", "lower_z"),
        upper=_vec3(node, "upper_x", "upper_y", "upper_z"),
        dims=dims,
        is_irregular=(node.usize("is_irregular") or 0) != 0,
    )
    for key, value in node.items():
        if isinstance(value, str):
            meta.raw_top_level[key] = value
        if key.startswith("schema_"):
            schema = _schema_from(value)
            if schema:
                meta.schemas.append(schema)
        elif key.startswith("var_") or key.startswith("special_"):
            var = _variable_from(value)
            if var:
                var.special = key.startswith("special_")
                meta.variables.append(var)
    return meta


# ── model ────────────────────────────────────────────────────────────────────
class BmfModel:
    def __init__(self, data: bytes):
        if len(data) < FILE_HEADER_LEN or not data.startswith(b"TBMS2.0\x00"):
            raise BmfError("not a Vulcan TBMS2.0 block model")
        self._bytes = data
        self.metadata = _metadata_from_node(_parse_bmf_metadata_root(data))
        self.rotation = compute_rotation_matrix(self.metadata.orientation)

    @classmethod
    def from_path(cls, path: str) -> "BmfModel":
        with open(path, "rb") as fh:
            return cls(fh.read())

    # -- variable helpers --
    def variable(self, name: str) -> Optional[BmfVariable]:
        return next((v for v in self.metadata.variables if v.name == name), None)

    def numeric_variables(self) -> List[BmfVariable]:
        return [v for v in self.metadata.variables if _is_numeric_type(v.physical_type)]

    def unsupported_variables(self) -> List[BmfVariable]:
        return [v for v in self.metadata.variables
                if not (_is_numeric_type(v.physical_type) or v.physical_type in NAMED_TYPES)]

    # -- pages --
    def _page(self, offset: int) -> bytes:
        if offset < PAGE_STRIDE or offset % PAGE_STRIDE != 0:
            raise BmfError(f"BMF page offset {offset} is not page-aligned")
        end = offset + PAGE_STRIDE
        if end > len(self._bytes):
            raise BmfError(f"BMF page offset {offset} is outside file")
        return self._bytes[offset:end]

    def _page_payload(self, offset: int) -> bytes:
        page = self._page(offset)
        return page[PAGE_HEADER_LEN:PAGE_HEADER_LEN + PAGE_PAYLOAD_LEN]

    @staticmethod
    def _read_u64_slot(payload: bytes, slot: int) -> int:
        start = slot * 8
        if start + 8 > len(payload):
            raise BmfError(f"BMF page table is missing slot {slot}")
        return struct.unpack_from("<Q", payload, start)[0]

    def _value_page_offsets(self, table_offset: int, first: int, last: int) -> List[int]:
        if first > last:
            raise BmfError(f"invalid BMF value-page range {first}..{last}")
        page = self._page(table_offset)
        kind = page[:2]
        payload = page[PAGE_HEADER_LEN:PAGE_HEADER_LEN + PAGE_PAYLOAD_LEN]
        offsets: List[int] = []
        if kind == b"\x01\x01":
            if last > PAGE_TABLE_SLOTS:
                raise BmfError("BMF leaf page table slot out of range")
            for slot in range(first, last):
                offsets.append(self._read_u64_slot(payload, slot))
            return offsets
        if kind == b"\x02\x01":
            if last > TWO_LEVEL_PAGE_TABLE_SLOTS:
                raise BmfError("BMF two-level page table slot out of range")
            if first == last:
                return offsets
            first_child = first // PAGE_TABLE_SLOTS
            last_child = (last - 1) // PAGE_TABLE_SLOTS
            for child_index in range(first_child, last_child + 1):
                child_page_start = child_index * PAGE_TABLE_SLOTS
                req_start = max(first, child_page_start) - child_page_start
                req_end = min(last, child_page_start + PAGE_TABLE_SLOTS) - child_page_start
                child_offset = self._read_u64_slot(payload, child_index)
                if child_offset == 0:
                    offsets.extend([0] * (req_end - req_start))
                    continue
                child = self._page(child_offset)
                if child[:2] != b"\x01\x01":
                    raise BmfError(f"expected BMF leaf page table at offset {child_offset}")
                child_payload = child[PAGE_HEADER_LEN:PAGE_HEADER_LEN + PAGE_PAYLOAD_LEN]
                for slot in range(req_start, req_end):
                    offsets.append(self._read_u64_slot(child_payload, slot))
            return offsets
        raise BmfError(f"expected page table at offset {table_offset}")

    # -- numeric --
    def numeric_values(self, name: str) -> List[float]:
        return self.numeric_values_range(name, 0, self.metadata.n_blocks)

    def numeric_values_range(self, name: str, start: int, end: int) -> List[float]:
        var = self.variable(name)
        if var is None:
            raise BmfError(f"unknown block variable '{name}'")
        if not _is_numeric_type(var.physical_type):
            raise BmfError(f"variable '{name}' is not numeric ({var.physical_type})")
        if start > end or end > self.metadata.n_blocks:
            raise BmfError(f"variable '{name}' invalid range {start}..{end}")
        requested = end - start
        if var.location == 0:
            return [_parse_default_f64(var)] * requested
        vpp = NUMERIC_VALUES_PER_PAGE[var.physical_type]
        first_page = start // vpp
        last_page = -(-end // vpp)  # ceil
        offsets = self._value_page_offsets(var.location, first_page, last_page)
        fmt, size = {"float": ("<f", 4), "short": ("<h", 2), "int": ("<i", 4),
                     "longlong": ("<q", 8), "double": ("<d", 8)}[var.physical_type]
        values: List[float] = []
        for rel, offset in enumerate(offsets):
            page_index = first_page + rel
            page_start = page_index * vpp
            page_end = page_start + vpp
            value_start = max(0, start - page_start)
            value_end = min(end, page_end) - page_start
            count = value_end - value_start
            if offset == 0:
                values.extend([_parse_default_f64(var)] * count)
                continue
            payload = self._page_payload(offset)
            base = value_start * size
            for k in range(count):
                values.append(float(struct.unpack_from(fmt, payload, base + k * size)[0]))
        return values

    # -- named / categorical --
    def named_code_values(self, name: str) -> List[int]:
        var = self.variable(name)
        if var is None:
            raise BmfError(f"unknown block variable '{name}'")
        if var.physical_type not in NAMED_TYPES:
            raise BmfError(f"variable '{name}' is not named ({var.physical_type})")
        if var.location == 0:
            return [_parse_default_code(var)] * self.metadata.n_blocks
        vpp = NAMED_VALUES_PER_PAGE[var.physical_type]
        required_pages = -(-self.metadata.n_blocks // vpp)
        offsets = self._value_page_offsets(var.location, 0, required_pages)
        values: List[int] = []
        for page_index, offset in enumerate(offsets):
            page_start = page_index * vpp
            count = min(self.metadata.n_blocks - page_start, vpp)
            if offset == 0:
                values.extend([_parse_default_code(var)] * count)
                continue
            payload = self._page_payload(offset)
            if var.physical_type == "namedbyte":
                values.extend(payload[:count])
            else:  # namedshort
                for k in range(count):
                    values.append(struct.unpack_from("<H", payload, k * 2)[0])
        return values

    # -- block bounds --
    def _empty_marker_variable(self) -> Optional[BmfVariable]:
        cands = [v for v in self.metadata.variables
                 if v.physical_type in NAMED_TYPES
                 and any(_is_empty_block_label(lbl) for lbl in v.strings.values())]
        if not cands:
            return None
        return max(cands, key=lambda v: 1 if v.name.lower() in ("geology", "rock", "material") else 0)

    def renderable_block_indices(self) -> List[int]:
        var = self._empty_marker_variable()
        if var is None:
            return list(range(self.metadata.n_blocks))
        empty_codes = {c for c, lbl in var.strings.items() if _is_empty_block_label(lbl)}
        if not empty_codes:
            return list(range(self.metadata.n_blocks))
        codes = self.named_code_values(var.name)
        return [i for i, code in enumerate(codes) if code not in empty_codes]

    def block_bounds(self) -> List[BlockBounds]:
        bound_vars = ["__lower_x", "__lower_y", "__lower_z",
                      "__upper_x", "__upper_y", "__upper_z"]
        if not all(self.variable(v) is not None for v in bound_vars):
            if self.metadata.is_irregular:
                raise BmfError("BMF is sub-blocked but missing explicit __lower/__upper bounds")
            return self._regular_block_bounds()
        cols = [self.numeric_values(v) for v in bound_vars]
        return [BlockBounds(lower=(cols[0][i], cols[1][i], cols[2][i]),
                            upper=(cols[3][i], cols[4][i], cols[5][i]))
                for i in range(self.metadata.n_blocks)]

    def _regular_block_bounds(self) -> List[BlockBounds]:
        dx, dy, dz = self.metadata.dims
        if dx == 0 or dy == 0 or dz == 0:
            raise BmfError("BMF has no block-bound variables or grid dimensions")
        if dx * dy * dz != self.metadata.n_blocks:
            raise BmfError("BMF regular-grid dimensions disagree with n_blocks")
        lo, up = self.metadata.lower, self.metadata.upper
        cell = ((up[0] - lo[0]) / dx, (up[1] - lo[1]) / dy, (up[2] - lo[2]) / dz)
        blocks = []
        for z in range(dz):
            for y in range(dy):
                for x in range(dx):
                    lower = (lo[0] + x * cell[0], lo[1] + y * cell[1], lo[2] + z * cell[2])
                    blocks.append(BlockBounds(lower=lower,
                                              upper=(lower[0] + cell[0], lower[1] + cell[1],
                                                     lower[2] + cell[2])))
        return blocks

    def local_to_world(self, local: Vec3) -> Vec3:
        r, o = self.rotation, self.metadata.origin
        return (o[0] + r[0][0] * local[0] + r[0][1] * local[1] + r[0][2] * local[2],
                o[1] + r[1][0] * local[0] + r[1][1] * local[1] + r[1][2] * local[2],
                o[2] + r[2][0] * local[0] + r[2][1] * local[1] + r[2][2] * local[2])

    def has_verified_rotation(self) -> bool:
        eps = 1e-6
        return abs(self.metadata.orientation[0]) < eps and abs(self.metadata.orientation[1]) < eps


def _parse_default_f64(var: BmfVariable) -> float:
    for candidate in (var.global_.strip(), var.default.strip()):
        try:
            return float(candidate)
        except ValueError:
            continue
    return 0.0


def _parse_default_code(var: BmfVariable) -> int:
    text = var.default.strip() if not var.global_.strip() else var.global_.strip()
    try:
        return int(text)
    except ValueError:
        pass
    for code, label in var.strings.items():
        if label.lower() == text.lower():
            return code
    return 0


# ── .bdf definition sidecar ─────────────────────────────────────────────────
@dataclass
class BdfSection:
    name: str
    fields: Dict[str, str] = field(default_factory=dict)


def parse_bdf(path: str) -> List[BdfSection]:
    sections: List[BdfSection] = []
    current: Optional[BdfSection] = None
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("*"):
                continue
            if line.startswith("BEGIN$DEF"):
                current = BdfSection(name=line[len("BEGIN$DEF"):].strip())
            elif line.startswith("END$DEF"):
                if current is not None:
                    sections.append(current)
                    current = None
            elif current is not None:
                if "=" in line:
                    key, value = line.split("=", 1)
                    current.fields[key.strip()] = value.strip().strip("'")
                else:
                    current.fields[line] = ""
    return sections


def parse_bmf_file(path: str) -> BmfModel:
    return BmfModel.from_path(path)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("usage: python vulcan_bmf_parser.py <file.bmf> [file.bmf ...]")
        raise SystemExit(2)
    for p in sys.argv[1:]:
        try:
            m = BmfModel.from_path(p)
            md = m.metadata
            print(f"{p}: {md.n_blocks} blocks, dims={md.dims}, "
                  f"{len(md.variables)} variables, {len(md.schemas)} schemas")
        except (OSError, BmfError) as exc:
            print(f"{p}: ERROR {exc}")
