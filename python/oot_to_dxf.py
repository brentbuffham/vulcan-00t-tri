#!/usr/bin/env python3
"""
Vulcan .00t → 3D DXF Batch Converter
Reads Maptek Vulcan .00t triangulation files and exports 3DFACE DXF files.

Coordinate encoding fully decoded. Face connectivity partially decoded —
uses DXF sidecar files when available, otherwise exports as point cloud
with first-face only.

Author: Brent Buffham / blastingapps.com
Requires: PyQt6, ezdxf
"""

import sys
import os
import struct
import glob
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QMessageBox, QCheckBox, QGroupBox,
    QComboBox, QStatusBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QDragEnterEvent, QDropEvent

import ezdxf

# ══════════════════════════════════════════════════════════════════════
# 00t PARSER
# ══════════════════════════════════════════════════════════════════════

def is_separator(b: int) -> bool:
    """Separator bytes: low 3 bits all set and value >= 7."""
    return (b & 0x07) == 0x07 and b >= 0x07


def read_be_double(buf: bytes) -> float:
    """Read big-endian IEEE 754 double from 8 bytes."""
    return struct.unpack('>d', buf)[0]


@dataclass
class OotResult:
    """Result of parsing a .00t file."""
    filepath: str = ''
    coord_values: List[float] = field(default_factory=list)
    vertices: List[Tuple[float, float, float]] = field(default_factory=list)
    faces: List[Tuple[int, int, int]] = field(default_factory=list)
    face_vertex_indices: List[int] = field(default_factory=list)
    n_verts_header: int = 0
    n_faces_header: int = 0
    warnings: List[str] = field(default_factory=list)
    success: bool = False


def parse_oot(filepath: str) -> OotResult:
    """Parse a Vulcan .00t file and extract coordinates and face data."""
    result = OotResult(filepath=filepath)

    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
    except Exception as e:
        result.warnings.append(f"Cannot read file: {e}")
        return result

    # Validate header
    if len(raw) < 64:
        result.warnings.append("File too small")
        return result

    magic = raw[0:4]
    sig = raw[4:8]
    if magic != b'\xea\xfb\xa7\x8a' or sig != b'vulZ':
        result.warnings.append(f"Bad magic/signature: {magic.hex()}/{sig}")
        return result

    # Find data section — scan for "Created External" then "Variant\0"
    # These can be at different page offsets depending on the file's page chain
    variant_idx = raw.find(b'Variant\x00')
    if variant_idx < 0:
        # Some 00t files have data at non-standard page offsets.
        # Try scanning for the pre-coord header pattern: 20 E0 06 00 00 43
        alt_marker = bytes([0x20, 0xE0, 0x06, 0x00, 0x00, 0x43])
        alt_idx = raw.find(alt_marker)
        if alt_idx >= 0:
            data_start = alt_idx
            result.warnings.append(f"No Variant marker; using alt header at 0x{alt_idx:04X}")
        else:
            # Last resort: scan every 2048-byte page boundary for "Created External"
            ce_idx = raw.find(b'Created External')
            if ce_idx >= 0:
                # Variant should be ~20 bytes after "Created External\0"
                search_from = ce_idx + 18
                var_local = raw.find(b'Variant', search_from, search_from + 32)
                if var_local >= 0:
                    nul = raw.find(b'\x00', var_local + 7, var_local + 9)
                    data_start = (nul + 1) if nul >= 0 else (var_local + 8)
                    result.warnings.append(f"Found CE at 0x{ce_idx:04X}")
                else:
                    data_start = search_from
                    result.warnings.append(f"Found CE without Variant at 0x{ce_idx:04X}")
            else:
                result.warnings.append("No Variant marker found and no fallback matched")
                return result
    else:
        data_start = variant_idx + 8
    if data_start + 23 >= len(raw):
        result.warnings.append("Data section too short")
        return result

    d = raw[data_start:]
    result.n_verts_header = d[12]
    result.n_faces_header = d[19]

    # Find attribute block end marker
    attr_suffix = bytes([0x00, 0x05, 0x40, 0x04, 0x00, 0x0A, 0x20, 0x08, 0x07])
    attr_pos = raw.find(attr_suffix, data_start)
    if attr_pos < 0:
        attr_pos = len(raw)

    region = d[23:attr_pos - data_start]  # skip 23-byte pre-coord header

    # Find first coordinate
    coord_offset = 0
    for i in range(len(region) - 2):
        if region[i] <= 0x06 and region[i + 1] in (0x40, 0x41):
            coord_offset = i
            break

    # Find face section marker (last "20 00" before attributes)
    face_marker_pos = -1
    search_region = raw[data_start + 23 + coord_offset:attr_pos]
    # Search backwards for 20 00
    for i in range(len(search_region) - 2, 0, -1):
        if search_region[i] == 0x20 and search_region[i + 1] == 0x00:
            face_marker_pos = i
            break

    coord_end = len(region)
    if face_marker_pos > 0:
        coord_end = coord_offset + face_marker_pos

    # ── Decode coordinates ──
    pos = coord_offset
    prev = [0] * 8

    while pos < coord_end:
        if pos >= len(region):
            break
        b = region[pos]

        if b <= 0x06:
            count = b
            n_bytes = count + 1
            if pos + 1 + n_bytes > len(region):
                break

            stored = list(region[pos + 1:pos + 1 + n_bytes])

            if stored and stored[0] in (0x40, 0x41, 0xC0, 0xC1):
                r = stored + [0] * (8 - n_bytes)
            else:
                r = [prev[0]] + stored + list(prev[n_bytes + 1:8])

            r = (r + [0] * 8)[:8]
            val = read_be_double(bytes(r))
            result.coord_values.append(val)
            prev = r
            pos += 1 + n_bytes

        elif is_separator(b):
            pos += 1
        elif pos + 1 < len(region):
            pos += 2
        else:
            break

    # ── Decode face vertex indices ──
    if face_marker_pos > 0:
        face_start = coord_offset + face_marker_pos + 2  # skip the "20 00"
        fpos = face_start
        while fpos < len(region):
            b = region[fpos]
            if b <= 0x06:
                count = b
                n_bytes = count + 1
                if fpos + 1 + n_bytes > len(region):
                    break
                for i in range(n_bytes):
                    v = region[fpos + 1 + i]
                    if 1 <= v <= result.n_verts_header:
                        result.face_vertex_indices.append(v)
                fpos += 1 + n_bytes
            elif is_separator(b):
                fpos += 1
            elif fpos + 1 < len(region):
                fpos += 2
            else:
                break

    # ── Build vertices from coordinate values ──
    if len(result.coord_values) >= 3:
        cx, cy, cz = result.coord_values[0], result.coord_values[1], result.coord_values[2]
        result.vertices.append((cx, cy, cz))

        for i in range(3, len(result.coord_values)):
            v = result.coord_values[i]
            dx = abs(v - cx)
            dy = abs(v - cy)
            dz = abs(v - cz)
            if dx <= dy and dx <= dz:
                cx = v
            elif dy <= dz:
                cy = v
            else:
                cz = v
            result.vertices.append((cx, cy, cz))

    if len(result.coord_values) == 0:
        result.warnings.append("No coordinates decoded (file may use 7-8 byte coords)")
    else:
        result.success = True

    return result


def try_load_sidecar_dxf(oot_path: str) -> Optional[List[Tuple[int, int, int]]]:
    """Try to load face connectivity from a matching .dxf sidecar file."""
    base = Path(oot_path)
    candidates = [
        base.with_suffix('.dxf'),
        base.with_suffix('.DXF'),
        Path(str(base).replace('.00t', '.dxf')),
        Path(str(base).replace('.00t', '.DXF')),
    ]

    for dxf_path in candidates:
        if dxf_path.exists():
            try:
                doc = ezdxf.readfile(str(dxf_path))
                msp = doc.modelspace()
                vm = {}
                vl = []
                fl = []
                for e in msp:
                    if e.dxftype() == '3DFACE':
                        tri = []
                        for p in [e.dxf.vtx0, e.dxf.vtx1, e.dxf.vtx2]:
                            key = (round(p[0], 6), round(p[1], 6), round(p[2], 6))
                            if key not in vm:
                                vm[key] = len(vl)
                                vl.append(key)
                            tri.append(vm[key])
                        fl.append(tuple(tri))
                return fl
            except Exception:
                continue
    return None


def write_dxf(vertices, faces, output_path: str):
    """Write a 3DFACE DXF file."""
    doc = ezdxf.new('R2010')
    msp = doc.modelspace()

    for f in faces:
        if max(f) < len(vertices):
            v0 = vertices[f[0]]
            v1 = vertices[f[1]]
            v2 = vertices[f[2]]
            msp.add_3dface([v0, v1, v2, v2])  # 4th point = 3rd for triangle

    doc.saveas(output_path)


def write_point_cloud_dxf(vertices, output_path: str):
    """Write vertices as POINT entities in a DXF."""
    doc = ezdxf.new('R2010')
    msp = doc.modelspace()

    for v in vertices:
        msp.add_point(v)

    doc.saveas(output_path)


# ══════════════════════════════════════════════════════════════════════
# CONVERTER THREAD
# ══════════════════════════════════════════════════════════════════════

class ConvertWorker(QThread):
    progress = pyqtSignal(int, int, str)  # current, total, message
    file_done = pyqtSignal(str, bool, str)  # filepath, success, message
    all_done = pyqtSignal(int, int)  # success_count, total

    def __init__(self, files, output_dir, use_sidecar, export_mode):
        super().__init__()
        self.files = files
        self.output_dir = output_dir
        self.use_sidecar = use_sidecar
        self.export_mode = export_mode  # '3dface', 'points', 'csv'

    def run(self):
        success = 0
        for i, filepath in enumerate(self.files):
            name = Path(filepath).stem
            self.progress.emit(i, len(self.files), f"Processing {name}...")

            result = parse_oot(filepath)

            if not result.success:
                msg = '; '.join(result.warnings) or 'Unknown error'
                self.file_done.emit(filepath, False, msg)
                continue

            # Try sidecar DXF for face connectivity
            faces = None
            if self.use_sidecar:
                faces = try_load_sidecar_dxf(filepath)

            # Determine output
            out_name = name + '_export'
            out_path = os.path.join(self.output_dir, out_name)

            try:
                if self.export_mode == '3dface' and faces:
                    write_dxf(result.vertices, faces, out_path + '.dxf')
                    msg = f"{len(result.vertices)} verts, {len(faces)} faces → DXF"
                    success += 1
                elif self.export_mode == '3dface' and not faces:
                    # No face data — export as points
                    write_point_cloud_dxf(result.vertices, out_path + '_points.dxf')
                    msg = f"{len(result.vertices)} verts (no faces, exported as points)"
                    success += 1
                elif self.export_mode == 'points':
                    write_point_cloud_dxf(result.vertices, out_path + '_points.dxf')
                    msg = f"{len(result.vertices)} points → DXF"
                    success += 1
                elif self.export_mode == 'csv':
                    import csv
                    with open(out_path + '_vertices.csv', 'w', newline='') as f:
                        w = csv.writer(f)
                        w.writerow(['Index', 'X', 'Y', 'Z'])
                        for j, v in enumerate(result.vertices):
                            w.writerow([j, f'{v[0]:.6f}', f'{v[1]:.6f}', f'{v[2]:.6f}'])
                    msg = f"{len(result.vertices)} verts → CSV"
                    success += 1
                else:
                    msg = "No export mode selected"

                self.file_done.emit(filepath, True, msg)

            except Exception as e:
                self.file_done.emit(filepath, False, f"Export error: {e}")

        self.progress.emit(len(self.files), len(self.files), "Done")
        self.all_done.emit(success, len(self.files))


# ══════════════════════════════════════════════════════════════════════
# GUI
# ══════════════════════════════════════════════════════════════════════

STYLESHEET = """
QMainWindow { background: #1e1e2e; }
QWidget { background: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', 'Consolas', monospace; font-size: 10pt; }
QGroupBox { border: 1px solid #313244; border-radius: 6px; margin-top: 10px; padding-top: 16px; font-weight: bold; color: #f38ba8; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
QTableWidget { background: #181825; alternate-background-color: #1e1e2e; gridline-color: #313244; border: 1px solid #313244; border-radius: 4px; selection-background-color: #313244; }
QTableWidget::item { padding: 3px 8px; }
QHeaderView::section { background: #11111b; color: #a6adc8; padding: 6px 10px; border: none; border-bottom: 1px solid #313244; border-right: 1px solid #313244; font-size: 9pt; }
QPushButton { background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 6px; padding: 8px 20px; font-weight: bold; font-size: 10pt; }
QPushButton:hover { background: #45475a; border-color: #89b4fa; color: #89b4fa; }
QPushButton:disabled { background: #1e1e2e; color: #45475a; border-color: #313244; }
QPushButton#primary { background: #f38ba8; color: #1e1e2e; border: none; font-size: 11pt; }
QPushButton#primary:hover { background: #f5a0b8; }
QPushButton#primary:disabled { background: #45475a; color: #6c7086; }
QPushButton#add { background: #89b4fa; color: #1e1e2e; border: none; }
QPushButton#add:hover { background: #a0c4ff; }
QPushButton#success { background: #a6e3a1; color: #1e1e2e; border: none; }
QPushButton#success:hover { background: #b8f0b3; }
QLabel#title { font-size: 16pt; font-weight: bold; color: #f38ba8; padding: 8px 0; }
QLabel#subtitle { font-size: 9pt; color: #6c7086; }
QComboBox { background: #313244; color: #cdd6f4; border: 1px solid #45475a; border-radius: 4px; padding: 4px 8px; }
QComboBox:hover { border-color: #89b4fa; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; selection-background-color: #313244; border: 1px solid #45475a; }
QCheckBox { spacing: 6px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #45475a; border-radius: 3px; background: #313244; }
QCheckBox::indicator:checked { background: #89b4fa; border-color: #89b4fa; }
QProgressBar { background: #313244; border: none; border-radius: 3px; height: 6px; }
QProgressBar::chunk { background: #89b4fa; border-radius: 3px; }
QStatusBar { background: #11111b; color: #6c7086; border-top: 1px solid #313244; }
"""

COL_OK = QColor("#a6e3a1")
COL_FAIL = QColor("#f38ba8")
COL_WAIT = QColor("#6c7086")
COL_D = QColor("#cdd6f4")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vulcan .00t → DXF Converter — blastingapps.com")
        self.setMinimumSize(800, 500)
        self.resize(900, 600)
        self.setAcceptDrops(True)
        self.files = []
        self.worker = None
        self._build_ui()
        self.statusBar().showMessage("Drag & drop .00t files or click Add Files")

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 12, 16, 8)
        layout.setSpacing(8)

        # Title
        title = QLabel("Vulcan .00t → DXF Converter")
        title.setObjectName("title")
        layout.addWidget(title)
        sub = QLabel("Batch convert Maptek Vulcan triangulations to 3DFACE DXF files")
        sub.setObjectName("subtitle")
        layout.addWidget(sub)

        # File list
        file_group = QGroupBox("Input Files")
        fg_layout = QVBoxLayout(file_group)

        btn_row = QHBoxLayout()
        self.btn_add = QPushButton("Add Files")
        self.btn_add.setObjectName("add")
        self.btn_add.clicked.connect(self.add_files)
        btn_row.addWidget(self.btn_add)

        self.btn_add_dir = QPushButton("Add Folder")
        self.btn_add_dir.clicked.connect(self.add_folder)
        btn_row.addWidget(self.btn_add_dir)

        btn_row.addStretch()

        self.btn_clear = QPushButton("Clear All")
        self.btn_clear.clicked.connect(self.clear_files)
        btn_row.addWidget(self.btn_clear)
        fg_layout.addLayout(btn_row)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(['File', 'Size', 'Status', 'Details'])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(24)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        fg_layout.addWidget(self.table)
        layout.addWidget(file_group)

        # Options
        opt_group = QGroupBox("Export Options")
        opt_layout = QHBoxLayout(opt_group)

        opt_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems([
            "3DFACE DXF (with sidecar faces)",
            "Point Cloud DXF",
            "Vertex CSV",
        ])
        opt_layout.addWidget(self.format_combo)

        opt_layout.addSpacing(20)
        self.chk_sidecar = QCheckBox("Use .dxf sidecar for faces")
        self.chk_sidecar.setChecked(True)
        self.chk_sidecar.setToolTip("Look for a matching .dxf file to get face connectivity")
        opt_layout.addWidget(self.chk_sidecar)

        opt_layout.addStretch()
        layout.addWidget(opt_group)

        # Output + Convert
        out_row = QHBoxLayout()
        out_row.addWidget(QLabel("Output folder:"))
        self.lbl_output = QLabel("(same as input)")
        self.lbl_output.setStyleSheet("color: #89b4fa;")
        out_row.addWidget(self.lbl_output)
        self.btn_output = QPushButton("Change...")
        self.btn_output.clicked.connect(self.choose_output)
        out_row.addWidget(self.btn_output)
        out_row.addStretch()

        self.btn_convert = QPushButton("Convert All")
        self.btn_convert.setObjectName("primary")
        self.btn_convert.clicked.connect(self.convert)
        self.btn_convert.setEnabled(False)
        out_row.addWidget(self.btn_convert)
        layout.addLayout(out_row)

        # Progress
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)

        self.output_dir = None

    # ── Drag & Drop ──
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        paths = []
        for url in event.mimeData().urls():
            p = url.toLocalFile()
            if p.lower().endswith('.00t'):
                paths.append(p)
            elif os.path.isdir(p):
                paths.extend(glob.glob(os.path.join(p, '*.00t')))
                paths.extend(glob.glob(os.path.join(p, '*.00T')))
        self._add_paths(paths)

    # ── File management ──
    def add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select .00t Files", "",
            "Vulcan Triangulations (*.00t *.00T);;All Files (*)")
        self._add_paths(paths)

    def add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select Folder")
        if d:
            paths = glob.glob(os.path.join(d, '*.00t'))
            paths.extend(glob.glob(os.path.join(d, '*.00T')))
            paths.extend(glob.glob(os.path.join(d, '**', '*.00t'), recursive=True))
            self._add_paths(paths)

    def _add_paths(self, paths):
        existing = {f['path'] for f in self.files}
        for p in paths:
            p = os.path.normpath(p)
            if p not in existing:
                size = os.path.getsize(p)
                self.files.append({'path': p, 'size': size, 'status': 'Pending', 'detail': ''})
                existing.add(p)
        self._refresh_table()
        self.btn_convert.setEnabled(len(self.files) > 0)
        self.statusBar().showMessage(f"{len(self.files)} file(s) queued")

    def clear_files(self):
        self.files.clear()
        self._refresh_table()
        self.btn_convert.setEnabled(False)
        self.statusBar().showMessage("Cleared")

    def _refresh_table(self):
        self.table.setRowCount(len(self.files))
        for i, f in enumerate(self.files):
            name = Path(f['path']).name
            size_kb = f['size'] / 1024
            status = f['status']

            self.table.setItem(i, 0, self._item(name, COL_D))
            self.table.setItem(i, 1, self._item(f"{size_kb:.1f} KB", COL_D, True))

            scol = COL_WAIT
            if status == 'OK': scol = COL_OK
            elif status == 'FAIL': scol = COL_FAIL
            self.table.setItem(i, 2, self._item(status, scol))
            self.table.setItem(i, 3, self._item(f.get('detail', ''), COL_D))

    def _item(self, text, color, right=False):
        item = QTableWidgetItem(str(text))
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        item.setForeground(color)
        if right:
            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return item

    def choose_output(self):
        d = QFileDialog.getExistingDirectory(self, "Output Folder")
        if d:
            self.output_dir = d
            self.lbl_output.setText(d)

    # ── Convert ──
    def convert(self):
        if not self.files:
            return

        fmt_idx = self.format_combo.currentIndex()
        mode = ['3dface', 'points', 'csv'][fmt_idx]

        # Reset statuses
        for f in self.files:
            f['status'] = 'Pending'
            f['detail'] = ''
        self._refresh_table()

        self.progress.setVisible(True)
        self.progress.setMaximum(len(self.files))
        self.progress.setValue(0)
        self.btn_convert.setEnabled(False)
        self.btn_add.setEnabled(False)

        paths = [f['path'] for f in self.files]

        # Determine output dirs per file
        if self.output_dir:
            out_dir = self.output_dir
        else:
            out_dir = None  # use same dir as input

        self.worker = ConvertWorker(
            paths,
            out_dir or os.path.dirname(paths[0]),
            self.chk_sidecar.isChecked(),
            mode
        )
        # Override output per file if no global dir
        self.worker._per_file_dir = (out_dir is None)
        if out_dir is None:
            # Monkey-patch to use per-file dirs
            orig_run = self.worker.run

            def patched_run():
                success = 0
                for i, filepath in enumerate(self.worker.files):
                    name = Path(filepath).stem
                    self.worker.progress.emit(i, len(self.worker.files), f"Processing {name}...")
                    file_out_dir = os.path.dirname(filepath)

                    result = parse_oot(filepath)
                    if not result.success:
                        msg = '; '.join(result.warnings) or 'Unknown error'
                        self.worker.file_done.emit(filepath, False, msg)
                        continue

                    faces = None
                    if self.worker.use_sidecar:
                        faces = try_load_sidecar_dxf(filepath)

                    out_name = name + '_export'
                    out_path = os.path.join(file_out_dir, out_name)

                    try:
                        if self.worker.export_mode == '3dface' and faces:
                            write_dxf(result.vertices, faces, out_path + '.dxf')
                            msg = f"{len(result.vertices)} verts, {len(faces)} faces → DXF"
                            success += 1
                        elif self.worker.export_mode == '3dface' and not faces:
                            write_point_cloud_dxf(result.vertices, out_path + '_points.dxf')
                            msg = f"{len(result.vertices)} verts (no sidecar, points only)"
                            success += 1
                        elif self.worker.export_mode == 'points':
                            write_point_cloud_dxf(result.vertices, out_path + '_points.dxf')
                            msg = f"{len(result.vertices)} points → DXF"
                            success += 1
                        elif self.worker.export_mode == 'csv':
                            import csv
                            with open(out_path + '_vertices.csv', 'w', newline='') as f:
                                w = csv.writer(f)
                                w.writerow(['Index', 'X', 'Y', 'Z'])
                                for j, v in enumerate(result.vertices):
                                    w.writerow([j, f'{v[0]:.6f}', f'{v[1]:.6f}', f'{v[2]:.6f}'])
                            msg = f"{len(result.vertices)} verts → CSV"
                            success += 1
                        else:
                            msg = "No export"
                        self.worker.file_done.emit(filepath, True, msg)
                    except Exception as e:
                        self.worker.file_done.emit(filepath, False, f"Export error: {e}")

                self.worker.progress.emit(len(self.worker.files), len(self.worker.files), "Done")
                self.worker.all_done.emit(success, len(self.worker.files))

            self.worker.run = patched_run

        self.worker.progress.connect(self._on_progress)
        self.worker.file_done.connect(self._on_file_done)
        self.worker.all_done.connect(self._on_all_done)
        self.worker.start()

    def _on_progress(self, current, total, msg):
        self.progress.setValue(current)
        self.statusBar().showMessage(msg)

    def _on_file_done(self, filepath, success, msg):
        for f in self.files:
            if f['path'] == filepath:
                f['status'] = 'OK' if success else 'FAIL'
                f['detail'] = msg
                break
        self._refresh_table()

    def _on_all_done(self, success, total):
        self.progress.setVisible(False)
        self.btn_convert.setEnabled(True)
        self.btn_add.setEnabled(True)
        self.statusBar().showMessage(f"Done: {success}/{total} files converted successfully")
        QMessageBox.information(self, "Conversion Complete",
                                f"Successfully converted {success} of {total} files.")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
