"""traceatlas.ingestion.container_detector - Container-level refinements.

Distinguishes formats that share a base magic: ZIP-family (docx/xlsx/pptx/epub/
kmz/wacz/odt/ods/odp all start PK\x03\x04), SQLite-family (sqlite/gpkg/mbtiles),
and OLE-family (doc/xls/ppt/mdb). Uses cheap directory-entry inspection rather
than full parsing.
"""
from __future__ import annotations

import io
import sqlite3
import zipfile
from typing import Optional


def refine_zip_format(data: bytes) -> Optional[str]:
    """Inspect ZIP entry names to identify OOXML/ODF/EPUB/KMZ/WACZ variants."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    names = set(zf.namelist())
    if "mimetype" in names:
        try:
            mt = zf.read("mimetype")[:64].decode("ascii", "replace").strip()
        except Exception:
            mt = ""
        if mt.startswith("application/epub"):
            return "epub"
        if mt.startswith("application/vnd.oasis.opendocument.text"):
            return "odt"
        if mt.startswith("application/vnd.oasis.opendocument.spreadsheet"):
            return "ods"
        if mt.startswith("application/vnd.oasis.opendocument.presentation"):
            return "odp"
    if any(n.startswith("word/") for n in names):
        return "docx"
    if any(n.startswith("xl/") for n in names):
        if any(n == "xl/vbaProject.bin" for n in names):
            return "xlsm"          # macros present: parse data, never execute
        return "xlsx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    if any(n.lower().endswith(".kml") for n in names) and \
            any(n.lower().endswith((".png", ".dae")) or n == "res/" for n in names):
        return "kmz"
    if "datapackage.json" in names or any(n.endswith(".warc.gz") for n in names):
        return "wacz"
    return None


def refine_sqlite_format(path_or_head: bytes) -> Optional[str]:
    """Open candidate sqlite in-memory read-only and probe gpkg/mbtiles tables."""
    if not path_or_head.startswith(b"SQLite format 3\x00"):
        return None
    try:
        con = sqlite3.connect("file:memdb_probe?mode=memory&cache=shared", uri=True)
        con.executescript  # noqa: B018 (attribute check only)
        cur = con.cursor()
        con.close()
    except sqlite3.Error:
        pass
    # byte-level probe: table-name markers appear literally in sqlite headers pages
    blob = path_or_head[:65536]
    if b"gpkg_contents" in blob:
        return "gpkg"
    if b"metadata" in blob and b"tiles" in blob:
        return "mbtiles"
    return "sqlite"


def refine_ole_format(data: bytes) -> Optional[str]:
    """OLE compound file: locate stream names to split doc/xls/ppt/mdb."""
    blob = data[:65536]
    # stream directory entries are UTF-16LE names inside the CFB
    probes = {
        "WordDocument": "doc",
        "Workbook": "xls",
        "Book": "xls",
        "PowerPoint Document": "ppt",
        "Access": "mdb",
    }
    for needle, fmt in probes.items():
        encoded = needle.encode("utf-16-le")
        if encoded in blob:
            return fmt
    return "ole"
