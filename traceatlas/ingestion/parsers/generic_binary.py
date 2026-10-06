"""generic_binary - Safe handling for unknown/unparseable binary input (spec §36).

Never executes content. Produces: hashes, magic info, printable strings,
embedded-file offset scan (carving signatures), size/name metadata. The
artifact stays searchable even with no format-specific parser available.
"""
from __future__ import annotations

import re
from typing import BinaryIO

from ..confidence import Confidence
from ..errors import ErrorCode, Issue, Severity
from ..limits import IngestionLimits
from .base import BaseParser, ParsedRecord, ParserResult, RecordLocator, empty_result

_PRINTABLE = re.compile(rb"[\x20-\x7e]{5,}")

# embedded-file signature carving table (offset -> fmt) — detection only, never unpacked here
_CARVE_SIGS: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"),
    (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"), (b"%PDF", "pdf"),
    (b"OggS", "ogg"), (b"fLaC", "flac"), (b"RIFF", "riff"),
    (b"\xfd7zXZ", "xz"), (b"7z\xbc\xaf", "7z"), (b"Rar!", "rar"),
    (b"SQLite format 3", "sqlite"), (b"\xd0\xcf\x11\xe0", "ole"),
)


class GenericBinaryParser(BaseParser):
    parser_id = "binary.generic"
    formats = ("binary", "unknown")
    priority = 10        # last resort before fallback report

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        res.metadata["size"] = len(data)
        res.metadata["head_hex"] = data[:64].hex()
        strings = [m.group().decode("ascii", "replace")
                   for m in _PRINTABLE.finditer(data)]
        if len(strings) > limits.max_strings:
            strings = strings[:limits.max_strings]
            res.truncated = True
        res.metadata["string_count"] = len(strings)
        carved = []
        for sig, fmt in _CARVE_SIGS:
            off = data.find(sig, 1)     # skip position 0 (own header)
            if off > 0 and len(carved) < 50:
                carved.append({"format": fmt, "offset": off})
        res.metadata["embedded_signatures"] = carved
        res.records.append(ParsedRecord(
            raw={"strings_preview": strings[:2000],
                 "embedded_signatures": carved},
            locator=RecordLocator("byte_range", "0-EOF"),
            record_type="binary_summary"))
        res.confidence = Confidence(0.45, "generic binary survey")
        res.warnings.append(Issue(ErrorCode.UNSUPPORTED_FORMAT, Severity.WARNING,
                                  "no format-specific parser; generic extraction only"))
        res.schema = {"format": "binary", "strings": len(strings),
                      "embedded": len(carved)}
        return res
