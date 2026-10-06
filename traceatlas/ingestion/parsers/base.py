"""traceatlas.ingestion.parsers.base - Parser plugin contract (spec §7).

Every parser — built-in or SDK-supplied — subclasses BaseParser and yields
ParsedRecord objects with stable locators so provenance survives to the field
level. Parsers MUST NOT: execute content, open network sockets, write outside
a supplied scratch path, or hold whole files in memory when streaming works.
"""
from __future__ import annotations

import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Optional

from ..confidence import Confidence
from ..errors import Issue
from ..limits import IngestionLimits


@dataclass(slots=True)
class RecordLocator:
    """Stable pointer back into the source artifact (spec §13)."""
    kind: str                       # csv_cell|xlsx_cell|json_pointer|xpath|sqlite_row|...
    value: str                      # canonical locator string ("Sheet1!B7", "/records/3/name")
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "extra": self.extra}


@dataclass(slots=True)
class ParsedRecord:
    """One logical record produced by a parser."""
    raw: dict[str, Any]                          # never mutated downstream
    locator: RecordLocator
    record_type: str = "row"                     # row|message|document|packet|feature|node|edge
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EmbeddedArtifact:
    """A file discovered inside another artifact (attachment, archive member,
    OLE embedded object). The engine ingests these recursively."""
    name: str
    data: bytes | None                           # may be streamed later; small ones inline
    stream: Optional[BinaryIO] = None
    suggested_mime: Optional[str] = None
    locator: Optional[RecordLocator] = None


@dataclass(slots=True)
class ParserResult:
    artifact_id: str
    parser_id: str
    parser_version: str
    records: list[ParsedRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    embedded_artifacts: list[EmbeddedArtifact] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    errors: list[Issue] = field(default_factory=list)
    confidence: Confidence = field(default_factory=lambda: Confidence(0.0))
    schema: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors or bool(self.records)

    def to_summary(self) -> dict[str, Any]:
        return {"artifact_id": self.artifact_id, "parser_id": self.parser_id,
                "parser_version": self.parser_version,
                "record_count": len(self.records),
                "embedded_count": len(self.embedded_artifacts),
                "warning_count": len(self.warnings),
                "error_count": len(self.errors),
                "confidence": self.confidence.to_dict(),
                "truncated": self.truncated}


class BaseParser(ABC):
    """Contract required by spec §7. Registry keys on parser_id."""

    parser_id: str = "base"
    version: str = "1.0.0"
    #: formats this parser can handle (detector format tokens)
    formats: tuple[str, ...] = ()
    #: declared permissions (SDK sandbox checks these)
    needs_filesystem: bool = False
    needs_network: bool = False
    max_file_size: int = 2 * 1024**3
    #: parsers listed first win ties; generic fallbacks use low priority
    priority: int = 50

    # ---- capability declaration ------------------------------------------------
    def supported_extensions(self) -> list[str]:
        from ..extension_detector import _EXT_TO_FORMAT
        exts = [e for e, f in _EXT_TO_FORMAT.items() if f in self.formats]
        return sorted(exts)

    def supported_mime_types(self) -> list[str]:
        from ..mime_detector import _INTERNAL
        mimes = {m for e, m in _INTERNAL.items()
                 if e in self.supported_extensions()}
        return sorted(mimes)

    def supported_magic(self) -> list[str]:
        return []

    # ---- lifecycle ------------------------------------------------------------
    def detect(self, head: bytes, filename: Optional[str]) -> Confidence:
        """Optional parser-specific detection boost. Default: no opinion."""
        return Confidence(0.0, "no-opinion")

    def validate(self, stream: BinaryIO, limits: IngestionLimits) -> list[Issue]:
        """Cheap pre-parse sanity checks; returning ERROR issues aborts parse."""
        return []

    # ---- core -----------------------------------------------------------------
    @abstractmethod
    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        """Parse a seekable stream. Must leave stream position at 0 on entry."""

    def stream(self, fh: BinaryIO, *, artifact_id: str,
               limits: IngestionLimits) -> Iterator[ParsedRecord]:
        """Streaming record iterator. Default wraps parse(); override for big files."""
        res = self.parse(fh, artifact_id=artifact_id, limits=limits)
        yield from res.records

    # ---- enrichment -------------------------------------------------------------
    def extract_metadata(self, stream: BinaryIO, limits: IngestionLimits) -> dict[str, Any]:
        return {}

    def extract_embedded(self, stream: BinaryIO, limits: IngestionLimits) -> list[EmbeddedArtifact]:
        return []

    def evidence_metadata(self, result: ParserResult) -> dict[str, Any]:
        """Fields that belong on the Evidence record (chain-of-custody extras)."""
        return {"parser": self.parser_id, "parser_version": self.version}

    def health(self) -> dict[str, Any]:
        return {"parser_id": self.parser_id, "version": self.version, "ok": True}

    def close(self) -> None:
        return None

    # ---- helpers ------------------------------------------------------------------
    @staticmethod
    def read_all_limited(fh: BinaryIO, limit: int) -> bytes:
        data = fh.read(limit + 1)
        fh.seek(0)
        if len(data) > limit:
            from ..errors import ResourceLimitExceeded
            raise ResourceLimitExceeded(f"file exceeds {limit} byte parser cap")
        return data

    @staticmethod
    def iter_lines(fh: BinaryIO, max_line: int) -> Iterator[bytes]:
        """Line iterator with per-line size guard (prevents one huge line DoS)."""
        buf = b""
        while True:
            chunk = fh.read(65536)
            if not chunk:
                if buf:
                    yield buf[:max_line]
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if len(line) > max_line:
                    line = line[:max_line]
                yield line
            if len(buf) > max_line * 2:      # pathological line without newline
                cut, buf = buf[:max_line], buf[max_line:]
                yield cut


def empty_result(artifact_id: str, parser: BaseParser) -> ParserResult:
    return ParserResult(artifact_id=artifact_id, parser_id=parser.parser_id,
                        parser_version=parser.version)


def text_of(data: bytes, encoding: Optional[str] = None) -> str:
    from ..charset_detector import detect_charset
    enc = encoding or detect_charset(data[:65536]).encoding
    try:
        return data.decode(enc)
    except (UnicodeDecodeError, LookupError):
        return data.decode("latin-1", errors="replace")
