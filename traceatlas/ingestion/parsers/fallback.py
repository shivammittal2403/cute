"""fallback - Final safety net: always returns *something* honest.

If nothing else matched, we still preserve the artifact and report the exact
limitation plus a parser-development requirement (spec §50). Never invents
parsed content.
"""
from __future__ import annotations

from typing import BinaryIO

from ..confidence import Confidence
from ..errors import ErrorCode, Issue, Severity
from ..limits import IngestionLimits
from .base import BaseParser, ParsedRecord, ParserResult, RecordLocator, empty_result


class FallbackParser(BaseParser):
    parser_id = "fallback.none"
    formats = ()          # explicitly not routed by format; engine invokes directly
    priority = 0

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        head = stream.read(4096)
        stream.seek(0)
        res.records.append(ParsedRecord(
            raw={"status": "UNSUPPORTED_FORMAT", "head_hex": head.hex()},
            locator=RecordLocator("byte_range", "0-4096"),
            record_type="placeholder"))
        res.errors.append(Issue(ErrorCode.NO_PARSER, Severity.ERROR,
                                "No parser available; artifact preserved unmodified"))
        res.metadata["parser_development_requirement"] = {
            "summary": "Custom parser plugin required for this format",
            "sdk_path": "traceatlas/ingestion/sdk",
            "detection_evidence": {"head_hex": head[:64].hex()},
        }
        res.confidence = Confidence(0.0, "unsupported")
        return res
