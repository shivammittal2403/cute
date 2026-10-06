"""generic_text - TXT/LOG/MD/key-value/INI/ENV/properties/RTF plain text.

Produces one record per logical unit (paragraph for notes, key/value line for
config) with line-number locators so every extracted value traces to a line.
"""
from __future__ import annotations

import re
from typing import BinaryIO, Optional

from ..confidence import Confidence
from ..limits import IngestionLimits
from .base import BaseParser, ParsedRecord, ParserResult, RecordLocator, empty_result, text_of


class TextParser(BaseParser):
    parser_id = "text.generic"
    formats = ("text", "markdown", "log")
    priority = 40

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, min(limits.max_file_bytes, self.max_file_size))
        text = text_of(data)
        res.metadata["chars"] = len(text)
        res.confidence = Confidence(0.85 if text.strip() else 0.3, "decoded text")
        lines = text.splitlines()
        res.schema = {"format": "text", "lines": len(lines)}
        para: list[tuple[int, str]] = []
        for i, ln in enumerate(lines, 1):
            if ln.strip() == "":
                if para:
                    res.records.append(_para_record(para))
                    para = []
            else:
                para.append((i, ln))
                if len(para) >= 50:
                    res.records.append(_para_record(para))
                    para = []
        if para:
            res.records.append(_para_record(para))
        return res


def _para_record(para: list[tuple[int, str]]) -> ParsedRecord:
    first, last = para[0][0], para[-1][0]
    body = "\n".join(t for _, t in para)
    return ParsedRecord(raw={"text": body, "line_start": first, "line_end": last},
                        locator=RecordLocator("text_lines", f"L{first}-L{last}"),
                        record_type="document")


_KV_SPLIT = re.compile(r"\s*[=:]\s*")


class KeyValueParser(BaseParser):
    """INI / CFG / CONF / ENV / .properties style key=value data."""
    parser_id = "text.keyvalue"
    formats = ("keyvalue",)
    priority = 60

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        text = text_of(data)
        section: Optional[str] = None
        parsed = 0
        for i, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            m = re.match(r"^\[(.+)\]$", line)
            if m:
                section = m.group(1)
                continue
            if _KV_SPLIT.search(line):
                k, v = _KV_SPLIT.split(line, 1)
                val = v.strip().strip('"').strip("'")
                res.records.append(ParsedRecord(
                    raw={"key": k.strip(), "value": val, "section": section},
                    locator=RecordLocator("text_line", f"L{i}"),
                    record_type="keyvalue"))
                parsed += 1
            else:
                res.records.append(ParsedRecord(
                    raw={"key": None, "value": line, "section": section},
                    locator=RecordLocator("text_line", f"L{i}"),
                    record_type="keyvalue"))
        res.confidence = Confidence(0.8 if parsed else 0.4, "key=value lines")
        res.schema = {"format": "keyvalue", "fields": ["key", "value", "section"]}
        return res


_RTF_CTRL = re.compile(r"\\[a-z]+-?\d* ?|[{}]|\\[^a-z]")


class RtfParser(BaseParser):
    parser_id = "text.rtf"
    formats = ("rtf",)
    priority = 60

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        text = text_of(data)
        stripped = _RTF_CTRL.sub("", text)
        stripped = re.sub(r"\\'[0-9a-fA-F]{2}", "", stripped)
        res.records.append(ParsedRecord(raw={"text": stripped.strip()},
                                        locator=RecordLocator("rtf_document", "body"),
                                        record_type="document"))
        res.metadata["char_count"] = len(stripped)
        res.confidence = Confidence(0.7 if text.startswith("{\\rtf") else 0.3,
                                    "rtf control words")
        return res
