"""generic_structured - JSON/JSONL/YAML/TOML/XML/HTML/CSV-family parsers.

All produce dict records with precise locators (JSON Pointer, XPath-ish, row).
YAML uses safe_load only — never yaml.load — so tagged objects cannot execute.
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, BinaryIO, Iterator

from ..confidence import Confidence
from ..errors import ErrorCode, Issue, Severity
from ..limits import IngestionLimits
from .base import BaseParser, ParsedRecord, ParserResult, RecordLocator, empty_result, text_of


def _esc(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


class JsonParser(BaseParser):
    parser_id = "structured.json"
    formats = ("json",)
    priority = 60

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        try:
            obj = json.loads(text_of(data))
        except json.JSONDecodeError as exc:
            res.errors.append(Issue(ErrorCode.PARSER_ERROR, Severity.ERROR,
                                    f"invalid JSON: {exc}"))
            res.confidence = Confidence(0.0, "json parse failed")
            return res
        res.confidence = Confidence(0.97, "json decoded")
        res.metadata["top_level"] = type(obj).__name__
        res.schema = {"format": "json"}
        for rec in self._walk(obj, ""):
            res.records.append(rec)
        return res

    def _walk(self, obj: Any, pointer: str) -> Iterator[ParsedRecord]:
        if isinstance(obj, dict):
            yield ParsedRecord(raw=obj,
                               locator=RecordLocator("json_pointer", pointer or "/"),
                               record_type="document")
            for k, v in obj.items():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    for i, item in enumerate(v):
                        yield from self._walk(item, f"{pointer}/{_esc(k)}/{i}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                yield from self._walk(item, f"{pointer}/{i}")
        else:
            yield ParsedRecord(raw={"value": obj},
                               locator=RecordLocator("json_pointer", pointer),
                               record_type="scalar")


class JsonlParser(BaseParser):
    parser_id = "structured.jsonl"
    formats = ("jsonl",)
    priority = 70

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        n_ok = n_bad = 0
        for i, line in enumerate(self.iter_lines(stream, limits.max_line_bytes), 1):
            s = line.decode("utf-8", errors="replace").strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                n_bad += 1
                if n_bad <= 5:
                    res.warnings.append(Issue(ErrorCode.CORRUPT_RECORD, Severity.WARNING,
                                              f"line {i} is not valid JSON"))
                continue
            raw = obj if isinstance(obj, dict) else {"value": obj}
            res.records.append(ParsedRecord(raw=raw,
                                            locator=RecordLocator("jsonl_line", f"L{i}"),
                                            record_type="row"))
            n_ok += 1
        res.confidence = Confidence(0.95 * n_ok / max(1, n_ok + n_bad), "ndjson lines")
        res.schema = {"format": "jsonl", "records": n_ok, "bad_lines": n_bad}
        return res


class YamlParser(BaseParser):
    parser_id = "structured.yaml"
    formats = ("yaml",)
    priority = 65

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        import yaml   # declared dependency; safe_load ONLY
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        try:
            docs = list(yaml.safe_load_all(text_of(data)))
        except yaml.YAMLError as exc:
            res.errors.append(Issue(ErrorCode.PARSER_ERROR, Severity.ERROR,
                                    f"invalid YAML: {str(exc)[:300]}"))
            return res
        for di, doc in enumerate(docs):
            if doc is None:
                continue
            if isinstance(doc, list):
                for ri, item in enumerate(doc):
                    raw = item if isinstance(item, dict) else {"value": item}
                    res.records.append(ParsedRecord(
                        raw=raw, locator=RecordLocator("yaml_path", f"doc{di}[{ri}]"),
                        record_type="row"))
            else:
                raw = doc if isinstance(doc, dict) else {"value": doc}
                res.records.append(ParsedRecord(
                    raw=raw, locator=RecordLocator("yaml_path", f"doc{di}"),
                    record_type="document"))
        res.confidence = Confidence(0.9, "safe_load ok")
        res.schema = {"format": "yaml", "documents": len(docs)}
        return res


class TomlParser(BaseParser):
    parser_id = "structured.toml"
    formats = ("toml",)
    priority = 65

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        import tomllib
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        try:
            obj = tomllib.loads(text_of(data))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            res.errors.append(Issue(ErrorCode.PARSER_ERROR, Severity.ERROR, str(exc)[:300]))
            return res
        flat: dict[str, Any] = {}

        def walk(d: Any, prefix: str = "") -> None:
            if isinstance(d, dict):
                for k, v in d.items():
                    walk(v, f"{prefix}.{k}" if prefix else str(k))
            elif isinstance(d, list):
                flat[prefix] = d
            else:
                flat[prefix] = d
        walk(obj)
        res.records.append(ParsedRecord(raw=flat,
                                        locator=RecordLocator("toml_document", "/"),
                                        record_type="document"))
        res.confidence = Confidence(0.9, "toml decoded")
        return res


def _local(tag: str) -> str:
    return re.sub(r"^\{.*?\}", "", tag)


class XmlParser(BaseParser):
    parser_id = "structured.xml"
    formats = ("xml",)
    priority = 55

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        try:
            root = ET.fromstring(text_of(data))
        except ET.ParseError as exc:
            res.errors.append(Issue(ErrorCode.PARSER_ERROR, Severity.ERROR,
                                    f"XML parse error: {exc}"))
            return res
        res.metadata["root"] = root.tag
        count = 0
        for path, elem in _walk_xml(root, ""):
            kids = list(elem)
            if not kids and (elem.text or "").strip():
                raw = {_local(elem.tag): elem.text.strip()}
                raw.update({f"@{k}": v for k, v in elem.attrib.items()})
                res.records.append(ParsedRecord(
                    raw=raw, locator=RecordLocator("xpath", path),
                    record_type="element"))
                count += 1
            elif kids:
                tags = [_local(c.tag) for c in kids]
                if len(tags) >= 2 and len(set(tags)) < len(tags):
                    raw2: dict[str, Any] = {_local(c.tag): _subtree(c) for c in kids}
                    raw2.update({f"@{k}": v for k, v in elem.attrib.items()})
                    res.records.append(ParsedRecord(
                        raw=raw2, locator=RecordLocator("xpath", path),
                        record_type="document"))
                    count += 1
        res.confidence = Confidence(0.9 if count else 0.5, "well-formed XML")
        res.schema = {"format": "xml", "root": _local(root.tag)}
        return res


def _walk_xml(elem: ET.Element, path: str) -> Iterator[tuple[str, ET.Element]]:
    name = _local(elem.tag)
    idx = 1
    yield (f"{path}/{name}[{idx}]", elem)
    for child in elem:
        yield from _walk_xml(child, f"{path}/{name}[{idx}]")
        idx += 1


def _subtree(e: ET.Element) -> Any:
    kids = list(e)
    if not kids:
        return (e.text or "").strip()
    return {_local(c.tag): _subtree(c) for c in kids}


class CsvDialectParser(BaseParser):
    """CSV/TSV/PSV with header detection and row+column locators."""
    parser_id = "structured.csv"
    formats = ("csv", "tsv", "psv")
    priority = 70

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        from ..schema_detector import classify_value, infer_delimiter
        res = empty_result(artifact_id, self)
        head_bytes = stream.read(262_144)
        stream.seek(0)
        head_text = text_of(head_bytes)
        delim = infer_delimiter(head_text.splitlines()[:20]) or ","
        reader = csv.reader(io.StringIO(head_text), delimiter=delim)
        rows_iter: Iterator[list[str]] = reader
        try:
            first = next(rows_iter)
        except StopIteration:
            res.confidence = Confidence(0.0, "empty")
            return res
        looks_header = len(first) > 1 and len(set(first)) == len(first) and \
            all(not any(ch.isdigit() for ch in c) or classify_value(c) == set()
                for c in first if c)
        if looks_header:
            header = [c.strip() or f"col{i}" for i, c in enumerate(first)]
            base_row = 2
        else:
            header = [f"col{i}" for i in range(len(first))]
            base_row = 1
            res.records.append(_csv_row(first, header, 1))
        total = 0
        for row in rows_iter:
            total += 1
            if total > limits.max_records_preview * 10000:
                res.truncated = True
                res.warnings.append(Issue(ErrorCode.RESOURCE_LIMIT, Severity.WARNING,
                                          "record cap reached"))
                break
            res.records.append(_csv_row(row, header, base_row + total))
        res.confidence = Confidence(0.95, "csv dialect parse")
        res.schema = {"format": "csv", "delimiter": delim, "header": header,
                      "has_header": looks_header, "rows": len(res.records)}
        return res


def _csv_row(values: list[str], header: list[str], row_no: int) -> ParsedRecord:
    raw = {h: (values[i] if i < len(values) else "") for i, h in enumerate(header)}
    return ParsedRecord(raw=raw,
                        locator=RecordLocator("csv_row", f"R{row_no}",
                                              {"columns": header}),
                        record_type="row")


_HTML_TAG = re.compile(r"<[^>]+>")
_SCRIPT_STYLE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)


class HtmlParser(BaseParser):
    parser_id = "structured.html"
    formats = ("html",)
    priority = 60

    def parse(self, stream: BinaryIO, *, artifact_id: str,
              limits: IngestionLimits) -> ParserResult:
        res = empty_result(artifact_id, self)
        data = self.read_all_limited(stream, limits.max_file_bytes)
        text = text_of(data)
        # NEVER execute JS: strip script/style entirely before text extraction
        cleaned = _SCRIPT_STYLE.sub(" ", text)
        title_m = re.search(r"<title[^>]*>(.*?)</title>", cleaned, re.S | re.I)
        body = re.sub(r"\s+", " ", _HTML_TAG.sub(" ", cleaned)).strip()
        links = re.findall(r'href=["\']([^"\']+)["\']', cleaned, re.I)
        meta = re.findall(
            r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]*content=["\']([^"\']*)["\']',
            cleaned, re.I)
        raw: dict[str, Any] = {"text": body[:1_000_000], "link_count": len(links)}
        if title_m:
            raw["title"] = _HTML_TAG.sub("", title_m.group(1)).strip()
        res.records.append(ParsedRecord(raw=raw,
                                        locator=RecordLocator("html_document", "body"),
                                        record_type="document"))
        if links:
            res.records.append(ParsedRecord(raw={"links": links[:5000]},
                                            locator=RecordLocator("html_collection", "a[href]"),
                                            record_type="collection"))
        if meta:
            res.records.append(ParsedRecord(raw=dict(meta[:500]),
                                            locator=RecordLocator("html_collection", "meta"),
                                            record_type="collection"))
        res.metadata["title"] = raw.get("title")
        res.metadata["links"] = len(links)
        res.confidence = Confidence(0.85, "html text extracted (scripts removed)")
        return res
