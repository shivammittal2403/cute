"""traceatlas/ingestion/schema_detector - Structural schema inference.

Given decoded text (or a parsed object), infer: delimiter, header row, column
names, types, nullability, uniqueness, candidate keys and semantic field roles
(timestamps, geo, identity, indicators...). Inference is a PROPOSAL with
confidence per column — never treated as ground truth downstream.
"""
from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

# --------------------------------------------------------------------------- types

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
URL_RE = re.compile(r"^https?://", re.I)
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
HASH_RE = {16: "md5", 32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
BTC_RE = re.compile(r"^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$")
ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
CART_RE = re.compile(r"^-?\d{1,3}\.\d+$")
DATEISH_RES = (
    re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"),
    re.compile(r"^\d{2}/\d{2}/\d{4}$"),
    re.compile(r"^\d{2}-\d{2}-\d{4}$"),
    re.compile(r"^\d{10}$"),                      # epoch seconds
    re.compile(r"^\d{13}$"),                      # epoch millis
)


def classify_value(v: str) -> set[str]:
    """Return the set of semantic type tags consistent with one sample value."""
    v = v.strip()
    if not v:
        return {"empty"}
    tags: set[str] = set()
    low = v.lower()
    if v.isdigit():
        tags.add("integer")
        if len(v) == 10 and v[:2] in ("15", "16", "17", "18", "19", "20", "21"):
            tags.add("timestamp_epoch")
        if len(v) == 13 and v[:2] in ("15", "16", "17", "18", "19", "20", "21"):
            tags.add("timestamp_epoch_ms")
        if 1 <= int(v[0]) <= 5 and len(v) >= 7:
            tags.add("maybe_phone")
    elif re.match(r"^-?\d+(\.\d+)?$", v):
        tags.add("float")
        if CART_RE.match(v):
            tags.add("maybe_coordinate")
    for rx in DATEISH_RES:
        if rx.match(v):
            tags.add("timestamp")
            break
    if EMAIL_RE.match(v):
        tags.add("email")
    elif URL_RE.match(v):
        tags.add("url")
    elif DOMAIN_RE.match(v) and "." in v and not v.replace(".", "").isdigit():
        tags.add("domain")
    elif IPV4_RE.match(v) and all(0 <= int(o) <= 255 for o in v.split(".")):
        tags.add("ip_address")
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HASH_RE:
        tags.add(f"hash_{HASH_RE[len(v)]}")
        tags.add("hash")
    if BTC_RE.match(v):
        tags.add("crypto_address")
    if ETH_RE.match(v):
        tags.add("crypto_address")
        tags.add("eth_address")
    if TX_RE.match(v) and not any(c.isupper() for c in v[2:] if v.startswith("0x")):
        pass  # too generic alone; requires context
    if CVE_RE.match(v):
        tags.add("cve")
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.\-]{1,30}", v) and not any(c.isdigit() for c in v[:2]):
        tags.add("identifier_like")
    if re.search(r"[^\x00-\x7F]", v):
        tags.add("non_ascii")
    _ = low
    return tags


@dataclass(frozen=True, slots=True)
class ColumnProposal:
    name: str
    inferred_type: str                    # integer|float|string|boolean|timestamp|...
    semantic_role: Optional[str]          # email|phone|ip_address|coordinate|...
    nullable: bool
    unique_ratio: float
    confidence: float
    sample_values: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.inferred_type,
                "semantic_role": self.semantic_role, "nullable": self.nullable,
                "unique_ratio": round(self.unique_ratio, 3),
                "confidence": round(self.confidence, 3),
                "sample_values": list(self.sample_values)}


@dataclass(frozen=True, slots=True)
class SchemaProposal:
    format: str                           # csv|json|xml|table|document|binary
    columns: tuple[ColumnProposal, ...] = ()
    delimiter: Optional[str] = None
    has_header: Optional[bool] = None
    candidate_primary_keys: tuple[str, ...] = ()
    foreign_key_candidates: tuple[tuple[str, str], ...] = ()
    record_count_estimate: Optional[int] = None
    confidence: float = 0.0
    unresolved_fields: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"format": self.format, "delimiter": self.delimiter,
                "has_header": self.has_header,
                "columns": [c.to_dict() for c in self.columns],
                "candidate_primary_keys": list(self.candidate_primary_keys),
                "foreign_key_candidates": [[a, b] for a, b in self.foreign_key_candidates],
                "record_count_estimate": self.record_count_estimate,
                "confidence": round(self.confidence, 3),
                "unresolved_fields": list(self.unresolved_fields)}


_ROLE_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(e[-_]?mail|email_addr)", re.I), "email"),
    (re.compile(r"(phone|mobile|tel(_?no)?)", re.I), "phone"),
    (re.compile(r"^(ip|src_ip|dst_ip|source_ip|dest_ip|client_ip|server_ip)$", re.I), "ip_address"),
    (re.compile(r"(lat(itude)?|y_coord|geo_lat)", re.I), "latitude"),
    (re.compile(r"(lon(gitude)?|x_coord|geo_lon)", re.I), "longitude"),
    (re.compile(r"(url|href|link|uri)", re.I), "url"),
    (re.compile(r"(domain|host(name)?)", re.I), "domain"),
    (re.compile(r"(hash|md5|sha1|sha256|checksum)", re.I), "hash"),
    (re.compile(r"(wallet|address_btc|btc_addr|eth_addr)", re.I), "crypto_address"),
    (re.compile(r"(user(name|_id)|handle|nick)", re.I), "username"),
    (re.compile(r"(first[-_ ]?name|given)", re.I), "person_first_name"),
    (re.compile(r"(last[-_ ]?name|surname|family)", re.I), "person_last_name"),
    (re.compile(r"(full[-_ ]?name|display[-_ ]?name|^name$|contact)", re.I), "person_name"),
    (re.compile(r"(company|org(anization)?|employer|^firm)", re.I), "organization"),
    (re.compile(r"^(time|date|timestamp|seen_at|created|updated|_at$|ts)", re.I), "timestamp"),
    (re.compile(r"(cve|vuln)", re.I), "cve"),
    (re.compile(r"(country|city|location|address|geo)", re.I), "location"),
    (re.compile(r"(file_hash|filename|path)", re.I), "file"),
    (re.compile(r"(amount|price|total|currency)", re.I), "currency"),
)


def _role_from_name(col: str) -> Optional[str]:
    for rx, role in _ROLE_HINTS:
        if rx.search(col):
            return role
    return None


def _majority(values: list[set[str]]) -> tuple[str, float]:
    if not values:
        return ("string", 0.0)
    counts: dict[str, int] = {}
    total = 0
    for vs in values:
        for t in vs:
            counts[t] = counts.get(t, 0) + 1
        total += 1
    if not counts:
        return ("string", 0.0)
    best_tag, n = max(counts.items(), key=lambda kv: kv[1])
    return best_tag, n / max(1, total)


def infer_delimiter(sample_lines: list[str]) -> Optional[str]:
    """Sniff CSV-family delimiter from header-ish lines."""
    joined = "\n".join(sample_lines[:20])
    try:
        dialect = csv.Sniffer().sniff(joined, delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        pass
    counts = {d: sum(line.count(d) for line in sample_lines[:20])
              for d in ",;\t|"}
    if not sample_lines:
        return None
    best = max(counts, key=lambda k: counts[k])
    return best if counts[best] >= len(sample_lines[:1]) else None


def propose_tabular(rows: list[list[str]], delimiter: Optional[str] = None,
                    fmt: str = "csv") -> SchemaProposal:
    """Infer schema proposal from raw string rows (row 0 may be header)."""
    if not rows:
        return SchemaProposal(format=fmt, confidence=0.0)
    width = max(len(r) for r in rows)
    # header heuristic: first row is all non-numeric strings & unique-ish
    first = rows[0]
    looks_header = (
        len(first) > 1
        and all(not classify_value(c or "x").isdisjoint({"identifier_like", "string"})
                or classify_value(c or "") == set() or not any(ch.isdigit() for ch in c)
                for c in first)
        and len(set(first)) == len(first)
    )
    header = [c.strip() or f"col{i}" for i, c in enumerate(first)] if looks_header \
        else [f"col{i}" for i in range(width)]
    body = rows[1:] if looks_header else rows

    cols: list[ColumnProposal] = []
    unresolved: list[str] = []
    for i, name in enumerate(header):
        vals = [(r[i].strip() if i < len(r) else "") for r in body]
        nonempty = [v for v in vals if v != ""]
        tags = [classify_value(v) for v in nonempty[:200]]
        tag_union_counts: dict[str, int] = {}
        for ts in tags:
            for t in ts:
                tag_union_counts[t] = tag_union_counts.get(t, 0) + 1
        n = max(1, len(tags))
        # choose most specific consistent semantic tag first
        semantic_priority = ["email", "ip_address", "crypto_address", "hash_sha256",
                             "hash_md5", "hash_sha1", "cve", "url", "domain",
                             "timestamp", "timestamp_epoch", "timestamp_epoch_ms",
                             "float", "integer", "identifier_like"]
        chosen_sem = None
        for cand in semantic_priority:
            if tag_union_counts.get(cand, 0) >= 0.8 * n:
                chosen_sem = cand
                break
        name_role = _role_from_name(name)
        role = name_role or chosen_sem
        # cross-check: name says email but values don't look like emails → lower conf
        conf = 0.5
        if chosen_sem:
            conf = min(0.95, 0.5 + tag_union_counts[chosen_sem] / n * 0.45)
        if name_role and chosen_sem:
            agree = (name_role in ("email", "ip_address", "url", "domain", "hash",
                                   "crypto_address", "cve", "phone", "timestamp")
                     and (chosen_sem.startswith(name_role) or name_role.rstrip('s') in chosen_sem
                          or (name_role == "hash" and chosen_sem.startswith("hash"))
                          or (name_role == "timestamp" and chosen_sem.startswith("timestamp"))))
            conf = min(0.98, conf + (0.2 if agree else -0.25))
        uniq = len(set(nonempty)) / max(1, len(nonempty)) if nonempty else 0.0
        nullable = any(v == "" for v in vals)
        itype = chosen_sem if chosen_sem in ("integer", "float") else (
            "timestamp" if chosen_sem and chosen_sem.startswith("timestamp") else "string")
        if role is None and chosen_sem is None:
            unresolved.append(name)
        cols.append(ColumnProposal(name=name, inferred_type=itype, semantic_role=role,
                                   nullable=nullable, unique_ratio=uniq,
                                   confidence=conf,
                                   sample_values=tuple(nonempty[:3])))
    pks = tuple(c.name for c in cols if c.unique_ratio >= 0.99 and not c.nullable)
    fks: list[tuple[str, str]] = []
    names = {c.name.lower() for c in cols}
    for c in cols:
        m = re.match(r"(.+)[-_]?id$", c.name, re.I)
        if m and m.group(1).lower() in names:
            fks.append((c.name, m.group(1)))
    avg_conf = sum(c.confidence for c in cols) / max(1, len(cols))
    return SchemaProposal(format=fmt, columns=tuple(cols), delimiter=delimiter,
                          has_header=looks_header, candidate_primary_keys=pks,
                          foreign_key_candidates=tuple(fks),
                          record_count_estimate=len(body),
                          confidence=avg_conf, unresolved_fields=tuple(unresolved))


def propose_csv(text: str, max_rows: int = 200) -> SchemaProposal:
    delim = infer_delimiter(text.splitlines()[:20]) or ","
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    rows = []
    for i, row in enumerate(reader):
        if i >= max_rows:
            break
        rows.append(row)
    return propose_tabular(rows, delimiter=delim)


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(_flatten(v, key))
            else:
                out[key] = v
    elif isinstance(obj, list):
        out[prefix or "$"] = obj
    else:
        out[prefix or "$"] = obj
    return out


def propose_json(data: Any) -> SchemaProposal:
    """Schema proposal for JSON documents / arrays of records."""
    records: list[Any] = []
    fmt = "json"
    if isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]
    elif isinstance(data, dict):
        # STIX bundle style: find largest array-of-dicts under any key
        best_key, best = None, []
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict) and len(v) > len(best):
                best_key, best = k, v
        if best_key:
            records = best
            fmt = "json_array_field"
        else:
            records = [data]
    flat = [_flatten(r) for r in records[:500]]
    all_keys: list[str] = []
    for f in flat:
        for k in f:
            if k not in all_keys:
                all_keys.append(k)
    rows = [[("" if f.get(k) is None else str(f.get(k))) for k in all_keys] for f in flat]
    prop = propose_tabular(rows, fmt=fmt)
    return SchemaProposal(**{**prop.__dict__, "record_count_estimate": len(records)})


def detect_xml_shape(text: str) -> dict[str, Any]:
    """Cheap XML structure probe without full parse (root, namespaces, depth)."""
    import xml.etree.ElementTree as ET
    info: dict[str, Any] = {}
    try:
        head = text[:2_000_000]
        root = ET.fromstring(head if head.count("<") > head.count("</") is False else head)
    except ET.ParseError:
        m = re.search(r"<\s*([\w:.-]+)", text)
        return {"root": m.group(1) if m else None, "well_formed": False}
    def depth(e) -> int:
        return 1 + (max((depth(c) for c in e), default=0))
    kids = [re.sub(r"^\{.*?\}", "", c.tag) for c in list(root)[:50]]
    info.update(root=re.sub(r"^\{.*?\}", "", root.tag),
                namespace=root.tag.split("}")[0][1:] if "}" in root.tag else None,
                depth=depth(root), well_formed=True, child_tags=sorted(set(kids)))
    return info
