"""traceatlas.intelligence.normalization — canonical schema mapping (§7, §24).

Connector CollectResult observations are SOURCE RESULTS. This service turns
them into OBSERVATIONS with preserved raw evidence — never into facts. A
source result that cannot be normalized is recorded as an explicit unsupported
observation with a reason; content is never invented.

Canonical observation shape:
  {subject, predicate, value, observed_at, retrieved_at, source_slug,
   source_uri, evidence_id, context}
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from traceatlas.core.observation import Observation


# ---------------------------------------------------------------- input validators
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_HASH_RE = re.compile(r"^[0-9a-f]{64}$|^[0-9a-f]{40}$|^[0-9a-f]{32}$", re.I)


def valid_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.strip().lower().rstrip(".")))


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def valid_url(value: str) -> bool:
    try:
        p = urlparse(value.strip())
        return p.scheme in ("http", "https") and bool(p.netloc)
    except ValueError:
        return False


def valid_cve(value: str) -> bool:
    return bool(_CVE_RE.match(value.strip()))


def valid_hash(value: str) -> bool:
    return bool(_HASH_RE.match(value.strip()))


def detect_input_kind(value: str) -> str:
    """Safe format identification for a single-string input (§24: identify,
    never guess content). Returns one of: domain/ip/url/cve/hash/username/query."""
    v = value.strip()
    if not v:
        return "query"
    if valid_url(v):
        return "url"
    if valid_ip(v):
        return "ip_address"
    if valid_cve(v):
        return "cve"
    if valid_hash(v):
        return "hash"
    bare = v.split("/")[-1].split(":")[0]
    if valid_domain(bare):
        return "domain"
    if re.match(r"^@?[A-Za-z0-9_.-]{1,80}$", v) and " " not in v:
        return "username"
    return "query"


# ---------------------------------------------------------------- timestamp helpers
def parse_time(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def normalize_observations(result, *, source_slug: str, case_id: Optional[str],
                           evidence_id: Optional[str],
                           default_predicate_ns: str = "") -> list[Observation]:
    """Map connector observations to canonical Observations.

    `result` is a CollectResult-like object (ok, observations, source_uri, meta).
    Malformed entries are SKIPPED with a count in context — never repaired by
    invention. Schema drift therefore degrades honestly to fewer observations.
    """
    out: list[Observation] = []
    skipped = 0
    retrieved = parse_time(getattr(result, "meta", {}).get("retrieved_at")) or \
        datetime.now(timezone.utc)
    source_uri = getattr(result, "source_uri", "") or ""
    for item in getattr(result, "observations", []) or []:
        if not isinstance(item, dict):
            skipped += 1
            continue
        subject = str(item.get("subject") or "").strip()
        predicate = str(item.get("predicate") or "").strip()
        if not subject or not predicate:
            skipped += 1
            continue
        if default_predicate_ns and "." not in predicate:
            predicate = f"{default_predicate_ns}.{predicate}"
        obs = Observation(
            case_id=case_id,
            subject_id=subject,
            predicate=predicate,
            value=item.get("value"),
            evidence_id=evidence_id,
            source_id=source_slug,
            observed_at=parse_time(item.get("observed_at")),
            context={
                "retrieved_at": retrieved.isoformat(),
                "source_uri": source_uri,
                "source_slug": source_slug,
                "module_normalized": True,
            },
        )
        out.append(obs)
    if skipped:
        # record the skip itself as an observation about the collection process
        out.append(Observation(
            case_id=case_id, subject_id=source_uri or source_slug,
            predicate="collection.schema_skipped_items", value=skipped,
            evidence_id=evidence_id, source_id=source_slug,
            context={"note": "malformed entries dropped during normalization; "
                             "raw bytes preserved as evidence"}))
    return out
