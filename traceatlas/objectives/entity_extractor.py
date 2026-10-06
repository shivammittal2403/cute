"""traceatlas.objectives.entity_extractor - Pull candidate entities from text."""
from __future__ import annotations

import re
import unicodedata

DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# URL char class excludes whitespace and both quote characters; built via union.
URL_STOP = "\s" + chr(34) + chr(39) + "<>)\]"
URL_RE = re.compile("https?://[^" + URL_STOP + "]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
HANDLE_RE = re.compile(r"(?:^|\s|\bat\s+)([A-Za-z][A-Za-z0-9_]{2,29})(?=$|\s|[.,!?])")
ASN_RE = re.compile(r"\bAS\d{1,7}\b", re.I)


def extract_strings(text: str) -> dict[str, list[str]]:
    """Return recognised literal strings grouped by kind (deterministic)."""
    text = unicodedata.normalize("NFC", text)
    urls = URL_RE.findall(text)
    rest = URL_RE.sub(" ", text)
    doms = [d.lower().rstrip(".") for d in DOMAIN_RE.findall(rest)]
    ips = IPV4_RE.findall(rest)
    emails = EMAIL_RE.findall(rest)
    asns = sorted({a.upper() for a in ASN_RE.findall(rest)})
    return {"url": urls, "domain": doms, "ip_address": ips,
            "email": emails, "asn": asns}
