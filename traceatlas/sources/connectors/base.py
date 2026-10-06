"""traceatlas.sources.connectors.base - Connector contract + result types."""
from __future__ import annotations

import ipaddress
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse


@dataclass(slots=True)
class CollectResult:
    ok: bool
    observations: list[dict[str, Any]] = field(default_factory=list)
    raw_bytes: Optional[bytes] = None
    media_type: str = "application/octet-stream"
    source_uri: str = ""
    error: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def is_safe_url(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """SSRF guard: only http(s), host must resolve to a public address."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "unparseable url"
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme {parsed.scheme!r} not allowed"
    host = parsed.hostname
    if not host:
        return False, "missing host"
    if not allow_private:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False, "dns resolution failed"
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast):
                return False, f"private/reserved address {ip}"
    return True, ""


class BaseConnector(ABC):
    source_slug: str = "generic"
    connector_type: str = "base"

    @abstractmethod
    def collect(self, target: str, capability: str) -> CollectResult:
        ...

    def health(self) -> bool:
        return True

    def close(self) -> None:
        pass
