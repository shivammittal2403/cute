"""traceatlas.ingestion.parsers.registry - Format→parser routing table."""
from __future__ import annotations

from typing import Optional

from .base import BaseParser


class ParserRegistry:
    def __init__(self) -> None:
        self._by_id: dict[str, BaseParser] = {}
        self._by_format: dict[str, list[BaseParser]] = {}

    def register(self, parser: BaseParser) -> None:
        if parser.parser_id in self._by_id:
            raise ValueError(f"duplicate parser_id {parser.parser_id}")
        self._by_id[parser.parser_id] = parser
        for fmt in parser.formats:
            lst = self._by_format.setdefault(fmt, [])
            lst.append(parser)
            lst.sort(key=lambda p: -p.priority)

    def unregister(self, parser_id: str) -> None:
        p = self._by_id.pop(parser_id, None)
        if p is None:
            return
        for fmt in p.formats:
            lst = self._by_format.get(fmt, [])
            if p in lst:
                lst.remove(p)

    def get(self, parser_id: str) -> Optional[BaseParser]:
        return self._by_id.get(parser_id)

    def for_format(self, fmt: str) -> Optional[BaseParser]:
        cands = self._by_format.get(fmt)
        return cands[0] if cands else None

    def candidates_for(self, fmt: str) -> list[BaseParser]:
        return list(self._by_format.get(fmt, []))

    def all_parsers(self) -> list[BaseParser]:
        return list(self._by_id.values())

    def formats_supported(self) -> set[str]:
        return set(self._by_format)
