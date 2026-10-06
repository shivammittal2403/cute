"""traceatlas.core.timeline - Ordered event collection."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional

from .event import Event
from .identifiers import ID, new_id

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(slots=True)
class Timeline:
    timeline_id: ID = field(default_factory=lambda: new_id("timeline"))
    case_id: Optional[ID] = None
    title: str = ""
    _events: list[Event] = field(default_factory=list)

    @staticmethod
    def _sort_key(e: Event) -> datetime:
        k = e.effective_time()
        if k is None:
            return _EPOCH
        return k if k.tzinfo else k.replace(tzinfo=_EPOCH.tzinfo)

    def add(self, event: Event) -> None:
        key = self._sort_key(event)
        lo, hi = 0, len(self._events)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._sort_key(self._events[mid]) <= key:
                lo = mid + 1
            else:
                hi = mid
        self._events.insert(lo, event)

    def window(self, start: datetime, end: datetime) -> list[Event]:
        return [e for e in self._events if e.overlaps_window(start, end)]

    def __iter__(self) -> Iterator[Event]:
        return iter(self._events)

    def __len__(self) -> int:
        return len(self._events)
