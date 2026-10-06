"""traceatlas.objectives.temporal_scope - Extract time windows from text."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

_YEAR_RX = re.compile(r"\b(19[89]\d|20[0-4]\d)\b")
_REL_RX = re.compile(r"last (\d+) (year|month|week|day)s?", re.I)


def infer_window(text: str,
                 now: Optional[datetime] = None,
                 ) -> tuple[Optional[datetime], Optional[datetime]]:
    """Return (start, end) inferred from explicit years or relative phrases."""
    now = now or datetime.now(timezone.utc)
    rel = _REL_RX.search(text)
    if rel:
        n, unit = int(rel.group(1)), rel.group(2).lower()
        days = {"year": 365, "month": 30, "week": 7, "day": 1}[unit] * n
        return (now - timedelta(days=days), now)
    years = _YEAR_RX.findall(text)
    if len(years) == 1:
        y = int(years[0])
        return (datetime(y, 1, 1, tzinfo=timezone.utc),
                datetime(y, 12, 31, 23, 59, tzinfo=timezone.utc))
    if len(years) >= 2:
        lo, hi = sorted(int(y) for y in years)
        return (datetime(lo, 1, 1, tzinfo=timezone.utc),
                datetime(hi, 12, 31, 23, 59, tzinfo=timezone.utc))
    return (None, None)
