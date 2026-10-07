"""traceatlas.intelligence.watch - Continuous Intelligence Desk (watchlists).

Implements the CONTINUOUS INTELLIGENCE DESK requirements on top of the real,
credential-free RSS connector already in traceatlas.sources.connectors.rss:

* Watchlist rule = entity/keyword + approved sources + relevance filters
  (industry/region/language) + budget.
* Each poll preserves publisher, original URL, publication time, retrieval
  time and an evidence reference (raw XML bytes -> EvidenceStore).
* Syndication clustering: repeated articles are ONE story with N copies —
  never treated as independent corroboration (publisher fan-out counted).
* Alert suppression: unchanged stories do not re-alert; quiet monitoring does
  not spam. Every alert carries why-it-matters, evidence, uncertainty state
  and a next investigation step.
* Monitoring budgets enforced through BudgetGuard; source outages are exposed
  honestly (an outage is never reported as "no news").
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from traceatlas.core.budget import Budget
from traceatlas.investigation.economy import BudgetGuard


def _norm_title(t: str) -> str:
    t = re.sub(r"[^\w\s]", "", (t or "").lower())
    return re.sub(r"\s+", " ", t).strip()


@dataclass(slots=True)
class FeedItem:
    title: str
    url: str
    published: str = ""            # event-time proxy from the feed
    publisher: str = ""
    language: str = ""
    retrieved_at: str = ""         # distinct from publication time
    evidence_id: str = ""          # raw-bytes artifact reference
    source_slug: str = ""

    def story_key(self) -> str:
        return _norm_title(self.title)[:80]


@dataclass(slots=True)
class WatchRule:
    rule_id: str
    name: str
    keyword: str                          # matched against title (case-insensitive)
    feeds: tuple[str, ...]                # allowed feed URLs (approved sources)
    regions: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("en",)
    industries: tuple[str, ...] = ()
    budget_usd: float = 1.0
    enabled: bool = True

    def matches(self, item: FeedItem) -> bool:
        if self.keyword.lower().strip('"') not in item.title.lower():
            return False
        if self.languages and item.language and item.language not in self.languages:
            return False
        return True


@dataclass(slots=True)
class StoryCluster:
    """One underlying story plus its syndicated copies."""
    story_key: str
    canonical: FeedItem                    # earliest-published copy
    copies: list[FeedItem] = field(default_factory=list)
    independent_publishers: int = 1

    @property
    def corroboration_note(self) -> str:
        if self.independent_publishers <= 1:
            return ("single-source story; syndicated copies are NOT independent "
                    "corroboration")
        return f"{self.independent_publishers} independent publishers"


@dataclass(slots=True)
class WatchAlert:
    alert_id: str
    rule_id: str
    story: StoryCluster
    why_it_matters: str
    uncertainty: str                       # qualitative band
    next_step: str
    raised_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"alert_id": self.alert_id, "rule_id": self.rule_id,
                "title": self.story.canonical.title,
                "url": self.story.canonical.url,
                "publisher": self.story.canonical.publisher,
                "published": self.story.canonical.published,
                "evidence_id": self.story.canonical.evidence_id,
                "copies": len(self.story.copies),
                "independent_publishers": self.story.independent_publishers,
                "why_it_matters": self.why_it_matters,
                "uncertainty": self.uncertainty,
                "next_step": self.next_step, "raised_at": self.raised_at}


class WatchDesk:
    """Poll rules over real connectors, cluster, dedup, alert-with-suppression."""

    def __init__(self, connectors: dict[str, Any], workspace: str | Path):
        self.connectors = connectors       # slug -> connector; optional "_evidence_store"
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.seen_stories: set[str] = set()
        self.outages: list[dict[str, str]] = []
        self._load_state()

    # ------------------------------------------------------------------ state
    def _state_path(self) -> Path:
        return self.workspace / "watch_state.json"

    def _load_state(self) -> None:
        p = self._state_path()
        if p.exists():
            try:
                d = json.loads(p.read_text())
                self.seen_stories = set(d.get("seen_stories", []))
                self.outages = list(d.get("outages", []))
            except ValueError:
                pass

    def save_state(self) -> None:
        self._state_path().write_text(json.dumps(
            {"seen_stories": sorted(self.seen_stories), "outages": self.outages[-50:]}))

    # ------------------------------------------------------------------- poll
    def poll(self, rule: WatchRule, *, now: Optional[datetime] = None) -> dict[str, Any]:
        """Run one monitoring cycle for a rule. Returns honest outcome dict:
        new_alerts, suppressed (unchanged), outages, cost snapshot, stop reason."""
        now = now or datetime.now(timezone.utc)
        guard = BudgetGuard(Budget(max_cost_usd=rule.budget_usd),
                           case_id=f"watch:{rule.rule_id}")
        items: list[FeedItem] = []
        errors: list[str] = []
        rss = self.connectors.get("google-news-rss") or self.connectors.get("rss-generic")
        if rss is None:
            return {"rule_id": rule.rule_id, "ok": False,
                    "stop_reason": "configuration_blocked: no rss connector registered",
                    "new_alerts": [], "suppressed_unchanged": 0}
        for feed_url in rule.feeds:
            res = guard.reserve(f"fetch:{feed_url}", estimated_usd=0.0)
            if res is None:
                errors.append(f"budget refused fetch for {feed_url}")
                break
            try:
                if getattr(rss, "source_slug", "") == "google-news-rss":
                    out = rss.collect(rule.keyword, "news.entity")
                else:
                    out = rss.collect(feed_url)
            except Exception as exc:  # noqa: BLE001 — outage must surface, not crash desk
                guard.release(res, "connector_error")
                errors.append(f"{type(exc).__name__}: {exc}")
                self.outages.append({"feed": feed_url, "at": now.isoformat(),
                                     "error": str(exc)})
                continue
            if not getattr(out, "ok", False):
                guard.release(res, "feed_error")
                errors.append(f"feed error {feed_url}: {getattr(out, 'error', '')}")
                self.outages.append({"feed": feed_url, "at": now.isoformat(),
                                     "error": getattr(out, "error", "unknown")})
                continue
            evidence_id = ""
            ev_store = self.connectors.get("_evidence_store")
            raw = getattr(out, "raw_bytes", b"") or b""
            if ev_store is not None and raw:
                ev = ev_store.put_bytes(raw, source_uri=getattr(out, "source_uri", feed_url),
                                        media_type="application/rss+xml",
                                        case_id=f"watch_{rule.rule_id}")
                evidence_id = ev.evidence_id
            for o in getattr(out, "observations", []) or []:
                it = FeedItem(title=o.get("value") or o.get("title", ""),
                              url=o.get("link", (o.get("context") or {}).get("link", "")),
                              published=str(o.get("published", o.get("observed_at", ""))),
                              publisher=_host(getattr(out, "source_uri", feed_url)),
                              retrieved_at=now.isoformat(), evidence_id=evidence_id,
                              source_slug=getattr(rss, "source_slug", "rss"))
                if it.title and rule.matches(it):
                    items.append(it)
            guard.settle(res, actual_usd=0.0, http_requests=1,
                         source_slug=getattr(rss, "source_slug", "rss"))

        clusters = self._cluster(items)
        alerts: list[WatchAlert] = []
        suppressed = 0
        for c in clusters:
            if c.story_key in self.seen_stories:
                suppressed += 1
                continue                      # quiet monitoring: no repeat alerts
            self.seen_stories.add(c.story_key)
            alerts.append(WatchAlert(
                alert_id="alrt-" + hashlib.sha256(
                    (rule.rule_id + c.story_key).encode()).hexdigest()[:10],
                rule_id=rule.rule_id, story=c,
                why_it_matters=(f"New item matching watch rule {rule.name!r}: "
                                f"{c.corroboration_note}"),
                uncertainty=("MODERATE (single source until independently corroborated)"
                             if c.independent_publishers <= 1 else "HIGH-relative (multi-publisher)"),
                next_step=("open supporting evidence; run bounded domain/entity "
                           "investigation on mentioned assets"),
                raised_at=now.isoformat()))
        result = {"rule_id": rule.rule_id, "ok": bool(items) or not errors,
                  "new_alerts": [a.to_dict() for a in alerts],
                  "suppressed_unchanged": suppressed,
                  "items_seen": len(items), "clusters": len(clusters),
                  "source_errors": errors,
                  "outage_disclosure": ("SOURCE OUTAGE — absence of items below is "
                                        "NOT evidence of no activity" if errors else ""),
                  "cost": guard.snapshot()}
        if guard.exhausted():
            result["stop_reason"] = "monitoring budget exhausted"
        self.save_state()
        return result

    # -------------------------------------------------------------- clustering
    def _cluster(self, items: list[FeedItem]) -> list[StoryCluster]:
        by_key: dict[str, list[FeedItem]] = {}
        for it in items:
            by_key.setdefault(it.story_key(), []).append(it)
        clusters: list[StoryCluster] = []
        for key, group in by_key.items():
            group.sort(key=lambda i: i.published or "9999")
            canonical = group[0]
            pubs = {i.publisher for i in group if i.publisher}
            clusters.append(StoryCluster(story_key=key, canonical=canonical,
                                         copies=group,
                                         independent_publishers=max(1, len(pubs))))
        return clusters


def _host(uri: str) -> str:
    m = re.match(r"https?://([^/]+)", uri or "")
    return m.group(1) if m else (uri or "")
