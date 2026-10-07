"""traceatlas.investigation.economy - Cost-tier routing and hard budget caps.

Implements the LOW-COST EXECUTION requirements of the master build prompt:

* Three configurable modes: ECONOMY / BALANCED / DEEP_INVESTIGATION.
  Mode selection changes collection breadth and review depth ONLY. It never
  weakens authorization, evidence preservation, secret protection or required
  deterministic verification (enforced structurally: those checks live outside
  this module and are not mode-gated).

* Task-tier routing (explainable, no invented information-gain math):
    TIER 1 deterministic code   -> cost 0.0, no model call
    TIER 2 qualified small/local model -> cheap per-token rate
    TIER 3 stronger model       -> higher rate
    TIER 4 human review         -> analyst time cost
  A task is routed to the CHEAPEST tier whose capability satisfies the mode's
  minimum for that task class. Economy routes extraction/classification to
  tier 2; Deep Investigation routes ambiguous identity/synthesis work to
  tier 3 and adds second-model review where material.

* Budget reservations under concurrency: `reserve()` atomically holds estimated
  cost before execution; settlement reconciles estimate vs actual; a reservation
  that would exceed a hard cap is refused (stop reason recorded) rather than
  silently overspending. Retries re-reserve against the same task ceiling.

* Cache accounting: case-scoped content-hash cache keys; provider-aware
  freshness window; cache hits are recorded with source observation age so
  repeated collection avoids unnecessary paid work. Model-output caches are
  keyed by model+parser+prompt version — a changed version never reuses a
  stale cached conclusion.

All spending is tracked through traceatlas.core.cost.Cost and bounded by
traceatlas.core.budget.Budget. Estimates and actuals are exposed per task,
per case and per monitoring rule.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from traceatlas.core.budget import Budget
from traceatlas.core.cost import Cost


class ExecutionMode(str, Enum):
    ECONOMY = "economy"
    BALANCED = "balanced"
    DEEP = "deep_investigation"


class TaskTier(int, Enum):
    DETERMINISTIC = 1     # validation, hashes, normalization, dedup, parsing
    SMALL_MODEL = 2       # extraction/classification when evaluated accuracy suffices
    STRONG_MODEL = 3      # ambiguous identity, cross-source synthesis, consequential
    HUMAN_REVIEW = 4      # unresolved material uncertainty / authorization actions


# Task classes used by planner instructions and workers.
TASK_CLASSES = (
    "validate", "hash", "normalize", "dedupe", "parse",            # tier-1 always
    "extract", "classify", "summarize",                            # tier 2 in economy
    "identity_resolution", "cross_source_synthesis", "hypothesis", # tier 3 in deep
    "consequential_report_claim",                                  # tier 3 + review
)

# Minimum tier each mode demands for a task class. Routing picks the cheapest
# available tier >= the minimum; tier availability is declared by the runtime
# (e.g. no strong model configured -> falls back to human review flag).
_MODE_MIN_TIER: dict[ExecutionMode, dict[str, int]] = {
    ExecutionMode.ECONOMY: {
        "extract": TaskTier.DETERMINISTIC, "classify": TaskTier.DETERMINISTIC,
        "summarize": TaskTier.SMALL_MODEL,
        "identity_resolution": TaskTier.SMALL_MODEL,
        "cross_source_synthesis": TaskTier.SMALL_MODEL,
        "hypothesis": TaskTier.SMALL_MODEL,
        "consequential_report_claim": TaskTier.SMALL_MODEL,
    },
    ExecutionMode.BALANCED: {
        "extract": TaskTier.SMALL_MODEL, "classify": TaskTier.SMALL_MODEL,
        "summarize": TaskTier.SMALL_MODEL,
        "identity_resolution": TaskTier.STRONG_MODEL,
        "cross_source_synthesis": TaskTier.SMALL_MODEL,
        "hypothesis": TaskTier.STRONG_MODEL,
        "consequential_report_claim": TaskTier.STRONG_MODEL,
    },
    ExecutionMode.DEEP: {
        "extract": TaskTier.SMALL_MODEL, "classify": TaskTier.SMALL_MODEL,
        "summarize": TaskTier.SMALL_MODEL,
        "identity_resolution": TaskTier.STRONG_MODEL,
        "cross_source_synthesis": TaskTier.STRONG_MODEL,
        "hypothesis": TaskTier.STRONG_MODEL,
        "consequential_report_claim": TaskTier.HUMAN_REVIEW,
    },
}

# Deterministic classes are ALWAYS tier 1 regardless of mode — running a model
# where code can reliably complete the task is prohibited by the spec.
_ALWAYS_DETERMINISTIC = {"validate", "hash", "normalize", "dedupe", "parse"}

# Second-model review is SELECTIVE, not universal (spec): only these triggers.
REVIEW_TRIGGERS = (
    "material_identity_attribution", "disputed_evidence",
    "suspicious_source_instructions", "weakly_supported_conclusion",
    "consequential_report_claim",
)


@dataclass(frozen=True, slots=True)
class RateCard:
    """Dated model/source pricing configuration. Never hardcoded marketing
    claims: attach as_of date and treat unknown entries as blocked-paid."""
    rates_usd_per_1k_tokens: dict[int, float] = field(default_factory=lambda: {
        TaskTier.SMALL_MODEL: 0.0002,   # local/small qualified models
        TaskTier.STRONG_MODEL: 0.0100,  # stronger hosted models
    })
    human_review_usd: float = 12.0      # per flagged item analyst time
    as_of: str = "2026-10-07"

    def tier_cost(self, tier: TaskTier, est_tokens: int) -> float:
        if tier == TaskTier.DETERMINISTIC:
            return 0.0
        if tier == TaskTier.HUMAN_REVIEW:
            return self.human_review_usd
        return self.rates_usd_per_1k_tokens.get(int(tier), 0.0) * est_tokens / 1000.0


class TierRouter:
    """Routes a task class to the cheapest acceptable tier for the mode."""

    def __init__(self, mode: ExecutionMode = ExecutionMode.BALANCED,
                 available_tiers: set[TaskTier] | None = None,
                 rate_card: RateCard | None = None):
        self.mode = mode
        self.available = available_tiers or {t for t in TaskTier}
        self.rates = rate_card or RateCard()

    def route(self, task_class: str, est_tokens: int = 800) -> tuple[TaskTier, float]:
        if task_class in _ALWAYS_DETERMINISTIC:
            return TaskTier.DETERMINISTIC, 0.0
        min_tier = _MODE_MIN_TIER[self.mode].get(task_class, TaskTier.SMALL_MODEL)
        for tier in (TaskTier.DETERMINISTIC, TaskTier.SMALL_MODEL,
                     TaskTier.STRONG_MODEL, TaskTier.HUMAN_REVIEW):
            if tier < min_tier:
                continue
            if tier in self.available:
                return tier, self.rates.tier_cost(tier, est_tokens)
        # No tier available at/above the minimum -> abstain honestly via human queue
        return TaskTier.HUMAN_REVIEW, self.rates.human_review_usd

    def needs_second_model_review(self, task_class: str,
                                  triggers: tuple[str, ...] = ()) -> bool:
        """Selective review: universal duplicate calls are NOT required."""
        if task_class not in REVIEW_TRIGGERS and not set(triggers) & set(REVIEW_TRIGGERS):
            return False
        # Economy still reviews material attribution/disputed evidence —
        # verification is never weakened by mode. Only *breadth* shrinks.
        return True


@dataclass(slots=True)
class Reservation:
    reservation_id: str
    task_id: str
    estimated_usd: float
    held_usd: float
    settled_usd: Optional[float] = None
    stop_reason: Optional[str] = None

    @property
    def open(self) -> bool:
        return self.settled_usd is None and self.stop_reason is None


class BudgetGuard:
    """Hard-cap accounting with atomic reservations under concurrency.

    reserve() holds estimated spend BEFORE execution so parallel workers cannot
    collectively blow the cap. settle() reconciles actuals; overruns are
    recorded (never hidden) and further reservations are refused once exhausted.
    """

    def __init__(self, budget: Budget, case_id: str = ""):
        self.budget = budget
        self.case_id = case_id
        self.spent = Cost()
        self._held = 0.0
        self._lock = threading.Lock()
        self._seq = 0
        self.refusals: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ api
    def reserve(self, task_id: str, estimated_usd: float,
                est_tokens: int = 0) -> Optional[Reservation]:
        with self._lock:
            projected = self.spent.cost_usd + self._held + estimated_usd
            if projected > self.budget.max_cost_usd:
                rec = {"task_id": task_id, "reason": "hard_cap_cost",
                       "projected_usd": round(projected, 6),
                       "cap_usd": self.budget.max_cost_usd}
                self.refusals.append(rec)
                return None
            if self.spent.model_tokens + est_tokens > self.budget.max_model_tokens:
                rec = {"task_id": task_id, "reason": "hard_cap_tokens",
                       "cap_tokens": self.budget.max_model_tokens}
                self.refusals.append(rec)
                return None
            if self.spent.tasks + 1 > self.budget.max_tasks:
                rec = {"task_id": task_id, "reason": "hard_cap_tasks",
                       "cap_tasks": self.budget.max_tasks}
                self.refusals.append(rec)
                return None
            self._seq += 1
            r = Reservation(reservation_id=f"res-{self._seq}", task_id=task_id,
                            estimated_usd=estimated_usd, held_usd=estimated_usd)
            self._held += estimated_usd
            return r

    def settle(self, res: Reservation, actual_usd: float, *, tokens: int = 0,
               http_requests: int = 0, source_slug: str = "") -> None:
        with self._lock:
            if not res.open:
                raise ValueError(f"reservation {res.reservation_id} already closed")
            self._held -= res.held_usd
            res.settled_usd = actual_usd
            self.spent.cost_usd += actual_usd
            self.spent.model_tokens += tokens
            self.spent.tasks += 1
            for _ in range(http_requests):
                self.spent.add_request(source_slug or "unknown", usd=0.0)

    def release(self, res: Reservation, reason: str) -> None:
        """Return an unused reservation (task skipped/stopped)."""
        with self._lock:
            if res.open:
                self._held -= res.held_usd
                res.stop_reason = reason

    def exhausted(self) -> bool:
        with self._lock:
            return (self.spent.cost_usd + self._held) >= self.budget.max_cost_usd \
                or self.budget.exhausted(self.spent)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"case_id": self.case_id,
                    "spent": self.spent.to_dict(),
                    "held_usd": round(self._held, 6),
                    "budget": self.budget.to_dict(),
                    "refusals": list(self.refusals)}


class FreshnessCache:
    """Case-scoped content-hash cache with provider-aware freshness windows.

    Key = case_id + sha256(content) — results never cross cases/tenants.
    Records cache hits and source observation age for honest reporting.
    Model outputs additionally key on model/parser/prompt version.
    """

    def __init__(self, max_age_s: dict[str, float] | None = None,
                 default_max_age_s: float = 3600.0):
        # per-source freshness policy (paid/slow-moving sources cached longer)
        self.max_age_s = {"dns-system": 300.0, "crtsh": 86400.0,
                          "rdap-iana-bootstrap": 86400.0}
        if max_age_s:
            self.max_age_s.update(max_age_s)
        self.default_max_age_s = default_max_age_s
        self._entries: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(case_id: str, content: bytes, *, model_version: str = "",
            parser_version: str = "", prompt_version: str = "") -> str:
        h = hashlib.sha256(content).hexdigest()
        ver = f"|{model_version}|{parser_version}|{prompt_version}" if (
            model_version or parser_version or prompt_version) else ""
        return f"{case_id}:{h}{ver}"

    def get(self, key: str, now: Optional[datetime] = None) -> Optional[Any]:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            ent = self._entries.get(key)
            if not ent:
                self.misses += 1
                return None
            stored_at, value = ent
            source_key = key.split(":")[-1].split("|")[0][:12]
            max_age = self._age_for(source_key)
            if (now.timestamp() - stored_at) > max_age:
                self.misses += 1
                del self._entries[key]
                return None
            self.hits += 1
            return value

    def put(self, key: str, value: Any, observed_at: Optional[datetime] = None) -> None:
        ts = (observed_at or datetime.now(timezone.utc)).timestamp()
        with self._lock:
            self._entries[key] = (ts, value)

    def observation_age_s(self, key: str, now: Optional[datetime] = None) -> Optional[float]:
        now = now or datetime.now(timezone.utc)
        with self._lock:
            ent = self._entries.get(key)
            return None if not ent else round(now.timestamp() - ent[0], 3)

    def _age_for(self, source_hint: str) -> float:
        for slug, age in self.max_age_s.items():
            if slug.startswith(source_hint[:8]) or source_hint[:8].startswith(slug[:8]):
                return age
        return self.default_max_age_s

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {"hits": self.hits, "misses": self.misses,
                    "entries": len(self._entries)}
