"""traceatlas.intelligence.budget — reserve/commit/refund cost accounting (§6).

Runs reserve abstract budget units BEFORE execution. Exhausted budget produces
BLOCKED_BUDGET, never a silently-truncated "success". Reservations are tracked
per case so one runaway investigation cannot starve the tenant.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass(slots=True)
class Reservation:
    reservation_id: str
    case_id: str
    module_id: str
    units: float
    state: str = "reserved"      # reserved | committed | refunded


class BudgetExceeded(Exception):
    def __init__(self, requested: float, remaining: float):
        super().__init__(f"budget exhausted: requested {requested}, remaining {remaining}")
        self.requested = requested
        self.remaining = remaining


class BudgetLedger:
    """Simple deterministic unit ledger (production target: per-tenant DB table)."""

    def __init__(self, limit_units: float = 1000.0):
        self.limit = limit_units
        self._lock = threading.Lock()
        self._spent = 0.0
        self._reservations: dict[str, Reservation] = {}
        self._seq = 0

    # ------------------------------------------------------------------ basics
    @property
    def remaining(self) -> float:
        held = sum(r.units for r in self._reservations.values() if r.state == "reserved")
        return self.limit - self._spent - held

    def reserve(self, case_id: str, module_id: str, units: float) -> Reservation:
        if units < 0:
            raise ValueError("negative budget reservation")
        with self._lock:
            if units > self.remaining:
                raise BudgetExceeded(units, self.remaining)
            self._seq += 1
            res = Reservation(reservation_id=f"bud_{self._seq:06d}", case_id=case_id,
                              module_id=module_id, units=units)
            self._reservations[res.reservation_id] = res
            return res

    def commit(self, reservation_id: str, actual_units: float | None = None) -> None:
        with self._lock:
            res = self._reservations.get(reservation_id)
            if res is None or res.state != "reserved":
                raise KeyError(f"no active reservation {reservation_id}")
            res.state = "committed"
            res.units = actual_units if actual_units is not None else res.units
            self._spent += res.units

    def refund(self, reservation_id: str) -> None:
        """Blocked/cancelled runs must release their hold on budget."""
        with self._lock:
            res = self._reservations.get(reservation_id)
            if res and res.state == "reserved":
                res.state = "refunded"

    def estimate(self, cost_class: str, latency_class: str) -> float:
        """Coarse honest estimate from manifest classes; metered/paid cost more."""
        base = {"free": 1.0, "metered": 3.0, "paid": 8.0, "licensed": 12.0}.get(cost_class, 2.0)
        mult = {"fast": 1.0, "moderate": 1.5, "slow": 2.0, "variable": 2.5}.get(latency_class, 1.0)
        return round(base * mult, 2)

    def snapshot(self) -> dict:
        return {"limit": self.limit, "spent": self._spent, "remaining": self.remaining,
                "open_reservations": [vars(r) for r in self._reservations.values()
                                      if r.state == "reserved"]}
