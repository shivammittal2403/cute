"""traceatlas.planning.risk_planner - Flag risky task categories up front."""
from __future__ import annotations

from traceatlas.core.enums import RiskLevel

RISKY_CAPABILITIES = {
    "direct_probe": RiskLevel.HIGH,      # touching target infra = active recon
    "dark": RiskLevel.CRITICAL,
    "credential": RiskLevel.MEDIUM,
}


def task_risk(instruction: dict) -> RiskLevel:
    cap = instruction.get("capability", "")
    for needle, level in RISKY_CAPABILITIES.items():
        if needle in cap:
            return level
    return RiskLevel.LOW
