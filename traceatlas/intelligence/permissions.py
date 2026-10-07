"""traceatlas.intelligence.permissions — authorization + tenant enforcement (§6, §30, §34).

Two distinct gates live here:
1. Case authorization: an InvestigationRequest must carry a valid, unexpired
   Authorization (granted_by + basis + scopes) OR an explicit caller assertion
   of authorized scope. Without either, collection is refused (BLOCKED_PERMISSION).
2. Tenant/case access: cross-tenant reads/writes are refused before anything else.

Consequential actions (§34) can NEVER be authorized by these helpers — they are
prohibited at the module contract level and re-checked here as defense in depth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from traceatlas.core.authorization import Authorization
from traceatlas.intelligence.constants import PROHIBITED_BASELINE


@dataclass(slots=True)
class PermissionDecision:
    allowed: bool
    reason: str = ""
    gate: str = ""          # "tenant" | "authorization" | "action" | "network"


def check_tenant_access(*, request_tenant: str, case_tenant: str) -> PermissionDecision:
    """Tenant breakout attempt => deny, always. Empty case tenant means the
    record predates tenancy and only the default tenant may touch it."""
    if not case_tenant or case_tenant == "default":
        if request_tenant not in ("", "default"):
            return PermissionDecision(False, "case belongs to default tenant; "
                                              f"tenant '{request_tenant}' denied", "tenant")
        return PermissionDecision(True)
    if request_tenant != case_tenant:
        return PermissionDecision(
            False, f"cross-tenant access denied ({request_tenant!r} -> {case_tenant!r})",
            "tenant")
    return PermissionDecision(True)


def check_case_authorization(auth: Optional[Authorization], *,
                             asserted_scope: bool = False,
                             activity: str = "collect.public") -> PermissionDecision:
    """Valid Authorization object wins; otherwise an explicit caller assertion
    (API-level `authorized_scope`) is accepted for the requested activity."""
    if auth is not None and auth.is_valid():
        if auth.permits(activity) or auth.permits("collect.public") or "*" in auth.scopes:
            return PermissionDecision(True, "valid authorization record", "authorization")
        return PermissionDecision(False,
                                  f"authorization scopes do not permit '{activity}'",
                                  "authorization")
    if asserted_scope:
        return PermissionDecision(True, "caller asserted authorized scope", "authorization")
    return PermissionDecision(
        False, "no valid authorization and no asserted scope; refusing to collect",
        "authorization")


def check_action_permitted(action: str, allowed_actions: tuple[str, ...],
                          prohibited_actions: tuple[str, ...]) -> PermissionDecision:
    """Baseline prohibitions override everything: even a misconfigured manifest
    that 'allows' a prohibited action is denied here."""
    if action in PROHIBITED_BASELINE or action in prohibited_actions:
        return PermissionDecision(False, f"action '{action}' is prohibited "
                                         "(human governance required)", "action")
    if action not in allowed_actions:
        return PermissionDecision(False, f"action '{action}' not in module allowed_actions",
                                  "action")
    return PermissionDecision(True)


def check_network_permission(manifest_network: bool, *, authorization_ok: bool) -> PermissionDecision:
    if not manifest_network:
        return PermissionDecision(True, "offline ingestion only", "network")
    if not authorization_ok:
        return PermissionDecision(False, "network collection requires authorization",
                                  "network")
    return PermissionDecision(True)
