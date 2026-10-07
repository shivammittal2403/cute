"""traceatlas.security.tool_grants — least-privilege, task-scoped tool grants.

Enforces in APPLICATION CODE (not model instructions) that:
  * a tool call is only honored if a pre-issued grant covers it;
  * grants are short-lived (TTL), scoped to one task and one tenant/case;
  * text arriving from external content or from a model cannot widen a grant
    (prompt-injection containment: the "requested_by_text" argument is
    recorded for audit but NEVER parsed as an instruction);
  * revoked/expired grants fail closed.

This module backs scripts/demo_economy_security.py::_security_probe_tool_injection.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class ToolGrant:
    grant_id: str
    task_id: str
    allowed_tools: tuple[str, ...]
    tenant_id: str = ""
    case_id: str = ""
    issued_at: float = field(default_factory=time.time)
    ttl_seconds: float = 900.0  # 15 minutes default; short-lived by design
    revoked: bool = False

    def is_active(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return not self.revoked and (now - self.issued_at) < self.ttl_seconds


class ToolGrantPolicy:
    """Default-deny issuer/checker for task-scoped tool permissions."""

    def __init__(self) -> None:
        self._grants: dict[str, ToolGrant] = {}
        self.audit_log: list[dict] = []

    # ------------------------------------------------------------- issuing
    def issue(
        self,
        grant_id: str,
        task_id: str,
        allowed_tools: list[str],
        *,
        tenant_id: str = "",
        case_id: str = "",
        ttl_seconds: float = 900.0,
    ) -> ToolGrant:
        if not allowed_tools:
            raise ValueError("grant must enumerate at least one tool")
        g = ToolGrant(
            grant_id=grant_id,
            task_id=task_id,
            allowed_tools=tuple(sorted(set(allowed_tools))),
            tenant_id=tenant_id,
            case_id=case_id,
            ttl_seconds=ttl_seconds,
        )
        self._grants[grant_id] = g
        self._audit({"event": "issue", "grant_id": grant_id, "task_id": task_id,
                     "tools": list(g.allowed_tools)})
        return g

    def revoke(self, grant_id: str) -> None:
        g = self._grants.get(grant_id)
        if g is not None:
            g.revoked = True
            self._audit({"event": "revoke", "grant_id": grant_id})

    # ------------------------------------------------------------ checking
    def request_from_model(
        self,
        grant_id: str,
        tool: str,
        *,
        requested_by_text: str = "",
        now: Optional[float] = None,
    ) -> tuple[bool, str]:
        """Return (allowed, reason). `requested_by_text` is untrusted content
        captured for audit only — it never affects the decision."""
        g = self._grants.get(grant_id)
        if g is None:
            self._audit({"event": "deny", "reason": "unknown_grant", "tool": tool})
            return False, "unknown_grant"
        if not g.is_active(now):
            self._audit({"event": "deny", "reason": "grant_expired_or_revoked",
                         "tool": tool, "grant_id": grant_id})
            return False, "grant_expired_or_revoked"
        if tool not in g.allowed_tools:
            self._audit({"event": "deny", "reason": "tool_not_granted",
                         "tool": tool, "grant_id": grant_id,
                         "hostile_text_len": len(requested_by_text)})
            return False, "tool_not_granted"
        self._audit({"event": "allow", "tool": tool, "grant_id": grant_id})
        return True, "granted"

    def check_tenant_isolation(self, grant_id: str, tenant_id: str) -> bool:
        g = self._grants.get(grant_id)
        return g is not None and g.tenant_id == tenant_id

    # --------------------------------------------------------------- audit
    def _audit(self, record: dict) -> None:
        record = dict(record)
        record["ts"] = time.time()
        record.setdefault("grant_id", "")
        self.audit_log.append(record)


def new_grant_id() -> str:
    return f"grant-{uuid.uuid4().hex[:12]}"
