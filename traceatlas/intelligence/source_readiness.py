"""traceatlas.intelligence.source_readiness — is a module runnable right now?

Answers §6's "check source readiness" step honestly: for each declared
SourceRequirement, look the capability up in the governed SourceRegistry and
report whether a configured connector exists AND meets the minimum
qualification. Readiness never implies truth of results; it only says whether
collection could be attempted at all.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from traceatlas.intelligence.contracts import ModuleManifest, SourceRequirement
from traceatlas.sources.registry import SourceRegistry


@dataclass(slots=True)
class RequirementReadiness:
    capability: str
    required: bool
    min_qualification: str
    satisfied: bool
    matching_sources: tuple[str, ...] = ()
    connectors_available: tuple[str, ...] = ()
    reason: str = ""


@dataclass(slots=True)
class ReadinessReport:
    module_id: str
    ready: bool                      # all REQUIRED requirements satisfied
    items: list[RequirementReadiness] = field(default_factory=list)
    notes: tuple[str, ...] = ()

    def blocked_reason(self) -> str:
        missing = [i.capability for i in self.items if i.required and not i.satisfied]
        return f"required capabilities unavailable: {missing}" if missing else ""


def check_requirement(req: SourceRequirement, registry: SourceRegistry,
                      connectors: dict | None = None) -> RequirementReadiness:
    candidates = registry.find(req.capability, min_qualification=req.min_qualification)
    slugs = tuple(c.slug for c in candidates)
    available: tuple[str, ...] = ()
    if connectors is not None:
        available = tuple(s for s in slugs if s in connectors)
    else:
        available = slugs  # no connector map supplied: config-level view only
    satisfied = bool(available) if req.required else True
    reason = ""
    if req.required and not slugs:
        reason = (f"no source record provides '{req.capability}' at "
                  f">={req.min_qualification} qualification")
    elif req.required and slugs and not available:
        reason = f"sources exist ({list(slugs)}) but no connector is wired"
    return RequirementReadiness(
        capability=req.capability, required=req.required,
        min_qualification=req.min_qualification, satisfied=satisfied,
        matching_sources=slugs, connectors_available=available, reason=reason)


def check_manifest(manifest: ModuleManifest, registry: SourceRegistry,
                   connectors: dict | None = None) -> ReadinessReport:
    """Offline-safe modules (no network permission) are trivially ready for
    their declared ingestion; networked modules need qualified + wired sources."""
    report = ReadinessReport(module_id=manifest.module_id, ready=True)
    notes: list[str] = []
    if not manifest.source_requirements:
        notes.append("no source requirements declared"
                     + ("" if not manifest.permissions.network else
                        " (network permission without requirements — contract violation)"))
    for req in manifest.source_requirements:
        item = check_requirement(req, registry, connectors)
        report.items.append(item)
        if req.required and not item.satisfied:
            report.ready = False
    # configured_sources that don't resolve in the registry are flagged honestly
    for slug in manifest.configured_sources:
        if registry.get(slug) is None:
            notes.append(f"configured_source '{slug}' not present in governed registry")
            report.ready = False
    report.notes = tuple(notes)
    return report
