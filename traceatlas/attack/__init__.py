"""traceatlas.attack - Versioned MITRE ATT&CK knowledge-base subsystem.

ATT&CK changes over time; nothing here hardcodes an eternal technique list.
The KB is loaded from official STIX bundles (or a pinned snapshot), versioned,
and every mapping records the attack_version it was made against so historical
mappings stay interpretable when objects are deprecated or revoked upstream.
"""
from __future__ import annotations

from .version import AttackVersion, CURRENT_KNOWN_VERSIONS, pin_version
from .client import AttackClient
from .loader import StixLoader
from .updater import AttackUpdater
from .enterprise import EnterpriseMatrix
from .mobile import MobileMatrix
from .ics import IcsMatrix
from .tactics import TacticStore
from .techniques import TechniqueStore
from .subtechniques import SubtechniqueStore
from .software import SoftwareStore
from .groups import GroupStore
from .campaigns import CampaignStore
from .mitigations import MitigationStore
from .detections import DetectionGuideStore
from .procedures import ProcedureStore
from .relationships import RelationshipStore
from .mapper import AttackMapper
from .matcher import BehaviorMatcher
from .validator import AttackValidator, ValidationResult
from .comparator import AttackComparator
from .coverage import CoverageAnalyzer
from .matrix import MatrixBuilder
from .graph import AttackGraph
from .timeline import AttackTimeline

__all__ = [
    "AttackVersion", "CURRENT_KNOWN_VERSIONS", "pin_version", "AttackClient",
    "StixLoader", "AttackUpdater", "EnterpriseMatrix", "MobileMatrix", "IcsMatrix",
    "TacticStore", "TechniqueStore", "SubtechniqueStore", "SoftwareStore",
    "GroupStore", "CampaignStore", "MitigationStore", "DetectionGuideStore",
    "ProcedureStore", "RelationshipStore", "AttackMapper", "BehaviorMatcher",
    "AttackValidator", "ValidationResult", "AttackComparator", "CoverageAnalyzer",
    "MatrixBuilder", "AttackGraph", "AttackTimeline",
]
