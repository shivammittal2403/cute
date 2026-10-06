"""Smoke tests: the scaffolded package tree imports and contracts exist."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_core_packages_import():
    for name in [
        "traceatlas.core.case",
        "traceatlas.planning.planner",
        "traceatlas.investigation.engine",
        "traceatlas.employees.orchestrator",
        "traceatlas.intelligence.webint.search",
        "traceatlas.sources.connectors.base",
        "traceatlas.evidence.store",
        "traceatlas.entities.resolver",
        "traceatlas.graph.model",
        "traceatlas.verification.engine",
        "traceatlas.contradictions.engine",
        "traceatlas.ai.gateway",
        "traceatlas.reporting.builder",
        "traceatlas.security.authorization",
        "traceatlas.policy.engine",
        "traceatlas.db.session",
        "traceatlas.storage.local",
        "traceatlas.api.app",
        "traceatlas.cli.main",
    ]:
        importlib.import_module(name)


def test_source_schemas_are_valid_json():
    for schema in (ROOT / "sources/schema").glob("*.json"):
        doc = json.loads(schema.read_text())
        assert "$id" in doc and "properties" in doc


def test_catalog_files_exist():
    catalog = ROOT / "sources/catalog"
    assert len(list(catalog.glob("*.yaml"))) == 36
