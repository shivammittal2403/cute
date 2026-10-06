"""Golden offline + live-gated tests for the domain vertical slice."""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from traceatlas.core.enums import EntityKind, TaskKind, TaskStatus
from traceatlas.core.observation import Observation
from traceatlas.evidence.store import EvidenceStore
from traceatlas.entities.resolver import EntityResolver
from traceatlas.graph.model import KnowledgeGraph
from traceatlas.core.entity import Entity
from traceatlas.investigation.engine import EngineConfig, InvestigationEngine
from traceatlas.planning.planner import Planner
from traceatlas.objectives.parser import ObjectiveParser
from traceatlas.sources.connectors.base import CollectResult
from traceatlas.sources.registry import SourceRegistry


class FakeConnector:
    """Deterministic connector for offline golden runs (fixture evidence)."""

    def __init__(self, slug: str, results: dict[str, CollectResult]):
        self.slug = slug
        self.results = results
        self.calls: list[tuple[str, str]] = []

    def collect(self, target: str, capability: str) -> CollectResult:
        self.calls.append((target, capability))
        return self.results.get(capability,
                                CollectResult(ok=False, source_uri=f"fake://{capability}",
                                              error="no fixture"))


def _dns_result(records):
    raw = json.dumps({"qname": "example.com", "records": records}).encode()
    return CollectResult(ok=True, source_uri="dns://A/example.com", raw_bytes=raw,
                         media_type="application/json",
                         observations=[{"subject": "example.com", "predicate": "dns.a",
                                        "value": r} for r in records])


@pytest.fixture()
def fake_world(tmp_path):
    ev = EvidenceStore(tmp_path / "evidence")
    graph = KnowledgeGraph(tmp_path / "graph.jsonl")
    connectors = {
        "dns-system": FakeConnector("dns-system", {"dns.A": _dns_result(["93.184.216.34"]),
                                                   "dns.NS": _dns_result(["a.iana-servers.net"])}),
        "rdap-iana-bootstrap": FakeConnector(
            "rdap-iana-bootstrap",
            {"rdap.domain": CollectResult(
                ok=True, source_uri="rdap://example.com",
                raw_bytes=b'{"registrar": "Example Registrar"}',
                media_type="application/rdap+json",
                observations=[{"subject": "example.com", "predicate": "registrar",
                               "value": "Example Registrar Inc."}]})},
    }
    return tmp_path, ev, graph, connectors


def test_authorization_refusal_without_scope():
    mgr_needs_auth = "Investigate example.com"
    spec = ObjectiveParser().parse(mgr_needs_auth)
    assert not spec.authorization.is_valid()


def test_objective_parser_extracts_domain_target():
    spec = ObjectiveParser().parse(
        "Who owns the domain example.com? passive only, GDPR constraints.")
    kinds = [(t.kind.value, t.value) for t in spec.targets]
    assert ("domain", "example.com") in kinds


def test_planner_uses_registry_and_emits_waves():
    spec = ObjectiveParser().parse("Map infrastructure of example.com, passive only.")
    plan = Planner(SourceRegistry.load_default()).plan(spec)
    collect_tasks = [t for t in plan.tasks if t.kind == TaskKind.COLLECT]
    assert collect_tasks, "planner produced no collection tasks"
    waves = {t.wave for t in plan.tasks}
    assert max(waves) >= 3, "expected collect/analysis/report waves"


def test_engine_end_to_end_offline(fake_world):
    tmp_path, ev, graph, connectors = fake_world
    spec = ObjectiveParser().parse("Map infrastructure of example.com, passive only.")
    plan = Planner(SourceRegistry.load_default()).plan(spec)
    engine = InvestigationEngine(case_id="case_golden", evidence_store=ev, graph=graph,
                                 connectors=connectors,
                                 config=EngineConfig(max_workers=2, base_backoff_s=0.01),
                                 checkpoint_path=tmp_path / "checkpoint.json")
    summary = engine.run(plan)
    assert summary["tasks_total"] == summary["tasks_done"]
    assert summary["observations"] >= 3
    assert summary["entities"] >= 3 and summary["edges"] >= 2
    # every observation must be evidence-linked
    assert all(o.evidence_id for o in engine.observations)
    # evidence integrity + dedup registry persisted
    for o in engine.observations:
        assert ev.verify(o.evidence_id)
    assert (tmp_path / "checkpoint.json").exists()
    # graph reloads from disk (canonical rebuild)
    reloaded = KnowledgeGraph(tmp_path / "graph.jsonl")
    assert len(reloaded.entities) == len(graph.entities)
    # entity for IP exists and is linked to the domain
    ip_ent = reloaded.find_entity(EntityKind.IP_ADDRESS, "93.184.216.34")
    dom_ent = reloaded.find_entity(EntityKind.DOMAIN, "example.com")
    assert ip_ent and dom_ent
    path = reloaded.shortest_path(dom_ent.entity_id, ip_ent.entity_id)
    assert path == [dom_ent.entity_id, ip_ent.entity_id]


def test_engine_resilient_to_dead_source(fake_world):
    tmp_path, ev, graph, connectors = fake_world
    connectors["crtsh"] = FakeConnector("crtsh", {})  # will fail every call
    spec = ObjectiveParser().parse("Map infrastructure of example.com, passive only.")
    plan = Planner(SourceRegistry.load_default()).plan(spec)
    engine = InvestigationEngine(case_id="case_partial", evidence_store=ev, graph=graph,
                                 connectors=connectors,
                                 config=EngineConfig(max_workers=2, base_backoff_s=0.01))
    summary = engine.run(plan)
    # partial failure tolerated; other tasks still completed
    assert summary["tasks_done"] == summary["tasks_total"]
    failed = [r for r in engine.results.values() if r.status == TaskStatus.FAILED]
    assert failed, "expected the dead-source task to fail honestly"


def test_kill_switch_stops_execution(fake_world):
    tmp_path, ev, graph, connectors = fake_world
    spec = ObjectiveParser().parse("Map infrastructure of example.com, passive only.")
    plan = Planner(SourceRegistry.load_default()).plan(spec)
    engine = InvestigationEngine(case_id="case_killed", evidence_store=ev, graph=graph,
                                 connectors=connectors,
                                 config=EngineConfig(max_workers=1, base_backoff_s=0.01))
    engine.kill = True
    summary = engine.run(plan)
    assert summary["cancelled"] is True


def test_resolver_conservative_person_policy():
    r = EntityResolver()
    a = Entity(kind=EntityKind.PERSON, display_name="John Smith")
    b = Entity(kind=EntityKind.PERSON, display_name="Johnny Smith")
    d = r.compare(a, b)
    assert d.state in ("UNRESOLVED", "POSSIBLE_MATCH")
    assert not r.apply_merge.__self__ is None
    # apply_merge refuses non-verified states
    class G:  # minimal stub graph to prove refusal before mutation
        entities = {}
        relationships = {}
    assert r.apply_merge(G(), d) is False


def test_evidence_dedup_and_integrity(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    e1 = store.put_bytes(b"same bytes", "https://a.example/x", case_id="c1")
    e2 = store.put_bytes(b"same bytes", "https://b.example/y", case_id="c1")
    assert e1.sha256 == e2.sha256 and e1.evidence_id != e2.evidence_id
    assert store.verify(e1.evidence_id)
    tampered = store.read_bytes(e1.evidence_id) + b"!"
    assert not e1.verify_integrity(tampered)


# ------------------------------------------------------------------ live canary
def _internet_ok():
    try:
        socket.create_connection(("data.iana.org", 443), timeout=3)
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _internet_ok(), reason="no outbound internet in sandbox")
def test_live_rdap_canary():
    from traceatlas.sources.connectors.rdap import RDAPConnector
    res = RDAPConnector(timeout=20).collect("example.com")
    assert res.ok, res.error
    preds = {o["predicate"] for o in res.observations}
    assert "registrar" in preds
    assert res.raw_bytes and len(res.raw_bytes) > 100


@pytest.mark.skipif(not _internet_ok(), reason="no outbound internet in sandbox")
def test_live_dns_a_canary():
    from traceatlas.sources.connectors.dns import DNSConnector
    res = DNSConnector().collect("example.com", "dns.A")
    assert res.ok, res.error
    assert any("." in str(o["value"]) for o in res.observations)
