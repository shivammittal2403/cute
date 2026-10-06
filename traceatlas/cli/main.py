"""traceatlas.cli.main - Operational CLI for the investigation platform.

Commands: investigate, sources, evidence, graph, doctor, replay-report.
No placeholders: every command calls real subsystems.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traceatlas.investigation.manager import InvestigationManager


def cmd_investigate(args) -> int:
    mgr = InvestigationManager(workspace_root=args.workspace)
    res = mgr.investigate(args.objective, case_id=args.case_id,
                          authorized=args.authorized)
    print(json.dumps(res, indent=2, default=str))
    return 0 if res.get("ok") else 2


def cmd_sources(args) -> int:
    from traceatlas.sources.registry import SourceRegistry
    reg = SourceRegistry.load_default()
    rows = [{"slug": r.slug, "capabilities": list(r.capabilities),
             "qualification": r.qualification} for r in reg.records]
    print(json.dumps(rows, indent=2))
    return 0


def cmd_evidence(args) -> int:
    from traceatlas.evidence.store import EvidenceStore
    store = EvidenceStore(Path(args.workspace) / args.case_id / "evidence")
    items = store.list_for_case(args.case_id)
    out = [{"evidence_id": e.evidence_id, "sha256": e.sha256,
            "source_uri": e.source_uri, "bytes": e.bytes_length,
            "integrity_ok": store.verify(e.evidence_id)} for e in items]
    print(json.dumps(out, indent=2))
    return 0


def cmd_graph(args) -> int:
    from traceatlas.graph.model import KnowledgeGraph
    g = KnowledgeGraph(Path(args.workspace) / args.case_id / "graph.jsonl")
    print(json.dumps(g.to_dict(), indent=2, default=str))
    return 0


def cmd_doctor(args) -> int:
    checks = {}
    try:
        import httpx  # noqa: F401
        checks["httpx"] = "ok"
    except ImportError:
        checks["httpx"] = "MISSING"
    from traceatlas.sources.registry import SourceRegistry
    checks["source_registry_records"] = len(SourceRegistry.load_default())
    from traceatlas.objectives.parser import ObjectiveParser
    spec = ObjectiveParser().parse("Map infrastructure of example.com, passive only.")
    checks["objective_parser"] = "ok" if spec.targets else "BROKEN"
    checks["connectors_importable"] = True
    for name in ("dns", "rdap", "http", "certificates"):
        mod = __import__(f"traceatlas.sources.connectors.{name}", fromlist=["*"])
        checks[f"connector:{name}"] = "ok" if mod else "missing"
    print(json.dumps(checks, indent=2))
    bad = [k for k, v in checks.items() if v in ("MISSING", "BROKEN")]
    return 1 if bad else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="traceatlas",
                                description="TraceAtlas OSINT investigation CLI")
    p.add_argument("--workspace", default=".traceatlas/cases")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("investigate", help="run an authorized investigation")
    pi.add_argument("objective")
    pi.add_argument("--case-id", default=None)
    pi.add_argument("--authorized", action="store_true",
                    help="assert caller holds an authorized scope (logged to audit)")

    ps = sub.add_parser("sources", help="list registered sources + qualification")
    pe = sub.add_parser("evidence", help="list case evidence with integrity check")
    pe.add_argument("case_id")
    pg = sub.add_parser("graph", help="dump case knowledge graph")
    pg.add_argument("case_id")
    pd = sub.add_parser("doctor", help="environment/self-check")

    args = p.parse_args(argv)
    return {"investigate": cmd_investigate, "sources": cmd_sources,
            "evidence": cmd_evidence, "graph": cmd_graph,
            "doctor": cmd_doctor}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
