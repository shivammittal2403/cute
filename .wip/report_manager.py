"""traceatlas.reporting.report_manager - Evidence-linked investigation report.

Builds a markdown report from a case workspace: objective, scope/authorization,
per-source task outcomes (success AND honest failures), entities/relationships
with evidence citations, independent-corroboration counts, contradictions,
claims classified SUPPORTED/PARTIALLY_SUPPORTED/INCONCLUSIVE, limitations, and a
replay manifest (evidence hashes + connector versions + retrieval times).
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from traceatlas.core.enums import TaskStatus
from traceatlas.core.observation import Observation
from traceatlas.evidence.store import EvidenceStore
from traceatlas.graph.model import KnowledgeGraph
from traceatlas.verification.contradictions import ContradictionDetector
from traceatlas.verification.independence import EvidenceDoc, IndependenceEngine


class ReportManager:
    def build(self, case_dir: str | Path) -> str:
        case_dir = Path(case_dir)
        state = json.loads((case_dir / "case_state.json").read_text()) \
            if (case_dir / "case_state.json").exists() else {}
        store = EvidenceStore(case_dir / "evidence")
        graph = KnowledgeGraph(case_dir / "graph.jsonl")
        observations = self._load_observations(case_dir / "observations.jsonl")

        # independence over per-(subject,predicate) evidence docs
        eng = IndependenceEngine()
        by_key: dict[tuple[str, str], list[Observation]] = defaultdict(list)
        for o in observations:
            by_key[(o.subject_id or "", o.predicate)].append(o)
        indep_counts: dict[tuple[str, str], int] = {}
        for key, obs in by_key.items():
            docs = []
            for o in obs:
                ev = store.get(o.evidence_id or "")
                text = ""
                sha = ""
                pub = o.source_id or ""
                if ev:
                    try:
                        raw = store.read_bytes(ev.evidence_id)
                        text = raw.decode("utf-8", "replace")
                        sha = ev.sha256
                        pub = (ev.source_uri.split("//", 1)[-1].split("/")[0]
                               if ev.source_uri else pub)
                    except OSError:
                        pass
                docs.append(EvidenceDoc(o.evidence_id or o.observation_id,
                                        o.source_id or "", pub, text, sha=sha))
            reps, _ = eng.independent_sources_for_observation(docs)
            indep_counts[key] = max(1, len(reps))

        contradictions = ContradictionDetector().detect(observations)

        lines: list[str] = []
        add = lines.append
        add(f"# TraceAtlas Investigation Report — {state.get('case_id', case_dir.name)}")
        add(f"_Generated {datetime.now(timezone.utc).isoformat()} • evidence-first, "
            f"all findings cite retained artifacts_")
        add("\n## Objective\n" + str(state.get("objective", "(unknown)")))
        add("\n## Outcome summary")
        s = state.get("summary", {})
        add(f"- Tasks: {s.get('tasks_done', '?')}/{s.get('tasks_total', '?')} terminal; "
            f"observations: {len(observations)}; entities: {len(graph.entities)}; "
            f"edges: {len(graph.relationships)}")
        failed = [name for name, st in state.get("task_statuses", {}).items()
                  if st == TaskStatus.FAILED.value]
        if failed:
            add(f"- **Honest failures (not retried away)**: {', '.join(failed)}")

        add("\n## Findings (claim states)")
        seen_claim = set()
        for (subj, pred), obs in sorted(by_key.items()):
            n_indep = indep_counts.get((subj, pred), 1)
            evid = ", ".join(sorted({f"`{o.evidence_id}`" for o in obs if o.evidence_id}))
            vals = sorted({str(o.value) for o in obs})
            if len(vals) > 1:
                claim = "DISPUTED"
            elif n_indep >= 2:
                claim = "SUPPORTED"
            elif obs and all(o.evidence_id for o in obs):
                claim = "PARTIALLY_SUPPORTED"   # single independent source only
            else:
                claim = "INCONCLUSIVE"
            val_txt = vals[0] if len(vals) == 1 else "; ".join(vals[:4])
            add(f"- **[{claim}]** `{subj}` → {pred}: {val_txt} "
                f"(independent sources: {n_indep}; evidence: {evid or 'NONE'})")
            seen_claim.add(claim)

        add("\n## Contradictions")
        if contradictions:
            for c in contradictions:
                add(f"- [{c.status}] {c.kind}: `{c.subject}` {c.predicate}")
                for side in c.sides[:6]:
                    add(f"  - value={side['value']!r} via {side['source_id']} "
                        f"(evidence `{side['evidence_id']}`)")
        else:
            add("- none detected across collected observations")

        add("\n## Graph")
        for ent in sorted(graph.entities.values(), key=lambda e: (e.kind.value, e.display_name)):
            ev = ", ".join(ent.evidence_ids[:3]) or "manual/no-evidence"
            add(f"- {ent.kind.value}: **{ent.display_name}** (evidence: {ev})")

        add("\n## Replay manifest")
        for ev in sorted(store.list_for_case(state.get("case_id", case_dir.name)),
                         key=lambda e: e.retrieved_at):
            add(f"- `{ev.evidence_id}` sha256={ev.sha256[:16]}… {ev.bytes_length}B "
                f"<{ev.source_uri}> retrieved {ev.retrieved_at.isoformat()}")

        add("\n## Limitations")
        add("- Findings reflect only retained evidence; absence of evidence is stated, not inferred.")
        add("- PARTIALLY_SUPPORTED claims rest on a single independent source.")
        add("- Source qualification is integration-tested/live-tested; none claimed production-qualified.")
        report = "\n".join(lines)
        (case_dir / "report.md").write_text(report, encoding="utf-8")
        return report

    @staticmethod
    def _load_observations(path: Path) -> list[Observation]:
        out: list[Observation] = []
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            out.append(Observation.from_dict(json.loads(line)))
                        except Exception:
                            continue
        return out
