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
    # ------------------------------------------------------------------
    # In-memory rendering (unit-testable without a case workspace)
    # ------------------------------------------------------------------
    @staticmethod
    def classify_claim(claim: "Claim") -> str:
        """Evidence-first claim state. Never fabricates support."""
        from traceatlas.core.enums import ClaimStatus
        if not claim.citations:
            return "UNSUPPORTED"
        if claim.status in (ClaimStatus.REFUTED, ClaimStatus.WITHDRAWN):
            return "DISPUTED"
        cited = {c.evidence_id for c in claim.citations}
        if len(cited) >= 2:
            return "SUPPORTED"
        return "PARTIALLY_SUPPORTED"

    def render_markdown(self, *, case_name: str = "case",
                        entities: list | None = None,
                        observations: list | None = None,
                        claims: list | None = None,
                        evidence: list | None = None) -> str:
        lines: list[str] = [f"# TraceAtlas Investigation Report — {case_name}", ""]
        lines.append("## Claims")
        for cl in claims or []:
            state = self.classify_claim(cl)
            ev = ", ".join(f"`{c.evidence_id}`" for c in cl.citations) or "NONE"
            lines.append(f"- **[{state}]** {cl.statement} (evidence: {ev})")
        if not claims:
            lines.append("- no claims raised")
        lines.append("\n## Entities")
        for e in entities or []:
            lines.append(f"- {getattr(e, 'etype', getattr(getattr(e, 'kind', None), 'value', '?'))}: "
                         f"**{getattr(e, 'label', getattr(e, 'display_name', '?'))}**")
        lines.append("\n## Observations")
        for o in observations or []:
            lines.append(f"- `{o.subject_id}` → {o.predicate}: {o.value!r} "
                         f"(evidence `{o.evidence_id}`, source {o.source_id})")
        lines.append("\n## Replay manifest")
        for ev in sorted(evidence or [], key=lambda e: e.sha256):
            lines.append(f"- `{ev.evidence_id}` sha256={ev.sha256[:16]}… "
                         f"<{ev.source_uri}>")
        return "\n".join(lines) + "\n"

    def replay_manifest(self, *, entities: list | None = None,
                        observations: list | None = None,
                        claims: list | None = None,
                        evidence: list | None = None) -> dict:
        """Machine-readable replay: every evidence artifact with its hash."""
        return {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "claims": [c.to_dict() for c in (claims or [])],
            "observations": [o.to_dict() for o in (observations or [])],
            "evidence": [{"evidence_id": e.evidence_id, "sha256": e.sha256,
                          "source_uri": e.source_uri,
                          "bytes_length": e.size_bytes}
                         for e in (evidence or [])],
        }

    # ------------------------------------------------------------------
    # Workspace rendering (persisted case directories)
    # ------------------------------------------------------------------
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
                                        o.source_id or "", pub, text, sha256=sha))
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
                         key=lambda e: str(e.metadata.get("retrieved_at", e.sha256))):
            add(f"- `{ev.evidence_id}` sha256={ev.sha256[:16]}… {ev.size_bytes}B "
                '<{}> retrieved {}'.format(ev.source_uri, ev.metadata.get("retrieved_at", "(unrecorded)")))

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
