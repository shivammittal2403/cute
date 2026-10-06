# Architecture Map

Layers (top → bottom):

1. **Web UI** (`web/`) — Next.js investigator console.
2. **API** (`traceatlas/api`) — FastAPI REST + WebSocket progress.
3. **AI Employees** (`traceatlas/employees`) — dispatcher/orchestrator over role workers with budgets, permissions, memory, handoffs.
4. **Investigation engine** (`traceatlas/investigation`, `traceatlas/planning`, `traceatlas/reasoning`) — plan → waves → tasks → knowledge state → next-best-action.
5. **Intelligence disciplines** (`traceatlas/intelligence/*`) — per-INT pipelines.
6. **Source fabric** (`traceatlas/sources` + `sources/` catalog) — governed connectors, qualification tiers, independence analysis.
7. **Truth layer** (`traceatlas/evidence`, `entities`, `graph`, `timeline`, `independence`, `verification`, `contradictions`).
8. **AI gateway** (`traceatlas/ai`) — provider routing, budgets, structured output, injection defenses.
9. **Reporting** (`traceatlas/reporting`) — citation-validated exports + replay manifests.
10. **Foundations** (`traceatlas/core`, `db`, `storage`, `security`, `policy`, `observability`, `evaluation`).

See `docs/architecture/` for details. Current implementation status: scaffold only.
