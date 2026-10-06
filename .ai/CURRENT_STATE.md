# CURRENT_STATE (updated 2026-10-06)

## Verified working vertical slice (P0 core, domain investigation)
Objective text -> ObjectiveParser (targets/constraints/ambiguities) -> authorization gate
(refuses without valid Authorization or explicit --authorized assertion) -> Planner
(capability/source registry-driven, waves 1..4) -> InvestigationEngine (bounded concurrency,
retry+backoff+jitter, kill switch, cancellation, checkpoints, audit log) -> real connectors
(DNS system resolver, RDAP via IANA bootstrap [LIVE_VERIFIED in sandbox], HTTP GET with SSRF
guard + redirect re-check, crt.sh CT [rate-limited upstream]) -> EvidenceStore (content-addressed
SHA-256 blobs, dedup, JSONL registry, integrity verify) -> Observations (all evidence-linked)
-> KnowledgeGraph (JSONL persistence, rebuild-from-disk tested, entity dedup, k-hop/BFS path,
components, temporal validity) -> EntityResolver V3 core (normalize/exact/fuzzy, conservative
person policy: never merges PERSON/USERNAME on name similarity alone without corroboration;
merge is logged/reversible-record) -> CLI (`python -m traceatlas.cli.main investigate|sources|evidence|graph|doctor`).

## Truthful maturity ledger
- Connectors implemented for real: 4 (dns-system, rdap-iana-bootstrap, web-direct, crtsh).
  Qualification: integration_tested. RDAP + DNS additionally live-tested in this environment
  (crt.sh returned upstream 5xx under rate limiting -> honest failure recorded, task FAILED,
  run continued). NO source is claimed LIVE_VERIFIED/PQ at scale. The ~1100-source target and
  the catalog remain NOT achieved; catalog YAML loading exists but repo has no populated catalog yet.
- tests/golden/test_vertical_slice.py: 10 passed (incl. 2 live canaries when internet present).
- Known limitations (see KNOWN_ISSUES): PostgreSQL persistence not wired (filesystem workspaces),
  API routes thin, frontend absent, AI Employee runtime/orchestrator still stubs, model gateway
  unimplemented, source independence/contradiction engines not operational, transforms/machines
  scaffold-only, IAM/OIDC missing. Many other files in tree remain STUBs (audit basis: grep STUB).
