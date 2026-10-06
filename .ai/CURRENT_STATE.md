# CURRENT STATE — audited 2026-10-06 @ commit f8c741e

## Verified working (39 tests pass: golden + unit)
- core domain model (40 modules, real)
- objectives parser pipeline, deterministic planner (+semantic proposal path)
- evidence store (SHA-256 content-addressed, dedup, integrity)
- REAL connectors: DNS, RDAP(IANA bootstrap), HTTP+SSRF guard, crt.sh, ipwhois.co,
  BGP.tools prefix owner, RIR whois prefixes, HackerTarget rDNS, Wayback CDX
  -> status: INTEGRATION_TESTED (NOT live_verified at scale)
- transforms engine: 8 typed evidence-producing pivots wired to real connectors
- graph (JSONL persisted, rebuildable, k-hop/shortest-path/components)
- entity resolution conservative core (person-merge policy enforced)
- independence clustering (hash/shingle/minhash), contradiction detection
- investigation engine (waves/retry/kill-switch/checkpoints) + manager
- AI Employee runtime (typed envelopes, dispatcher) + autonomous investigator loop
- report manager + replay manifest; CLI investigate/sources/evidence/graph/doctor

## Honest gaps (NO fake progress)
- 669/763 traceatlas/*.py files are scaffold stubs (see FILE_IMPLEMENTATION_LEDGER.json).
  Real code lives in ~94 files. Stubs will be REMOVED-BY-IMPLEMENTATION per vertical slice,
  not counted as architecture.
- Entire planes MISSING: machines/, blockchain/, darkint/, watch/, search/, events/,
  extensions/, mcp/, collaboration/, iam/, data_governance/, sre/, research_environment/
- api/ = 0 routes implemented; db/ = no SQLAlchemy models/migrations (filesystem persistence only)
- ai/ gateway = unimplemented (no providers); employees/ + intelligence/ legacy trees = stubs
  (superseded by ai_employees/ — DELETE justified once slices migrate)
- web/ UI pages not wired to backend; security/ policy checks exist only inside connectors/engine
- source catalog YAMLs are DOCUMENTED records, not integrations (~1100 target untouched)
- LIVE_VERIFIED count: 0 formally promoted (live canaries run but qualification ledger pending)

## Priority queue (P0 order from master prompt)
1. PostgreSQL persistence (SQLAlchemy models + alembic migrations) replacing fs-only path
2. FastAPI real routes over manager/graph/evidence/report
3. AI gateway (Ollama-first adapter + fallback chain) used by semantic planner/investigator
4. machines/ execution layer over transforms (domain_footprint.yaml first)
5. expand real connectors toward 25 with fixture+failure tests each
6. Graph Studio API + web wiring; IAM/RBAC before multi-tenant claims
