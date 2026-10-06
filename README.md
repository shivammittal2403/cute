# TraceAtlas-Automator

An AI-employee-driven open source intelligence (OSINT) and investigation
platform: governed source collection, evidence with provenance, entity
resolution, a temporal knowledge graph, contradiction detection, verification,
and report generation.

## Current status (truthful)

This repository is at the **scaffold stage**. The package layout, contracts,
configuration, and documentation skeletons exist. Most module bodies are
stubs; no end-to-end investigation has been certified yet. See
`docs/CURRENT_STATE.md`, `.ai/CURRENT_STATE.md`, and `ROADMAP.md`.

## Quickstart (once backend modules are implemented)

```bash
uv sync                       # install Python dependencies
cp .env.example .env          # fill in secrets
docker compose up -d          # postgres, redis, minio, api, worker
uv run traceatlas doctor      # verify configuration
uv run uvicorn traceatlas.api.app:app --reload   # API on :8000
pnpm install && pnpm --filter web dev            # investigator UI on :3000
```

## Layout

See `ARCHITECTURE.md` for the top-level map and `docs/` for subsystem detail.

## License

See `LICENSE`.
