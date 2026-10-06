#!/usr/bin/env bash
set -euo pipefail
uv run uvicorn traceatlas.api.app:app --reload
