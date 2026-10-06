#!/usr/bin/env bash
set -euo pipefail
uv run ruff check . && pnpm lint
