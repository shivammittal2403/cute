.PHONY: setup dev start stop test lint typecheck migrate seed doctor check

setup:
	uv sync && pnpm install

dev:
	uv run uvicorn traceatlas.api.app:app --reload

start:
	docker compose up -d

stop:
	docker compose down

test:
	uv run pytest

lint:
	uv run ruff check . && pnpm lint

typecheck:
	uv run mypy traceatlas && pnpm typecheck

migrate:
	uv run alembic upgrade head

seed:
	uv run python scripts/seed.py && uv run python scripts/seed_sources.py

doctor:
	uv run traceatlas doctor

check: lint typecheck test
