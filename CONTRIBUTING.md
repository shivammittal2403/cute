# Contributing

1. Read `AGENTS.md` and `docs/ACCEPTANCE_GATES.md`.
2. Create an issue first for non-trivial changes.
3. Branch from `main`, keep PRs small, add tests with every behavior change.
4. Run `make lint typecheck test` locally before requesting review.
5. Source/connector additions must update `sources/catalog/*.yaml` and pass canary tests.
