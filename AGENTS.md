# Coding Agent Instructions

- Never claim a capability exists unless its module is implemented AND covered by a passing test.
- Keep docstrings truthful; mark stubs explicitly.
- All external network access goes through `traceatlas/sources/connectors` with SSRF + rate-limit + evidence-capture enforced.
- Every mutation of evidence/entities/graph must be audited and reversible where designed.
- Update `.ai/*` ledgers when you complete or discover work.
- Run `make check` before finishing; do not delete failing tests to go green.
