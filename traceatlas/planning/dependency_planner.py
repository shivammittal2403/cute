"""traceatlas.planning.dependency_planner - Standard dependency chains."""
from __future__ import annotations

COLLECT_EXTRACT = "extract depends on collect"
RESOLVE_AFTER_EXTRACT = "resolve depends on extract"
VERIFY_AFTER_RESOLVE = "verify depends on correlate"
