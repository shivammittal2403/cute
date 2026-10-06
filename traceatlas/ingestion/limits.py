"""traceatlas.ingestion.limits - Resource limits for hostile-input safety.

Every numeric ceiling the pipeline enforces lives here so policy is auditable
in one place. Defaults are conservative; per-session overrides flow through
ImportRequest and are themselves clamped to hard maximums.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True, slots=True)
class IngestionLimits:
    # --- file / directory walk -------------------------------------------
    max_file_bytes: int = 2 * 1024**3              # single artifact cap (2 GiB)
    max_total_bytes: int = 20 * 1024**3            # session-wide input cap
    max_files: int = 50_000                        # files per session
    max_depth: int = 24                            # directory recursion depth
    # --- archive safety ----------------------------------------------------
    max_archive_members: int = 100_000
    max_member_bytes: int = 4 * 1024**3
    max_extracted_bytes: int = 8 * 1024**3         # post-extraction total
    max_compression_ratio: float = 1000.0          # decompressed/compressed
    max_nesting_depth: int = 4                     # archive-in-archive levels
    follow_symlinks: bool = False                  # symlink policy for walks
    allow_symlink_members: bool = False            # never materialize links by default
    # --- parsing ------------------------------------------------------------
    max_records_preview: int = 200                 # rows sampled for schema inference
    max_strings: int = 200_000                     # generic binary strings extraction
    min_string_length: int = 5
    max_text_scan_bytes: int = 64 * 1024           # bytes inspected for detection
    max_line_bytes: int = 10 * 1024 * 1024         # streaming line reader guard
    # --- processing -----------------------------------------------------------
    batch_size: int = 500                          # records per persistence batch
    checkpoint_every: int = 50                     # artifacts between checkpoints

    HARD_MAX_FILE_BYTES = 32 * 1024**3

    def clamp(self) -> "IngestionLimits":
        """Return limits with any override above the hard ceiling pulled back."""
        values = asdict(self)
        if values["max_file_bytes"] > self.HARD_MAX_FILE_BYTES:
            values["max_file_bytes"] = self.HARD_MAX_FILE_BYTES
        if values["max_nesting_depth"] > 8:
            values["max_nesting_depth"] = 8
        if values["follow_symlinks"]:
            values["follow_symlinks"] = False      # not permitted regardless of config
        return IngestionLimits(**values)

    def to_dict(self) -> dict:
        return asdict(self)


DEFAULT_LIMITS = IngestionLimits()


def limits_from_env() -> IngestionLimits:
    """Build limits with TRACEATLAS_INGEST_* environment overrides (clamped)."""
    base = DEFAULT_LIMITS
    over: dict[str, object] = {}
    for f in base.__dataclass_fields__:
        env = os.environ.get(f"TRACEATLAS_INGEST_{f.upper()}")
        if env is None:
            continue
        cur = getattr(base, f)
        if isinstance(cur, bool):
            over[f] = env.lower() in ("1", "true", "yes")
        elif isinstance(cur, float):
            over[f] = float(env)
        else:
            over[f] = int(env)
    return IngestionLimits(**{**asdict(base), **over}).clamp()
