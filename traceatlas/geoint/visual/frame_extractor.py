"""traceatlas.geoint.visual.frame_extractor - Video frame sampling.

Deterministic sampler interface: real deployments plug ffmpeg/OpenCV; tests use
a stub. Every extracted frame becomes retained evidence with its timestamp so
clues can be traced back to a specific moment (section 18 temporal fields).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(slots=True)
class ExtractedFrame:
    frame_index: int
    timestamp_s: float
    image_bytes: bytes = b""
    notes: str = ""


class FrameSource(Protocol):
    def duration_s(self) -> float: ...
    def extract(self, timestamps_s: list[float]) -> list[ExtractedFrame]: ...


def sample_uniform(duration_s: float, count: int = 8,
                   margin_frac: float = 0.05) -> list[float]:
    """Uniform timestamps avoiding first/last frames (often black/fades)."""
    if duration_s <= 0 or count <= 0:
        return []
    count = max(1, min(count, int(duration_s * 2)))   # cap ~2 fps sampling
    start, end = duration_s * margin_frac, duration_s * (1 - margin_frac)
    if end <= start:
        return [duration_s / 2]
    step = (end - start) / max(1, count - 1) if count > 1 else 0
    return [round(start + i * step, 3) for i in range(count)]


def sample_scene_change(candidate_timestamps: list[float],
                        detector=None) -> list[float]:
    """Optional scene-change refinement. `detector(ts_list)->bool list` is
    pluggable; without one, returns candidates unchanged (documented limit:
    video_frame_sampling)."""
    if detector is None:
        return list(candidate_timestamps)
    flags = detector(candidate_timestamps)
    return [t for t, keep in zip(candidate_timestamps, flags) if keep]
