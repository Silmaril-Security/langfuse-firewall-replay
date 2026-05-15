"""Shared dataclasses for replay extraction and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LoadedObservation:
    """One row read from a Langfuse export file."""

    row: dict[str, Any]
    source_path: str
    source_line: int | None = None


@dataclass(frozen=True)
class ReplayItem:
    """One firewall classification opportunity extracted from a Langfuse row."""

    item_id: str
    text: str
    hook: str
    source_field: str
    trace_id: str | None = None
    observation_id: str | None = None
    observation_type: str | None = None
    observation_name: str | None = None
    tool_name: str | None = None
    project_id: str | None = None
    environment: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    trace_name: str | None = None
    start_time: str | None = None
    source_path: str | None = None
    source_line: int | None = None


@dataclass(frozen=True)
class ExtractionResult:
    """Replay items and skip counters for one or more observations."""

    items: list[ReplayItem]
    skipped: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ReplayResult:
    """Firewall result or local dry-run/error status for one replay item."""

    item: ReplayItem
    prediction: str | None = None
    score: float | None = None
    threshold: float | None = None
    blocked: bool | None = None
    primary_outcome: str | None = None
    outcome_scores: dict[str, float] | None = None
    detector_scores: dict[str, float] | None = None
    detector_counts: dict[str, int] | None = None
    error_class: str | None = None
    error: str | None = None
    dry_run: bool = False
