"""Write replay artifacts."""

from __future__ import annotations

import json
import secrets
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from langfuse_firewall_replay.models import ReplayResult

PREVIEW_CHARS = 240


def timestamped_run_dir(root: Path = Path("runs")) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return root / f"langfuse-firewall-replay-{stamp}-{secrets.token_hex(3)}"


def _identifier_hash(value: str, salt: str) -> str:
    digest = sha256(f"{salt}\0{value}".encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _identifier(value: str | None, *, hash_identifiers: bool, identifier_salt: str) -> str | None:
    if value is None:
        return None
    if not hash_identifiers:
        return value
    return _identifier_hash(value, identifier_salt)


def _preview(text: str) -> str:
    one_line = " ".join(text.split())
    return one_line[:PREVIEW_CHARS]


def result_record(
    result: ReplayResult,
    *,
    include_text: bool = False,
    include_preview: bool = False,
    include_error_details: bool = False,
    hash_identifiers: bool = True,
    identifier_salt: str = "",
    include_source_paths: bool = False,
) -> dict[str, Any]:
    item = result.item
    record: dict[str, Any] = {
        "item_id": _identifier(
            item.item_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        ),
        "trace_id": _identifier(
            item.trace_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        ),
        "observation_id": _identifier(
            item.observation_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        ),
        "observation_type": item.observation_type,
        "observation_name": item.observation_name,
        "hook": item.hook,
        "tool_name": item.tool_name,
        "source_field": item.source_field,
        "prediction": result.prediction,
        "score": result.score,
        "threshold": result.threshold,
        "blocked": result.blocked,
        "primary_outcome": result.primary_outcome,
        "outcome_scores": result.outcome_scores,
        "detector_scores": result.detector_scores,
        "detector_counts": result.detector_counts,
        "error_class": result.error_class,
        "error": result.error if include_error_details else None,
        "dry_run": result.dry_run,
        "text_hash": _identifier_hash(item.text, identifier_salt),
        "text_length": len(item.text),
        "project_id": _identifier(
            item.project_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        ),
        "environment": item.environment,
        "session_id": _identifier(
            item.session_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        ),
        "user_id": _identifier(
            item.user_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        ),
        "trace_name": item.trace_name,
        "start_time": item.start_time,
        "source_path": item.source_path if include_source_paths else None,
        "source_line": item.source_line,
    }
    if include_preview:
        record["text_preview"] = _preview(item.text)
    if include_text:
        record["text"] = item.text
    return record


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def _new_trace_aggregate() -> dict[str, Any]:
    return {
        "item_count": 0,
        "malicious_count": 0,
        "error_count": 0,
        "max_score": None,
        "top_item_id": None,
        "top_hook": None,
        "top_tool_name": None,
        "hooks": set(),
        "tools": set(),
        "trace_name": None,
        "session_id": None,
        "user_id": None,
    }


def _update_trace_aggregate(
    aggregate: dict[str, Any],
    result: ReplayResult,
    *,
    hash_identifiers: bool,
    identifier_salt: str,
) -> None:
    item = result.item
    aggregate["item_count"] += 1
    if result.prediction == "MALICIOUS":
        aggregate["malicious_count"] += 1
    if result.error_class:
        aggregate["error_count"] += 1
    if item.hook:
        aggregate["hooks"].add(item.hook)
    if item.tool_name:
        aggregate["tools"].add(item.tool_name)
    if aggregate["trace_name"] is None and item.trace_name:
        aggregate["trace_name"] = item.trace_name
    if aggregate["session_id"] is None and item.session_id:
        aggregate["session_id"] = _identifier(
            item.session_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        )
    if aggregate["user_id"] is None and item.user_id:
        aggregate["user_id"] = _identifier(
            item.user_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        )

    if result.score is None:
        return
    if aggregate["max_score"] is None or float(result.score) > float(aggregate["max_score"]):
        aggregate["max_score"] = result.score
        aggregate["top_item_id"] = _identifier(
            item.item_id,
            hash_identifiers=hash_identifiers,
            identifier_salt=identifier_salt,
        )
        aggregate["top_hook"] = item.hook
        aggregate["top_tool_name"] = item.tool_name


def _trace_summary_rows(trace_aggregates: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for trace_id, aggregate in sorted(trace_aggregates.items()):
        rows.append(
            {
                "trace_id": trace_id,
                "item_count": aggregate["item_count"],
                "malicious_count": aggregate["malicious_count"],
                "error_count": aggregate["error_count"],
                "max_score": aggregate["max_score"],
                "top_item_id": aggregate["top_item_id"],
                "top_hook": aggregate["top_hook"],
                "top_tool_name": aggregate["top_tool_name"],
                "hooks": sorted(aggregate["hooks"]),
                "tools": sorted(aggregate["tools"]),
                "trace_name": aggregate["trace_name"],
                "session_id": aggregate["session_id"],
                "user_id": aggregate["user_id"],
            }
        )
    return rows


def _resolve_count(value: int | Callable[[], int]) -> int:
    return value() if callable(value) else value


def _resolve_skipped(value: dict[str, int] | Callable[[], dict[str, int]]) -> dict[str, int]:
    return value() if callable(value) else value


def write_reports(
    out_dir: Path,
    *,
    results: Iterable[ReplayResult],
    observation_count: int | Callable[[], int],
    skipped: dict[str, int] | Callable[[], dict[str, int]],
    config: dict[str, Any],
    include_text: bool = False,
    include_preview: bool = False,
    include_error_details: bool = False,
    hash_identifiers: bool = True,
    identifier_salt: str = "",
    include_source_paths: bool = False,
) -> dict[str, Path]:
    """Write results, trace summaries, and aggregate summary JSON."""

    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "results": out_dir / "results.jsonl",
        "trace_summary": out_dir / "trace_summary.jsonl",
        "summary": out_dir / "summary.json",
    }

    predictions: Counter[str] = Counter()
    hooks: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    scores: list[float] = []
    trace_aggregates: dict[str, dict[str, Any]] = defaultdict(_new_trace_aggregate)
    replay_count = 0

    with paths["results"].open("w", encoding="utf-8") as fh:
        for result in results:
            replay_count += 1
            if result.prediction:
                predictions[result.prediction] += 1
            if result.item.hook:
                hooks[result.item.hook] += 1
            if result.error_class:
                errors[result.error_class] += 1
            if result.score is not None:
                scores.append(float(result.score))

            trace_id = _identifier(
                result.item.trace_id or "unknown",
                hash_identifiers=hash_identifiers,
                identifier_salt=identifier_salt,
            )
            _update_trace_aggregate(
                trace_aggregates[trace_id or "unknown"],
                result,
                hash_identifiers=hash_identifiers,
                identifier_salt=identifier_salt,
            )
            row = result_record(
                result,
                include_text=include_text,
                include_preview=include_preview,
                include_error_details=include_error_details,
                hash_identifiers=hash_identifiers,
                identifier_salt=identifier_salt,
                include_source_paths=include_source_paths,
            )
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    trace_rows = _trace_summary_rows(trace_aggregates)
    summary = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "counts": {
            "observations": _resolve_count(observation_count),
            "replay_items": replay_count,
            "traces": len(trace_aggregates),
            "predictions": dict(predictions),
            "hooks": dict(hooks),
            "skipped": _resolve_skipped(skipped),
            "errors": dict(errors),
        },
        "scores": {
            "max": max(scores) if scores else None,
            "mean": (sum(scores) / len(scores)) if scores else None,
        },
    }
    _write_jsonl(paths["trace_summary"], trace_rows)
    _write_json(paths["summary"], summary)
    return paths
