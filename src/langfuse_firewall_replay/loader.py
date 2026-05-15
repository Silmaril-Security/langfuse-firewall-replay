"""Load Langfuse Blob Storage export files."""

from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from langfuse_firewall_replay.models import LoadedObservation

SUPPORTED_SUFFIXES = (".json", ".jsonl", ".json.gz", ".jsonl.gz")
MAX_SINGLE_DOCUMENT_JSON_CHARS = 128 * 1024 * 1024


class ExportLoadError(ValueError):
    """Raised when an export file cannot be parsed safely."""


def is_supported_export_file(path: Path) -> bool:
    """Return true when a path looks like a supported Langfuse export file."""

    if not path.is_file():
        return False
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in SUPPORTED_SUFFIXES)


def discover_export_files(path: Path) -> list[Path]:
    """Return supported export files under a file or directory input.

    If a directory contains an ``observations_v2`` subtree, prefer those files
    to avoid accidentally replaying scores or legacy traces from the same blob
    export root.
    """

    path = path.expanduser()
    if path.is_file():
        if not is_supported_export_file(path):
            raise ValueError(f"Unsupported export file type: {path}")
        return [path]
    if not path.is_dir():
        raise FileNotFoundError(f"Input path does not exist: {path}")

    candidates = sorted(p for p in path.rglob("*") if is_supported_export_file(p))
    observation_files = [
        p for p in candidates if any(part == "observations_v2" for part in p.parts)
    ]
    return observation_files or candidates


def _open_text(path: Path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _rows_from_json_payload(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(payload, dict):
        for key in ("data", "observations", "rows", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
                return
        if "trace_id" in payload or "id" in payload or "input" in payload:
            yield payload


def _json_decode_error(path: Path, exc: json.JSONDecodeError, *, line_no: int | None = None) -> ExportLoadError:
    location = f"{path}"
    if line_no is not None:
        location += f":{line_no}"
    else:
        location += f":{exc.lineno}"
    return ExportLoadError(f"Invalid JSON in {location}:{exc.colno}: {exc.msg}")


def _load_single_json_document(fh, path: Path) -> Any:
    chunks: list[str] = []
    total = 0
    while True:
        chunk = fh.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_SINGLE_DOCUMENT_JSON_CHARS:
            raise ExportLoadError(
                f"{path} is too large to parse as a single JSON document. "
                "Use a JSONL export for large replay inputs."
            )
        chunks.append(chunk)
    try:
        return json.loads("".join(chunks))
    except json.JSONDecodeError as exc:
        raise _json_decode_error(path, exc) from exc


def iter_export_file(path: Path) -> Iterator[LoadedObservation]:
    """Yield rows from one supported JSON/JSONL export file."""

    path = path.expanduser()
    is_jsonl = path.name.lower().endswith(".jsonl") or path.name.lower().endswith(".jsonl.gz")

    with _open_text(path) as fh:
        if is_jsonl:
            for line_no, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise _json_decode_error(path, exc, line_no=line_no) from exc
                if isinstance(payload, dict):
                    yield LoadedObservation(
                        row=payload,
                        source_path=str(path),
                        source_line=line_no,
                    )
            return

        payload = _load_single_json_document(fh, path)
        for row in _rows_from_json_payload(payload):
            yield LoadedObservation(row=row, source_path=str(path))


def load_export_file(path: Path) -> list[LoadedObservation]:
    """Load one supported JSON/JSONL export file."""

    return list(iter_export_file(path))


def iter_observations(path: Path) -> Iterator[LoadedObservation]:
    """Yield observations from a supported file or directory input."""

    for export_file in discover_export_files(path):
        yield from iter_export_file(export_file)


def load_observations(path: Path) -> list[LoadedObservation]:
    """Load all observations from a supported file or directory input."""

    return list(iter_observations(path))
