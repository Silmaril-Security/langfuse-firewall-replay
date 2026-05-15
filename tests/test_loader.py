from __future__ import annotations

import gzip
import json

import pytest

from langfuse_firewall_replay import loader
from langfuse_firewall_replay.loader import (
    ExportLoadError,
    discover_export_files,
    iter_observations,
    load_observations,
)


def test_load_jsonl_and_prefers_observations_v2_directory(tmp_path):
    export_root = tmp_path / "export"
    observations_dir = export_root / "project" / "observations_v2"
    scores_dir = export_root / "project" / "scores"
    observations_dir.mkdir(parents=True)
    scores_dir.mkdir(parents=True)
    (observations_dir / "rows.jsonl").write_text(
        '{"id":"obs-1","trace_id":"trace-1","type":"GENERATION","input":"hi"}\n',
        encoding="utf-8",
    )
    (scores_dir / "scores.jsonl").write_text('{"id":"score-1"}\n', encoding="utf-8")

    files = discover_export_files(export_root)
    rows = load_observations(export_root)

    assert files == [observations_dir / "rows.jsonl"]
    assert len(rows) == 1
    assert rows[0].row["id"] == "obs-1"
    assert rows[0].source_line == 1
    assert [row.row["id"] for row in iter_observations(export_root)] == ["obs-1"]


def test_load_json_and_gzip_payloads(tmp_path):
    json_path = tmp_path / "rows.json"
    gz_path = tmp_path / "rows.jsonl.gz"
    json_path.write_text(
        json.dumps({"data": [{"id": "obs-json", "trace_id": "trace-json"}]}),
        encoding="utf-8",
    )
    with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
        fh.write('{"id":"obs-gz","trace_id":"trace-gz"}\n')

    json_rows = load_observations(json_path)
    gz_rows = load_observations(gz_path)

    assert [row.row["id"] for row in json_rows] == ["obs-json"]
    assert [row.row["id"] for row in gz_rows] == ["obs-gz"]


def test_invalid_jsonl_error_includes_file_and_line(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        '{"id":"obs-1"}\n{"id":\n',
        encoding="utf-8",
    )

    with pytest.raises(ExportLoadError) as exc_info:
        list(iter_observations(path))

    message = str(exc_info.value)
    assert "bad.jsonl:2" in message
    assert "Invalid JSON" in message


def test_large_single_document_json_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "large.json"
    path.write_text(json.dumps({"data": [{"id": "obs-1", "text": "x" * 64}]}), encoding="utf-8")
    monkeypatch.setattr(loader, "MAX_SINGLE_DOCUMENT_JSON_CHARS", 32)

    with pytest.raises(ExportLoadError, match="Use a JSONL export"):
        list(iter_observations(path))
