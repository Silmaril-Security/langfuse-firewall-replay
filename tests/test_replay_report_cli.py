from __future__ import annotations

import json
from dataclasses import dataclass

from langfuse_firewall_replay import hooks
from langfuse_firewall_replay.cli import main, parse_args, resolve_api_url, resolve_api_url_source
from langfuse_firewall_replay.models import ReplayItem
from langfuse_firewall_replay.replay import replay_items
from langfuse_firewall_replay.report import result_record, timestamped_run_dir, write_reports


@dataclass(frozen=True)
class FakeBlockResult:
    prediction: str
    score: float
    threshold: float = 0.5
    primary_outcome: str | None = None
    outcome_scores: dict[str, float] | None = None
    detector_scores: dict[str, float] | None = None
    detector_counts: dict[str, int] | None = None


class FakeClient:
    def __init__(self):
        self.calls = []

    def classify(self, text, *, hook=None, tool_name=None, shadow_mode=None):
        self.calls.append((text, hook, tool_name))
        return FakeBlockResult(prediction="BENIGN", score=0.12)

    def classify_batch(self, *args, **kwargs):  # pragma: no cover - must never be called.
        raise AssertionError("classify_batch must not be used")


def _item(text="hello", trace_id="trace-1"):
    return ReplayItem(
        item_id=f"{trace_id}:obs-1:0",
        trace_id=trace_id,
        observation_id="obs-1",
        observation_type="GENERATION",
        observation_name="chat",
        hook=hooks.USER_INPUT,
        tool_name=None,
        source_field="input",
        text=text,
    )


def test_replay_uses_classify_only():
    client = FakeClient()
    results = replay_items([_item()], client=client)

    assert len(results) == 1
    assert results[0].prediction == "BENIGN"
    assert results[0].threshold == 0.5
    assert client.calls == [("hello", hooks.USER_INPUT, None)]


def test_api_url_resolution_only_uses_generic_env_var():
    args = parse_args(["--input", "observations.jsonl"])
    scoped_key = "_".join(["SILMARIL", "ACME", "PROD", "API_URL"])
    env = {
        scoped_key: "https://scoped.example/classify",
        "SILMARIL_API_URL": "https://generic.example/classify",
    }

    assert resolve_api_url(args, env) == "https://generic.example/classify"
    assert resolve_api_url_source(args, env) == "SILMARIL_API_URL"
    assert resolve_api_url(args, {scoped_key: "https://ignored"}) is None


def test_block_exceptions_are_serialized_as_malicious_results():
    class FakeBlocked(Exception):
        def __init__(self):
            self.result = FakeBlockResult(prediction="MALICIOUS", score=0.91)
            super().__init__("blocked text should not be written by default")

    class BlockingClient:
        def classify(self, text, *, hook=None, tool_name=None, shadow_mode=None):
            raise FakeBlocked()

    [result] = replay_items([_item(text="sensitive blocked text")], client=BlockingClient())

    assert result.prediction == "MALICIOUS"
    assert result.score == 0.91
    assert result.error_class is None


def test_dry_run_does_not_call_client():
    client = FakeClient()
    results = replay_items([_item()], client=client, dry_run=True)

    assert results[0].dry_run is True
    assert client.calls == []


def test_replay_retries_transient_connection_errors():
    class FlakyClient:
        def __init__(self):
            self.calls = 0

        def classify(self, text, *, hook=None, tool_name=None, shadow_mode=None):
            self.calls += 1
            if self.calls < 3:
                raise ConnectionError("temporary connection reset")
            return FakeBlockResult(prediction="BENIGN", score=0.2)

    client = FlakyClient()
    [result] = replay_items([_item()], client=client, retries=2, retry_backoff=0)

    assert client.calls == 3
    assert result.prediction == "BENIGN"
    assert result.error_class is None


def test_replay_records_error_after_retry_exhaustion():
    class DownClient:
        def __init__(self):
            self.calls = 0

        def classify(self, text, *, hook=None, tool_name=None, shadow_mode=None):
            self.calls += 1
            raise ConnectionError("still down")

    client = DownClient()
    [result] = replay_items([_item()], client=client, retries=1, retry_backoff=0)

    assert client.calls == 2
    assert result.prediction is None
    assert result.error_class == "ConnectionError"


def test_result_record_omits_full_text_and_preview_by_default():
    result = replay_items([_item(text="secret route text")], client=FakeClient())[0]

    record = result_record(result)

    assert "text" not in record
    assert "text_preview" not in record
    assert record["text_hash"].startswith("sha256:")
    assert record["trace_id"].startswith("sha256:")


def test_result_record_preview_and_plain_identifiers_are_opt_in():
    result = replay_items([_item(text="secret route text")], client=FakeClient())[0]

    record = result_record(
        result,
        include_preview=True,
        hash_identifiers=False,
    )

    assert record["text_preview"] == "secret route text"
    assert record["trace_id"] == "trace-1"


def test_result_record_redacts_error_details_by_default():
    class ErrorClient:
        def classify(self, text, *, hook=None, tool_name=None, shadow_mode=None):
            raise RuntimeError("error mentions secret route text")

    [result] = replay_items([_item(text="secret route text")], client=ErrorClient())

    redacted = result_record(result)
    detailed = result_record(result, include_error_details=True)

    assert redacted["error_class"] == "RuntimeError"
    assert redacted["error"] is None
    assert detailed["error"] == "error mentions secret route text"


def test_write_reports_outputs_expected_files(tmp_path):
    results = replay_items(
        [_item(trace_id="trace-a"), _item(text="bad", trace_id="trace-a")],
        client=FakeClient(),
    )

    paths = write_reports(
        tmp_path,
        results=results,
        observation_count=1,
        skipped={"system_prompt": 1},
        config={"dry_run": False, "api_url_configured": True, "api_url_source": "SILMARIL_API_URL"},
    )

    assert paths["results"].exists()
    assert paths["trace_summary"].exists()
    assert paths["summary"].exists()
    summary = json.loads(paths["summary"].read_text(encoding="utf-8"))
    assert summary["counts"]["observations"] == 1
    assert summary["counts"]["replay_items"] == 2
    assert "https://" not in paths["summary"].read_text(encoding="utf-8")


def test_timestamped_run_dir_is_collision_resistant():
    first = timestamped_run_dir()
    second = timestamped_run_dir()

    assert first != second
    assert first.name.startswith("langfuse-firewall-replay-")


def test_cli_dry_run_writes_reports(tmp_path, capsys):
    export_file = tmp_path / "observations.jsonl"
    out_dir = tmp_path / "out"
    export_file.write_text(
        json.dumps(
            {
                "id": "obs-1",
                "trace_id": "trace-1",
                "type": "GENERATION",
                "input": "hello",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    code = main(["--input", str(export_file), "--out", str(out_dir), "--dry-run"])

    captured = capsys.readouterr()
    assert code == 0
    assert "Replay items: 1" in captured.out
    assert (out_dir / "results.jsonl").exists()
    row = json.loads((out_dir / "results.jsonl").read_text(encoding="utf-8"))
    assert row["dry_run"] is True
    assert "text_preview" not in row
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["config"]["api_url_configured"] is False
    assert summary["config"]["input"] is None


def test_cli_preserves_camel_case_trace_metadata(tmp_path):
    export_file = tmp_path / "observations.jsonl"
    out_dir = tmp_path / "out"
    export_file.write_text(
        json.dumps(
            {
                "id": "obs-1",
                "traceId": "trace-camel",
                "traceName": "camel trace",
                "sessionId": "session-camel",
                "userId": "user-camel",
                "type": "GENERATION",
                "input": "hello",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    code = main(
        [
            "--input",
            str(export_file),
            "--out",
            str(out_dir),
            "--dry-run",
            "--plain-identifiers",
        ]
    )

    assert code == 0
    trace_row = json.loads((out_dir / "trace_summary.jsonl").read_text(encoding="utf-8"))
    assert trace_row["trace_id"] == "trace-camel"
    assert trace_row["trace_name"] == "camel trace"
    assert trace_row["session_id"] == "session-camel"
    assert trace_row["user_id"] == "user-camel"
