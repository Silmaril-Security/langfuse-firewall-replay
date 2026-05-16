from __future__ import annotations

import json

from langfuse_firewall_replay import hooks
from langfuse_firewall_replay.extractor import (
    extract_observation,
    extract_observations,
    parse_jsonish,
)
from langfuse_firewall_replay.models import LoadedObservation


def _loaded(row):
    return LoadedObservation(row=row, source_path="observations_v2/test.jsonl", source_line=1)


def test_parse_jsonish_leaves_plain_text_alone():
    assert parse_jsonish("hello") == "hello"
    assert parse_jsonish('{"a":1}') == {"a": 1}


def test_extract_generation_messages_tools_output_and_tool_calls():
    row = {
        "id": "obs-1",
        "trace_id": "trace-1",
        "type": "GENERATION",
        "name": "chat",
        "input": json.dumps(
            [
                {"role": "system", "content": "You are an operations assistant."},
                {"role": "user", "content": "first question"},
                {"role": "assistant", "content": "prior answer"},
                {"role": "tool", "name": "vehicle_lookup", "content": "vehicle status"},
                {"role": "user", "content": [{"type": "text", "text": "latest question"}]},
            ]
        ),
        "output": '{"content":"assistant final"}',
        "tool_calls": [
            json.dumps(
                {
                    "type": "function",
                    "function": {
                        "name": "dispatch_driver",
                        "arguments": "{\"driver_id\":\"D-1\"}",
                    },
                }
            )
        ],
        "tool_call_names": ["fallback_name"],
    }

    result = extract_observation(_loaded(row))
    by_source = {item.source_field: item for item in result.items}

    assert result.skipped == {hooks.SYSTEM_SKIP_REASON: 1}
    assert by_source["input.messages[4]"].hook == hooks.USER_INPUT
    assert by_source["input.messages[4]"].text == "latest question"
    assert by_source["input.messages[3]"].hook == hooks.TOOL_RESPONSE
    assert by_source["input.messages[3]"].tool_name == "vehicle_lookup"
    assert by_source["output"].hook == hooks.LLM_OUTPUT
    assert by_source["output"].text == "assistant final"
    assert by_source["tool_calls[0]"].hook == hooks.TOOL_CALL
    assert by_source["tool_calls[0]"].tool_name == "dispatch_driver"
    assert by_source["tool_calls[0]"].text == '{"driver_id":"D-1"}'


def test_extract_plain_generation_input():
    result = extract_observation(
        _loaded(
            {
                "id": "obs-2",
                "trace_id": "trace-2",
                "type": "GENERATION",
                "input": "Summarize this route.",
            }
        )
    )

    assert len(result.items) == 1
    assert result.items[0].hook == hooks.USER_INPUT
    assert result.items[0].source_field == "input"


def test_extract_langfuse_camel_case_metadata():
    result = extract_observation(
        _loaded(
            {
                "id": "obs-camel",
                "traceId": "trace-camel",
                "projectId": "project-camel",
                "sessionId": "session-camel",
                "userId": "user-camel",
                "traceName": "camel trace",
                "startTime": "2026-05-16T00:00:00Z",
                "type": "GENERATION",
                "name": "chat",
                "input": "hello from camel case",
                "toolCalls": [
                    {
                        "function": {
                            "name": "lookup_vehicle",
                            "arguments": {"vehicle_id": "VH-1"},
                        }
                    }
                ],
                "toolCallNames": ["lookup_vehicle"],
            }
        )
    )

    by_source = {item.source_field: item for item in result.items}
    item = by_source["input"]
    assert item.trace_id == "trace-camel"
    assert item.project_id == "project-camel"
    assert item.session_id == "session-camel"
    assert item.user_id == "user-camel"
    assert item.trace_name == "camel trace"
    assert item.start_time == "2026-05-16T00:00:00Z"
    assert item.item_id.startswith("trace-camel:obs-camel:")
    assert by_source["tool_calls[0]"].tool_name == "lookup_vehicle"


def test_extract_tool_span_input_and_output():
    result = extract_observation(
        _loaded(
            {
                "id": "span-1",
                "trace_id": "trace-3",
                "type": "SPAN",
                "name": "tool.vehicle_lookup",
                "metadata": {"tool_name": "vehicle_lookup"},
                "input": {"vehicle_id": "VH-1"},
                "output": {"status": "ok"},
            }
        )
    )

    assert [(item.hook, item.source_field, item.tool_name) for item in result.items] == [
        (hooks.TOOL_CALL, "span.input", "vehicle_lookup"),
        (hooks.TOOL_RESPONSE, "span.output", "vehicle_lookup"),
    ]


def test_extract_observations_aggregates_skips():
    rows = [
        _loaded(
            {
                "id": "obs-1",
                "trace_id": "trace-1",
                "type": "GENERATION",
                "input": [{"role": "system", "content": "sys"}],
            }
        ),
        _loaded(
            {
                "id": "obs-2",
                "trace_id": "trace-2",
                "type": "GENERATION",
                "input": "hello",
            }
        ),
    ]

    result = extract_observations(rows)

    assert len(result.items) == 1
    assert result.skipped == {hooks.SYSTEM_SKIP_REASON: 1}
