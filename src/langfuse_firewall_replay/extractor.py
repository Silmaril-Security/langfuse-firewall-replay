"""Extract Silmaril replay items from Langfuse observations_v2 rows."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from langfuse_firewall_replay import hooks
from langfuse_firewall_replay.models import ExtractionResult, LoadedObservation, ReplayItem

USER_ROLES = {"user", "human"}
SYSTEM_ROLES = {"system"}
TOOL_ROLES = {"tool", "function"}
ASSISTANT_ROLES = {"assistant", "ai"}
TOOL_SPAN_HINTS = ("tool", "retriever", "retrieve", "search", "function")
TOOL_NAME_KEYS = ("tool_name", "toolName", "tool", "name", "function_name", "functionName", "function")
ROW_FIELD_ALIASES = {
    "id": ("id", "observation_id", "observationId"),
    "trace_id": ("trace_id", "traceId"),
    "project_id": ("project_id", "projectId"),
    "session_id": ("session_id", "sessionId"),
    "user_id": ("user_id", "userId"),
    "trace_name": ("trace_name", "traceName"),
    "start_time": ("start_time", "startTime"),
    "provided_model_name": ("provided_model_name", "providedModelName"),
    "tool_calls": ("tool_calls", "toolCalls"),
    "tool_call_names": ("tool_call_names", "toolCallNames"),
    "type": ("type",),
    "name": ("name",),
    "input": ("input",),
    "output": ("output",),
    "environment": ("environment",),
    "metadata": ("metadata",),
}


def parse_jsonish(value: Any) -> Any:
    """Parse JSON strings while leaving plain text untouched."""

    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return value
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return value


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def coerce_text(value: Any) -> str:
    """Convert common Langfuse/OpenAI payload shapes into scannable text."""

    value = parse_jsonish(value)
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            text = coerce_text(item)
            if text:
                parts.append(text)
        return "\n".join(parts).strip()
    if isinstance(value, dict):
        block_type = str(value.get("type") or "").lower()
        if block_type == "text" and "text" in value:
            return coerce_text(value.get("text"))
        if block_type and "text" not in value and any(
            key in value for key in ("image_url", "input_audio", "source")
        ):
            return ""

        for key in (
            "content",
            "text",
            "message",
            "completion",
            "response",
            "answer",
            "output",
            "value",
        ):
            if key in value:
                text = coerce_text(value.get(key))
                if text:
                    return text

        if isinstance(value.get("choices"), list):
            return coerce_text(value["choices"])
        return compact_json(value)
    return str(value).strip()


def _role(message: dict[str, Any]) -> str:
    role = message.get("role") or message.get("type") or message.get("message_type")
    return str(role or "").lower()


def _message_content(message: dict[str, Any]) -> str:
    if "content" in message:
        return coerce_text(message["content"])
    if "text" in message:
        return coerce_text(message["text"])
    return ""


def _messages_from_input(value: Any) -> list[dict[str, Any]] | None:
    parsed = parse_jsonish(value)
    if isinstance(parsed, dict):
        for key in ("messages", "input", "prompt"):
            candidate = parse_jsonish(parsed.get(key))
            if _looks_like_messages(candidate):
                return candidate
    if _looks_like_messages(parsed):
        return parsed
    return None


def _looks_like_messages(value: Any) -> bool:
    return isinstance(value, list) and any(
        isinstance(item, dict) and (_role(item) or "content" in item) for item in value
    )


def _tool_names(value: Any) -> list[str | None]:
    parsed = parse_jsonish(value)
    if parsed is None or parsed == "":
        return []
    if isinstance(parsed, list):
        return [sanitize_tool_name(item) for item in parsed]
    return [sanitize_tool_name(parsed)]


def sanitize_tool_name(value: Any) -> str | None:
    if value is None:
        return None
    name = str(value).strip()
    if not name:
        return None
    return name[:100]


def _metadata(row: dict[str, Any]) -> dict[str, Any]:
    metadata = parse_jsonish(_row_value(row, "metadata"))
    return metadata if isinstance(metadata, dict) else {}


def _row_value(row: dict[str, Any], field: str) -> Any:
    for key in ROW_FIELD_ALIASES.get(field, (field,)):
        value = row.get(key)
        if value is not None:
            return value
    return None


def _tool_name_from_metadata(row: dict[str, Any]) -> str | None:
    metadata = _metadata(row)
    for key in TOOL_NAME_KEYS:
        if key in metadata:
            name = sanitize_tool_name(metadata[key])
            if name:
                return name
    return sanitize_tool_name(_row_value(row, "name"))


def _item_prefix(row: dict[str, Any], index: int) -> str:
    basis = "|".join(
        str(value or "")
        for value in (
            _row_value(row, "trace_id"),
            _row_value(row, "id"),
            _row_value(row, "name"),
            _row_value(row, "start_time"),
            row.get("source_path"),
        )
    )
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10]
    return f"{_row_value(row, 'trace_id') or 'trace'}:{_row_value(row, 'id') or digest}:{index}"


def _base_item_kwargs(observation: LoadedObservation) -> dict[str, Any]:
    row = observation.row
    return {
        "trace_id": _optional_str(_row_value(row, "trace_id")),
        "observation_id": _optional_str(_row_value(row, "id")),
        "observation_type": _optional_str(_row_value(row, "type")),
        "observation_name": _optional_str(_row_value(row, "name")),
        "project_id": _optional_str(_row_value(row, "project_id")),
        "environment": _optional_str(_row_value(row, "environment")),
        "session_id": _optional_str(_row_value(row, "session_id")),
        "user_id": _optional_str(_row_value(row, "user_id")),
        "trace_name": _optional_str(_row_value(row, "trace_name")),
        "start_time": _optional_str(_row_value(row, "start_time")),
        "source_path": observation.source_path,
        "source_line": observation.source_line,
    }


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _make_item(
    observation: LoadedObservation,
    *,
    index: int,
    text: str,
    hook: str,
    source_field: str,
    tool_name: str | None = None,
) -> ReplayItem | None:
    text = text.strip()
    if not text:
        return None
    return ReplayItem(
        item_id=_item_prefix(observation.row, index),
        text=text,
        hook=hook,
        source_field=source_field,
        tool_name=tool_name,
        **_base_item_kwargs(observation),
    )


def _extract_tool_call_payload(call: Any) -> tuple[str, str | None]:
    parsed = parse_jsonish(call)
    if isinstance(parsed, dict):
        function = parsed.get("function")
        if isinstance(function, dict):
            name = sanitize_tool_name(function.get("name"))
            arguments = function.get("arguments")
            text = coerce_text(parse_jsonish(arguments))
            return text or coerce_text(parsed), name
        for name_key in ("name", "tool_name"):
            if name_key in parsed:
                name = sanitize_tool_name(parsed[name_key])
                for text_key in ("arguments", "args", "input", "parameters", "payload"):
                    if text_key in parsed:
                        text = coerce_text(parse_jsonish(parsed[text_key]))
                        return text or coerce_text(parsed), name
                return coerce_text(parsed), name
        return coerce_text(parsed), None
    return coerce_text(parsed), None


def _tool_calls(value: Any) -> list[Any]:
    parsed = parse_jsonish(value)
    if parsed is None or parsed == "":
        return []
    if isinstance(parsed, list):
        return parsed
    return [parsed]


def _is_generation(row: dict[str, Any]) -> bool:
    obs_type = str(_row_value(row, "type") or "").upper()
    return obs_type == "GENERATION" or bool(_row_value(row, "provided_model_name"))


def _is_tool_span(row: dict[str, Any]) -> bool:
    obs_type = str(_row_value(row, "type") or "").upper()
    if obs_type != "SPAN":
        return False
    metadata = _metadata(row)
    haystack = " ".join(
        str(value or "").lower()
        for value in (
            row.get("name"),
            metadata.get("type"),
            metadata.get("kind"),
            metadata.get("span_kind"),
            metadata.get("spanKind"),
            metadata.get("tool_name"),
            metadata.get("toolName"),
        )
    )
    return any(hint in haystack for hint in TOOL_SPAN_HINTS)


def extract_observation(observation: LoadedObservation) -> ExtractionResult:
    """Extract replayable firewall surfaces from one Langfuse observation."""

    row = observation.row
    items: list[ReplayItem] = []
    skipped: Counter[str] = Counter()
    next_index = 0

    def append_item(
        text: str,
        hook: str,
        source_field: str,
        tool_name: str | None = None,
    ) -> None:
        nonlocal next_index
        item = _make_item(
            observation,
            index=next_index,
            text=text,
            hook=hook,
            source_field=source_field,
            tool_name=tool_name,
        )
        next_index += 1
        if item is not None:
            items.append(item)

    if _is_generation(row):
        messages = _messages_from_input(_row_value(row, "input"))
        if messages is not None:
            last_user: tuple[int, str] | None = None
            for idx, message in enumerate(messages):
                role = _role(message)
                text = _message_content(message)
                if role in SYSTEM_ROLES and text:
                    skipped[hooks.SYSTEM_SKIP_REASON] += 1
                elif role in USER_ROLES and text:
                    last_user = (idx, text)
                elif role in TOOL_ROLES and text:
                    append_item(
                        text,
                        hooks.TOOL_RESPONSE,
                        f"input.messages[{idx}]",
                        tool_name=sanitize_tool_name(
                            message.get("name")
                            or message.get("tool_name")
                            or message.get("tool_call_id")
                        ),
                    )
                elif role in ASSISTANT_ROLES:
                    continue
            if last_user is not None:
                idx, text = last_user
                append_item(text, hooks.USER_INPUT, f"input.messages[{idx}]")
        else:
            text = coerce_text(_row_value(row, "input"))
            if text:
                append_item(text, hooks.USER_INPUT, "input")

        output_text = coerce_text(_row_value(row, "output"))
        if output_text:
            append_item(output_text, hooks.LLM_OUTPUT, "output")

        names = _tool_names(_row_value(row, "tool_call_names"))
        for idx, call in enumerate(_tool_calls(_row_value(row, "tool_calls"))):
            text, embedded_name = _extract_tool_call_payload(call)
            tool_name = embedded_name or (names[idx] if idx < len(names) else None)
            append_item(text, hooks.TOOL_CALL, f"tool_calls[{idx}]", tool_name=tool_name)

    elif _is_tool_span(row):
        tool_name = _tool_name_from_metadata(row)
        input_text = coerce_text(_row_value(row, "input"))
        if input_text:
            append_item(input_text, hooks.TOOL_CALL, "span.input", tool_name=tool_name)
        output_text = coerce_text(_row_value(row, "output"))
        if output_text:
            append_item(output_text, hooks.TOOL_RESPONSE, "span.output", tool_name=tool_name)

    return ExtractionResult(items=items, skipped=dict(skipped))


def extract_observations(observations: list[LoadedObservation]) -> ExtractionResult:
    """Extract replay items and aggregate skip counters from loaded rows."""

    all_items: list[ReplayItem] = []
    skipped: Counter[str] = Counter()
    for observation in observations:
        result = extract_observation(observation)
        all_items.extend(result.items)
        skipped.update(result.skipped)
    return ExtractionResult(items=all_items, skipped=dict(skipped))
