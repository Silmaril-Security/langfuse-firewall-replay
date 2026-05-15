"""Canonical Silmaril Firewall hook values.

The live SDK is the source of truth when it is importable. The fallback strings
match the public wire contract so dry-run and unit tests can run without live
SDK credentials or a local editable install.
"""

from __future__ import annotations

try:  # pragma: no cover - exercised when the public SDK is installed.
    from silmaril_security.sdk import HookLabel
except Exception:  # pragma: no cover - fallback is validated by tests.
    HookLabel = None  # type: ignore[assignment]

if HookLabel is not None:
    USER_INPUT = HookLabel.USER_INPUT.value
    SYSTEM_PROMPT = HookLabel.SYSTEM_PROMPT.value
    TOOL_CALL = HookLabel.TOOL_CALL.value
    TOOL_RESPONSE = HookLabel.TOOL_RESPONSE.value
    LLM_OUTPUT = HookLabel.LLM_OUTPUT.value
    UNKNOWN = HookLabel.UNKNOWN.value
else:  # pragma: no cover - fallback is validated by tests.
    USER_INPUT = "user_input"
    SYSTEM_PROMPT = "system_prompt"
    TOOL_CALL = "tool_call"
    TOOL_RESPONSE = "tool_response"
    LLM_OUTPUT = "llm_output"
    UNKNOWN = "unknown"


SYSTEM_SKIP_REASON = "system_prompt"
