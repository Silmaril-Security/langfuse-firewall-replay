"""Run extracted replay items through the Silmaril Firewall SDK."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol

from langfuse_firewall_replay.models import ReplayItem, ReplayResult

DEFAULT_RETRIES = 2
DEFAULT_RETRY_BACKOFF = 0.5
RETRYABLE_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}
RETRYABLE_EXCEPTION_NAMES = {
    "APIConnectionError",
    "APITimeoutError",
    "ConnectError",
    "ConnectionError",
    "ConnectTimeout",
    "NetworkError",
    "PoolTimeout",
    "ReadError",
    "ReadTimeout",
    "RemoteDisconnected",
    "RemoteProtocolError",
    "Timeout",
    "TimeoutError",
    "TimeoutException",
    "WriteError",
}


class FirewallClient(Protocol):
    def classify(
        self,
        text: str,
        *,
        hook: str | None = None,
        tool_name: str | None = None,
        shadow_mode: bool | None = None,
    ):
        """Classify one text using the Silmaril SDK."""


def make_firewall_client(*, api_key: str, api_url: str, timeout: float = 30.0) -> FirewallClient:
    """Create the SDK client lazily so dry-run and tests do not need credentials."""

    from silmaril_security.sdk import Firewall

    return Firewall(api_key=api_key, api_url=api_url, timeout=timeout, shadow_mode=True)


def _replay_result_from_sdk_result(item: ReplayItem, result) -> ReplayResult:
    prediction = getattr(result, "prediction", None)
    return ReplayResult(
        item=item,
        prediction=prediction,
        score=getattr(result, "score", None),
        threshold=getattr(result, "threshold", None),
        blocked=prediction == "MALICIOUS",
        primary_outcome=getattr(result, "primary_outcome", None),
        outcome_scores=getattr(result, "outcome_scores", None),
        detector_scores=getattr(result, "detector_scores", None),
        detector_counts=getattr(result, "detector_counts", None),
    )


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _exception_status_code(exc: BaseException) -> int | None:
    for candidate in _exception_chain(exc):
        for attr in ("status_code", "status"):
            value = getattr(candidate, attr, None)
            if isinstance(value, int):
                return value
        response = getattr(candidate, "response", None)
        value = getattr(response, "status_code", None)
        if isinstance(value, int):
            return value
        value = getattr(response, "status", None)
        if isinstance(value, int):
            return value
        error = getattr(candidate, "error", None)
        if isinstance(error, dict):
            value = error.get("status") or error.get("status_code")
            if isinstance(value, int):
                return value
    return None


def _is_retryable_exception(exc: BaseException) -> bool:
    status_code = _exception_status_code(exc)
    if status_code in RETRYABLE_STATUS_CODES:
        return True
    return any(
        type(candidate).__name__ in RETRYABLE_EXCEPTION_NAMES
        for candidate in _exception_chain(exc)
    )


def _sleep_before_retry(*, retry_backoff: float, attempt_index: int) -> None:
    if retry_backoff <= 0:
        return
    time.sleep(retry_backoff * (2**attempt_index))


def _classify_once(client: FirewallClient, item: ReplayItem) -> Any:
    return client.classify(
        item.text,
        hook=item.hook,
        tool_name=item.tool_name,
        shadow_mode=True,
    )


def _classify_one(
    client: FirewallClient,
    item: ReplayItem,
    *,
    retries: int = DEFAULT_RETRIES,
    retry_backoff: float = DEFAULT_RETRY_BACKOFF,
) -> ReplayResult:
    last_exc: Exception | None = None
    for attempt_index in range(retries + 1):
        try:
            result = _classify_once(client, item)
            return _replay_result_from_sdk_result(item, result)
        except Exception as exc:  # Keep the replay moving; preserve row-level error.
            blocked_result = getattr(exc, "result", None)
            if blocked_result is not None:
                return _replay_result_from_sdk_result(item, blocked_result)
            last_exc = exc
            if attempt_index < retries and _is_retryable_exception(exc):
                _sleep_before_retry(retry_backoff=retry_backoff, attempt_index=attempt_index)
                continue
            break

    return ReplayResult(
        item=item,
        error_class=type(last_exc).__name__,
        error=str(last_exc),
    )


class ReplayExecutor:
    """Thread-aware per-item replay executor."""

    def __init__(
        self,
        *,
        client: FirewallClient | None = None,
        api_key: str | None = None,
        api_url: str | None = None,
        timeout: float = 30.0,
        dry_run: bool = False,
        lock_provided_client: bool = False,
        retries: int = DEFAULT_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
    ) -> None:
        self.client = client
        self.api_key = api_key
        self.api_url = api_url
        self.timeout = timeout
        self.dry_run = dry_run
        self.retries = retries
        self.retry_backoff = retry_backoff
        self._thread_local = threading.local()
        self._provided_client_lock = threading.Lock() if lock_provided_client else None

    def _client_for_thread(self) -> FirewallClient:
        if self.client is not None:
            return self.client
        if not self.api_key:
            raise ValueError("api_key is required when dry_run is false")
        if not self.api_url:
            raise ValueError("api_url is required when dry_run is false")
        client = getattr(self._thread_local, "client", None)
        if client is None:
            client = make_firewall_client(
                api_key=self.api_key,
                api_url=self.api_url,
                timeout=self.timeout,
            )
            self._thread_local.client = client
        return client

    def classify(self, item: ReplayItem) -> ReplayResult:
        if self.dry_run:
            return ReplayResult(item=item, dry_run=True)
        client = self._client_for_thread()
        if self._provided_client_lock is None:
            return _classify_one(
                client,
                item,
                retries=self.retries,
                retry_backoff=self.retry_backoff,
            )
        with self._provided_client_lock:
            return _classify_one(
                client,
                item,
                retries=self.retries,
                retry_backoff=self.retry_backoff,
            )


def replay_iter(
    items: Iterable[ReplayItem],
    *,
    client: FirewallClient | None = None,
    api_key: str | None = None,
    api_url: str | None = None,
    workers: int = 1,
    dry_run: bool = False,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
    retry_backoff: float = DEFAULT_RETRY_BACKOFF,
) -> Iterator[ReplayResult]:
    """Yield replay results with bounded memory use."""

    if workers < 1:
        raise ValueError("workers must be >= 1")
    if retries < 0:
        raise ValueError("retries must be >= 0")
    if retry_backoff < 0:
        raise ValueError("retry_backoff must be >= 0")

    executor = ReplayExecutor(
        client=client,
        api_key=api_key,
        api_url=api_url,
        timeout=timeout,
        dry_run=dry_run,
        lock_provided_client=client is not None and workers > 1,
        retries=retries,
        retry_backoff=retry_backoff,
    )
    if workers == 1:
        for item in items:
            yield executor.classify(item)
        return

    max_pending = workers * 8
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = []
        for item in items:
            pending.append(pool.submit(executor.classify, item))
            if len(pending) >= max_pending:
                yield pending.pop(0).result()
        for future in pending:
            yield future.result()


def replay_items(
    items: Iterable[ReplayItem],
    *,
    client: FirewallClient | None = None,
    api_key: str | None = None,
    api_url: str | None = None,
    workers: int = 1,
    dry_run: bool = False,
    timeout: float = 30.0,
    retries: int = DEFAULT_RETRIES,
    retry_backoff: float = DEFAULT_RETRY_BACKOFF,
) -> list[ReplayResult]:
    """Classify replay items one at a time.

    This intentionally does not use ``classify_batch``. Long input handling is
    delegated to ``Firewall.classify(...)`` for each replay item.
    """

    return list(
        replay_iter(
            items,
            client=client,
            api_key=api_key,
            api_url=api_url,
            workers=workers,
            dry_run=dry_run,
            timeout=timeout,
            retries=retries,
            retry_backoff=retry_backoff,
        )
    )
