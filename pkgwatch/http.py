"""HTTP client: descriptive User-Agent, timeouts, bounded downloads, polite retries."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from .config import Config

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class HttpError(Exception):
    """A request failed after retries, or returned an unexpected status."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class NotFound(HttpError):
    """The resource does not exist (404 or 410)."""


class TooLarge(HttpError):
    """The response body exceeded the caller's byte limit."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def etag(self) -> str | None:
        return self.headers.get("etag")


class Client:
    """Thin wrapper over ``httpx.Client`` shared by every worker thread."""

    def __init__(
        self,
        config: Config,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        token: str | None = None,
    ):
        limits = config.limits
        self._max_retries = int(limits["max_retries"])
        self._backoff_base = float(limits["backoff_base_seconds"])
        self._backoff_max = float(limits["backoff_max_seconds"])
        self._default_max = int(limits["max_metadata_bytes"])
        self._sleep = sleep
        self._token = token
        concurrency = int(limits["concurrency"])
        self._semaphore = threading.BoundedSemaphore(concurrency)
        self._client = httpx.Client(
            headers={"User-Agent": config.user_agent},
            timeout=httpx.Timeout(float(limits["http_timeout_seconds"])),
            follow_redirects=True,
            transport=transport,
            limits=httpx.Limits(max_connections=concurrency),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), self._backoff_max * 2)
            except ValueError:
                pass
        return min(self._backoff_base * (2**attempt), self._backoff_max)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        content: bytes | None = None,
        json_body: Any = None,
        github: bool = False,
    ) -> Response:
        """Perform one request with retries. Raises ``HttpError`` subclasses on failure."""
        limit = self._default_max if max_bytes is None else max_bytes
        send_headers = dict(headers or {})
        if github and self._token:
            send_headers["Authorization"] = f"Bearer {self._token}"
        last_error = "no attempt made"
        for attempt in range(self._max_retries + 1):
            try:
                with (
                    self._semaphore,
                    self._client.stream(
                        method, url, headers=send_headers, content=content, json=json_body
                    ) as resp,
                ):
                    status = resp.status_code
                    if status in RETRY_STATUSES:
                        last_error = f"HTTP {status}"
                        retry_after = resp.headers.get("retry-after")
                    else:
                        return self._finish(resp, url, limit)
            except httpx.TransportError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                retry_after = None
            if attempt < self._max_retries:
                self._sleep(self._delay(attempt, retry_after))
        raise HttpError(f"{method} {url} failed after retries: {last_error}")

    @staticmethod
    def _finish(resp: httpx.Response, url: str, limit: int) -> Response:
        status = resp.status_code
        headers = {k.lower(): v for k, v in resp.headers.items()}
        if status in (404, 410):
            raise NotFound(f"{url} not found", status)
        if status == 304:
            return Response(status, headers, b"")
        if status >= 400:
            raise HttpError(f"{url} returned HTTP {status}", status)
        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise TooLarge(f"{url} declares {declared} bytes (limit {limit})", status)
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > limit:
                raise TooLarge(f"{url} exceeded {limit} bytes", status)
            chunks.append(chunk)
        return Response(status, headers, b"".join(chunks))

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.get(url, **kwargs).json()

    def get_conditional(self, url: str, etag: str | None, **kwargs: Any) -> Response:
        """GET with ``If-None-Match``; a 304 comes back as an empty-bodied response."""
        headers = dict(kwargs.pop("headers", None) or {})
        if etag:
            headers["If-None-Match"] = etag
        return self.get(url, headers=headers, **kwargs)
