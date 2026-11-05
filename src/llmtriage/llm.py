"""LLM clients. The default talks to xAI's Grok through its OpenAI-compatible chat API.

Design points:
  * The API key is read from the environment only (XAI_API_KEY). It is never logged, printed,
    stored in results, or included in error messages.
  * The client is a tiny Protocol so tests and dry-runs use a mock and other OpenAI-compatible
    providers can be used by changing XAI_BASE_URL / XAI_MODEL.
  * Retries with backoff on 429/5xx so a free-tier rate limit does not kill a whole run.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from typing import Protocol

import requests

DEFAULT_BASE_URL = "https://api.x.ai/v1"
DEFAULT_MODEL = "grok-4.3"


class LLMError(RuntimeError):
    """Transient or unexpected failure for one request (the run can continue)."""


class LLMAuthError(LLMError):
    """Missing or rejected credentials. The run should stop, retrying will not help."""


class LLMClient(Protocol):
    model: str

    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 90.0,
        max_retries: int = 4,
    ):
        key = api_key or os.environ.get("XAI_API_KEY", "")
        if not key:
            raise LLMAuthError(
                "XAI_API_KEY is not set. Export it in your shell (see .env.example); "
                "never paste it into code or commit it."
            )
        self._key = key
        self.model = model or os.environ.get("XAI_MODEL", DEFAULT_MODEL)
        self.base_url = (base_url or os.environ.get("XAI_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    def __repr__(self) -> str:  # never expose the key in logs/tracebacks
        return f"OpenAICompatClient(model={self.model!r}, base_url={self.base_url!r})"

    def complete(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}
        last = "no attempt made"
        for attempt in range(self.max_retries):
            try:
                resp = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                last = f"network error: {type(exc).__name__}"
                time.sleep(2**attempt)
                continue
            if resp.status_code in (401, 403):
                raise LLMAuthError(f"API rejected the credentials (HTTP {resp.status_code})")
            if resp.status_code == 429 or resp.status_code >= 500:
                last = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("Retry-After", "")
                delay = float(retry_after) if retry_after.isdigit() else 2**attempt
                time.sleep(min(delay, 30))
                continue
            if resp.status_code != 200:
                raise LLMError(f"API error HTTP {resp.status_code}: {resp.text[:200]}")
            try:
                return resp.json()["choices"][0]["message"]["content"] or ""
            except (KeyError, IndexError, ValueError) as exc:
                raise LLMError("unexpected response shape from API") from exc
        raise LLMError(f"gave up after {self.max_retries} attempts ({last})")


class MockClient:
    """Offline client for tests and dry runs. `responder(system, user) -> raw text`."""

    def __init__(self, responder: Callable[[str, str], str], model: str = "mock"):
        self.model = model
        self._responder = responder
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        return self._responder(system, user)


_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$")


def extract_json(text: str) -> object:
    """Parse JSON from a model reply, tolerating code fences and surrounding prose."""
    cleaned = _FENCE.sub("", text.strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object found in model reply")
    return json.loads(cleaned[start : end + 1])
