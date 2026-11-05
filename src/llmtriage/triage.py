"""Orchestration: for each finding, ask the LLM, validate the reply, record the result."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

from .context import SourceError, read_lines
from .llm import LLMAuthError, LLMClient, LLMError
from .models import Finding, TriageResult
from .prompts import TRIAGE_SYSTEM, triage_user_prompt
from .validate import validate_verdict

REPAIR_NOTE = (
    "\n\nYour previous reply was rejected: {error}\n"
    "Reply again with ONLY the JSON object, using exactly the required keys."
)


def _cache_path(cache_dir: Path, client: LLMClient, user: str) -> Path:
    key = hashlib.sha256(f"{client.model}\n{TRIAGE_SYSTEM}\n{user}".encode()).hexdigest()
    return cache_dir / f"{key}.json"


def triage_one(
    client: LLMClient,
    finding: Finding,
    root: Path,
    cache_dir: Path | None = None,
) -> TriageResult:
    try:
        lines = read_lines(root, finding.file)
    except SourceError as exc:
        return TriageResult(
            finding=finding, flags=["source_unavailable"], raw_error=str(exc), trusted=False
        )

    user = triage_user_prompt(finding, lines)
    cache_file = _cache_path(cache_dir, client, user) if cache_dir else None

    # Cached raw replies save API quota (important on free tiers). They are re-validated
    # against the current source every time, so a stale cache can never bypass validation.
    if cache_file and cache_file.is_file():
        result = validate_verdict(cache_file.read_text(encoding="utf-8"), finding, lines)
        if result.llm is not None:
            return result

    try:
        raw = client.complete(TRIAGE_SYSTEM, user)
        result = validate_verdict(raw, finding, lines)
        if result.llm is None:  # one repair attempt for malformed output
            raw = client.complete(TRIAGE_SYSTEM, user + REPAIR_NOTE.format(error=result.raw_error))
            result = validate_verdict(raw, finding, lines)
    except LLMAuthError:
        raise
    except LLMError as exc:
        return TriageResult(finding=finding, flags=[], raw_error=f"LLM call failed: {exc}")

    if cache_file and result.llm is not None:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(raw, encoding="utf-8")
    return result


def triage_findings(
    client: LLMClient,
    findings: list[Finding],
    root: Path,
    cache_dir: Path | None = None,
    max_findings: int | None = None,
    on_progress: Callable[[int, int, Finding], None] | None = None,
) -> list[TriageResult]:
    selected = findings[:max_findings] if max_findings else findings
    results = []
    for i, f in enumerate(selected, 1):
        if on_progress:
            on_progress(i, len(selected), f)
        results.append(triage_one(client, f, root, cache_dir))
    return results
