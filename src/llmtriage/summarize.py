"""Summarize mode: ask the LLM for possible weaknesses in a file, then verify each claim.

Each reported issue is classified:
  hallucinated - the quoted code is not in the file
  corroborated - quote is real AND a Bandit/Semgrep finding sits within a few lines of it
  unverified   - quote is real but no static analyzer flagged it (treat as a lead, not a fact)
"""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from .context import read_lines
from .llm import LLMClient, extract_json
from .models import Finding, SummaryResponse, ValidatedIssue
from .prompts import SUMMARY_SYSTEM, summary_user_prompt
from .validate import find_quote_lines

CORROBORATE_WITHIN = 3


def summarize_file(
    client: LLMClient, root: Path, rel_path: str, findings: list[Finding]
) -> tuple[SummaryResponse | None, list[ValidatedIssue], str]:
    lines = read_lines(root, rel_path)
    raw = client.complete(SUMMARY_SYSTEM, summary_user_prompt(rel_path, lines))
    try:
        resp = SummaryResponse.model_validate(extract_json(raw))
    except (ValueError, ValidationError) as exc:
        return None, [], f"invalid model output: {str(exc)[:200]}"

    nearby = [f for f in findings if f.file == rel_path]
    validated: list[ValidatedIssue] = []
    for item in resp.issues:
        hits = find_quote_lines(item.evidence_quote, lines)
        if not hits:
            validated.append(ValidatedIssue(item=item, quote_verified=False, status="hallucinated"))
            continue
        ids = [f.id for f in nearby if any(abs(f.line - h) <= CORROBORATE_WITHIN for h in hits)]
        validated.append(
            ValidatedIssue(
                item=item,
                quote_verified=True,
                corroborated_by=ids,
                status="corroborated" if ids else "unverified",
            )
        )
    return resp, validated, ""
