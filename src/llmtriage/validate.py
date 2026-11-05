"""Validation layer: never trust an LLM claim until it is checked against the real code.

For every verdict we check, in order:
  1. Schema: the reply is JSON and matches LLMVerdict exactly (types, ranges, no extra keys).
  2. Evidence exists: the quoted code is really in the file (whitespace-insensitive).
  3. Line claims: the cited line is inside the file and is where the quote actually appears.
  4. Relevance: the quote is near the line the scanner flagged.
  5. Cross-check with static analysis: "false_positive" on a high-severity/high-confidence
     scanner finding is flagged for human review instead of silently accepted.

Any flag means the verdict is NOT trusted and the final status becomes "needs_review".
"""

from __future__ import annotations

import re

from pydantic import ValidationError

from .llm import extract_json
from .models import Finding, LLMVerdict, TriageResult

NEAR_LINES = 10  # a quote farther than this from the flagged line is considered irrelevant
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    return _WS.sub(" ", text).strip()


def find_quote_lines(quote: str, lines: list[str]) -> list[int]:
    """1-based start lines where `quote` occurs in `lines` (whitespace-insensitive).

    A one-line quote matches if it is contained in a line. A multi-line quote must match a run
    of consecutive lines (first/last lines may be partial)."""
    q_lines = [normalize(x) for x in quote.splitlines() if x.strip()]
    if not q_lines:
        return []
    norm = [normalize(x) for x in lines]
    hits: list[int] = []
    k = len(q_lines)
    for i in range(len(norm) - k + 1):
        window = norm[i : i + k]
        if k == 1:
            ok = q_lines[0] in window[0]
        else:
            # first line may be partial only at its start, last only at its end
            ok = (
                window[0].endswith(q_lines[0])
                and window[1:-1] == q_lines[1:-1]
                and window[-1].startswith(q_lines[-1])
            )
        if ok:
            hits.append(i + 1)
    return hits


def validate_verdict(raw: str, finding: Finding, lines: list[str]) -> TriageResult:
    # 1. schema
    try:
        verdict = LLMVerdict.model_validate(extract_json(raw))
    except (ValueError, ValidationError) as exc:
        return TriageResult(
            finding=finding,
            llm=None,
            flags=["schema_invalid"],
            final_status="needs_review",
            trusted=False,
            raw_error=str(exc)[:300],
        )

    flags: list[str] = []

    # 3a. cited line must exist in the file
    if verdict.evidence_line > len(lines):
        flags.append("line_out_of_range")

    # 2. the quote must really appear in the file
    hits = find_quote_lines(verdict.evidence_quote, lines)
    if not hits:
        flags.append("quote_not_found")
    else:
        # 3b. the claimed start line must be where the quote actually is (+/- 1 for blank lines)
        if "line_out_of_range" not in flags and not any(
            abs(h - verdict.evidence_line) <= 1 for h in hits
        ):
            flags.append("line_mismatch")
        # 4. relevance to the flagged line
        if min(abs(h - finding.line) for h in hits) > NEAR_LINES:
            flags.append("quote_far_from_finding")

    # 5. cross-check against the static analyzer
    if (
        verdict.verdict == "false_positive"
        and finding.severity == "high"
        and finding.confidence == "high"
    ):
        flags.append("disagrees_with_scanner")

    trusted = not flags
    return TriageResult(
        finding=finding,
        llm=verdict,
        flags=flags,
        final_status=verdict.verdict if trusted else "needs_review",
        trusted=trusted,
    )
