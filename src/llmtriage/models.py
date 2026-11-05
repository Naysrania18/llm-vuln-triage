"""Data models: scanner findings, the schema the LLM must follow, and validated results."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high"]
VerdictLabel = Literal["true_positive", "false_positive", "needs_review"]


class Finding(BaseModel):
    """A normalized static-analysis finding (from Bandit or Semgrep)."""

    id: str  # stable id, e.g. "bandit:B602:app.py:42"
    tool: Literal["bandit", "semgrep"]
    rule_id: str
    file: str  # path relative to the source root
    line: int
    severity: Severity
    confidence: Severity = "medium"  # scanner's own confidence (Bandit); Semgrep default medium
    message: str


class LLMVerdict(BaseModel):
    """The JSON schema the model is instructed to return. Extra keys are rejected."""

    model_config = ConfigDict(extra="forbid")

    verdict: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = Field(min_length=1, max_length=1000)
    evidence_quote: str = Field(min_length=1, max_length=500)  # verbatim code from the file
    evidence_line: int = Field(ge=1)  # 1-based line where the quote starts
    suggested_fix: str = Field(default="", max_length=1000)


# Flags raised by the validation layer (see validate.py).
FLAGS = (
    "schema_invalid",  # response was not valid JSON for LLMVerdict
    "quote_not_found",  # cited code does not exist in the file (hallucination)
    "line_out_of_range",  # cited line number is outside the file
    "line_mismatch",  # quote exists, but not at the line the model claimed
    "source_unavailable",  # the file could not be read (missing / outside root / too large)
    "quote_far_from_finding",  # quote exists but nowhere near the flagged line
    "disagrees_with_scanner",  # LLM says false positive on a high/high scanner finding
)


class TriageResult(BaseModel):
    finding: Finding
    llm: LLMVerdict | None = None  # None if the response never validated against the schema
    flags: list[str] = Field(default_factory=list)
    # The status a human should act on. LLM verdicts that carry any flag are NOT trusted:
    # they are downgraded to needs_review.
    final_status: VerdictLabel = "needs_review"
    trusted: bool = False
    raw_error: str = ""


class SummaryItem(BaseModel):
    """One potential vulnerability reported by summarize mode (before validation)."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    line: int = Field(ge=1)
    evidence_quote: str = Field(min_length=1, max_length=500)
    explanation: str = Field(min_length=1, max_length=1000)
    severity: Severity = "medium"


class SummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(max_length=2000)
    issues: list[SummaryItem] = Field(default_factory=list)


class ValidatedIssue(BaseModel):
    item: SummaryItem
    quote_verified: bool
    corroborated_by: list[str] = Field(default_factory=list)  # scanner finding ids nearby
    status: Literal["corroborated", "unverified", "hallucinated"]
