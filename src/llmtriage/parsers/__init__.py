"""Parsers that turn Bandit and Semgrep JSON reports into normalized Finding objects."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, Severity

_SEV: dict[str, Severity] = {
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    # Semgrep severities
    "INFO": "low",
    "WARNING": "medium",
    "ERROR": "high",
}


class ReportError(ValueError):
    pass


def _norm_path(path: str, root: Path | None) -> str:
    p = Path(path)
    if root is not None:
        try:
            p = p.resolve().relative_to(root.resolve())
        except ValueError:
            pass  # already relative or outside the root: keep as given
    return p.as_posix().removeprefix("./")


def parse_bandit(path: str | Path, root: Path | None = None) -> list[Finding]:
    """Bandit `-f json` output: results[] with filename, line_number, test_id, ..."""
    doc = _load(path)
    if "results" not in doc:
        raise ReportError("not a Bandit JSON report (missing 'results')")
    findings = []
    for r in doc["results"]:
        file = _norm_path(r["filename"], root)
        findings.append(
            Finding(
                id=f"bandit:{r['test_id']}:{file}:{r['line_number']}",
                tool="bandit",
                rule_id=r["test_id"],
                file=file,
                line=int(r["line_number"]),
                severity=_SEV.get(str(r.get("issue_severity", "MEDIUM")).upper(), "medium"),
                confidence=_SEV.get(str(r.get("issue_confidence", "MEDIUM")).upper(), "medium"),
                message=r.get("issue_text", ""),
            )
        )
    return findings


def parse_semgrep(path: str | Path, root: Path | None = None) -> list[Finding]:
    """Semgrep `--json` output: results[] with check_id, path, start.line, extra.*."""
    doc = _load(path)
    if "results" not in doc:
        raise ReportError("not a Semgrep JSON report (missing 'results')")
    findings = []
    for r in doc["results"]:
        file = _norm_path(r["path"], root)
        extra = r.get("extra", {})
        findings.append(
            Finding(
                id=f"semgrep:{r['check_id']}:{file}:{r['start']['line']}",
                tool="semgrep",
                rule_id=r["check_id"],
                file=file,
                line=int(r["start"]["line"]),
                severity=_SEV.get(str(extra.get("severity", "WARNING")).upper(), "medium"),
                message=extra.get("message", ""),
            )
        )
    return findings


def _load(path: str | Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ReportError(f"unexpected JSON structure in {path}")
    return doc
