"""Report writers: JSON, Markdown, SARIF 2.1.0."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .models import TriageResult

SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
STATUS_ORDER = {"true_positive": 0, "needs_review": 1, "false_positive": 2}


def _sorted(results: list[TriageResult]) -> list[TriageResult]:
    return sorted(
        results, key=lambda r: (STATUS_ORDER[r.final_status], r.finding.file, r.finding.line)
    )


def summary_counts(results: list[TriageResult]) -> dict:
    status = Counter(r.final_status for r in results)
    flagged = sum(1 for r in results if r.flags)
    return {
        "total": len(results),
        "true_positive": status["true_positive"],
        "false_positive": status["false_positive"],
        "needs_review": status["needs_review"],
        "flagged_by_validation": flagged,
        "hallucination_flags": sum(
            1
            for r in results
            if any(f in r.flags for f in ("quote_not_found", "line_out_of_range"))
        ),
    }


def to_json(results: list[TriageResult], model: str) -> str:
    doc = {
        "tool": {"name": "llm-vuln-triage", "version": __version__},
        "model": model,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary_counts(results),
        "results": [r.model_dump() for r in _sorted(results)],
    }
    return json.dumps(doc, indent=2)


def to_markdown(results: list[TriageResult], model: str) -> str:
    c = summary_counts(results)
    lines = [
        "# LLM triage report",
        "",
        f"- **Model:** `{model}`",
        f"- **Findings triaged:** {c['total']}",
        f"- **Trusted true positives:** {c['true_positive']}",
        f"- **Trusted false positives:** {c['false_positive']}",
        f"- **Needs human review:** {c['needs_review']} "
        f"(of which {c['flagged_by_validation']} had validation flags)",
        "",
        "> LLM output is advisory. Any verdict with a validation flag is NOT trusted and is "
        "shown as `needs_review`.",
        "",
    ]
    for r in _sorted(results):
        f = r.finding
        lines.append(f"## `{f.file}:{f.line}` {f.rule_id} ({f.tool}, {f.severity})")
        lines.append("")
        lines.append(f"- **Status:** {r.final_status}{' (trusted)' if r.trusted else ''}")
        if r.llm:
            lines.append(f"- **LLM said:** {r.llm.verdict} (confidence {r.llm.confidence:.2f})")
            lines.append(f"- **Reason:** {r.llm.reason}")
            lines.append(f"- **Evidence (line {r.llm.evidence_line}):** `{r.llm.evidence_quote}`")
            if r.llm.suggested_fix:
                lines.append(f"- **Suggested fix:** {r.llm.suggested_fix}")
        if r.flags:
            lines.append(f"- **Validation flags:** {', '.join(r.flags)}")
        if r.raw_error:
            lines.append(f"- **Error:** {r.raw_error}")
        lines.append("")
    return "\n".join(lines)


def to_sarif(results: list[TriageResult], model: str) -> str:
    rules: dict[str, dict] = {}
    sarif_results = []
    for r in _sorted(results):
        f = r.finding
        rules.setdefault(
            f.rule_id, {"id": f.rule_id, "shortDescription": {"text": f.message[:200]}}
        )
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
                "properties": {
                    "scanner": f.tool,
                    "triage": {
                        "status": r.final_status,
                        "trusted": r.trusted,
                        "flags": r.flags,
                        "llm_verdict": r.llm.verdict if r.llm else None,
                        "reason": r.llm.reason if r.llm else None,
                    },
                },
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llm-vuln-triage",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {"model": model},
            }
        ],
    }
    return json.dumps(doc, indent=2)


WRITERS = {"json": (to_json, "json"), "md": (to_markdown, "md"), "sarif": (to_sarif, "sarif")}
