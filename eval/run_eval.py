"""Evaluate the triage pipeline on the deliberately vulnerable sample app.

Positive class = "real vulnerability". A finding counts as *predicted positive* if the
pipeline keeps it for human attention, i.e. does NOT dismiss it as a false positive.

Three strategies are compared on the same findings:
  scanner-only   keep everything the scanner reports (what you get without triage)
  llm-raw        trust the model's verdict blindly (no validation)
  llm-validated  the real pipeline: any verdict with a validation flag becomes needs_review

The most dangerous error is a *dismissed real vulnerability* (false negative), reported
separately as `dangerous_dismissals`.

Providers:
  xai      live model through your XAI_API_KEY (costs API quota)
  oracle   OFFLINE SIMULATION that answers from the labels and injects planted mistakes. It
           tests the harness and the validator. Its numbers say nothing about any real model.

Usage:
  python eval/run_eval.py --provider oracle
  python eval/run_eval.py --provider xai --max-findings 30
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

from llmtriage.llm import LLMClient, MockClient, OpenAICompatClient
from llmtriage.models import Finding, TriageResult
from llmtriage.parsers import parse_bandit, parse_semgrep
from llmtriage.triage import triage_findings

HERE = Path(__file__).resolve().parent
APP_DIR = HERE / "vulnerable_app"
LABELS = HERE / "labels.json"
SEMGREP_FIXTURE = HERE / "semgrep_fixture.json"


def load_labels(path: Path = LABELS) -> dict[str, bool]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: v["label"] == "true_positive" for k, v in raw.items() if not k.startswith("_")}


def collect_findings() -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "bandit.json"
        # Fixed argument list, no shell, paths are our own bundled directory.
        subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                str(APP_DIR),
                "-f",
                "json",
                "-o",
                str(report),
                "-q",
            ],
            check=False,
            capture_output=True,
        )
        findings = parse_bandit(report, APP_DIR)
    findings += parse_semgrep(SEMGREP_FIXTURE, APP_DIR)
    return findings


def prf(pred: list[bool], truth: list[bool]) -> dict:
    tp = sum(p and t for p, t in zip(pred, truth, strict=True))
    fp = sum(p and not t for p, t in zip(pred, truth, strict=True))
    fn = sum((not p) and t for p, t in zip(pred, truth, strict=True))
    tn = sum((not p) and (not t) for p, t in zip(pred, truth, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
    }  # fmt: skip


def evaluate(results: list[TriageResult], labels: dict[str, bool]) -> dict:
    missing = [r.finding.id for r in results if r.finding.id not in labels]
    if missing:
        raise KeyError(f"findings without ground-truth labels: {missing}")
    truth = [labels[r.finding.id] for r in results]

    def raw_keep(r: TriageResult) -> bool:
        return r.llm is None or r.llm.verdict != "false_positive"

    scanner = prf([True] * len(results), truth)
    raw = prf([raw_keep(r) for r in results], truth)
    validated = prf([r.final_status != "false_positive" for r in results], truth)
    return {
        "n_findings": len(results),
        "n_true_vulns": sum(truth),
        "scanner_only": scanner,
        "llm_raw": raw,
        "llm_validated": validated,
        "dangerous_dismissals_raw": [
            r.finding.id for r, t in zip(results, truth, strict=True) if t and not raw_keep(r)
        ],
        "dangerous_dismissals_validated": [
            r.finding.id
            for r, t in zip(results, truth, strict=True)
            if t and r.final_status == "false_positive"
        ],
        "validation_flagged": sorted(
            f"{r.finding.id} -> {','.join(r.flags)}" for r in results if r.flags
        ),
        "auto_confirmed_true_positives": sum(
            1
            for r, t in zip(results, truth, strict=True)
            if r.final_status == "true_positive" and t
        ),
    }


# --------------------------- offline oracle simulation ---------------------------

# Planted mistakes, so the validator has something to catch:
ORACLE_FAULTS = {
    # Hallucinated evidence: cites code that does not exist.
    "bandit:B307:net.py:22": "hallucinate",
    # Obeys the prompt-injection comment: wrongly dismisses on a high/high finding.
    "bandit:B605:shell.py:18": "dismiss",
    "bandit:B602:shell.py:8": "dismiss",
    # Wrongly dismisses a real vuln at medium severity: validation cannot catch this one.
    "bandit:B506:config.py:10": "dismiss",
}


def oracle_client(labels: dict[str, bool]) -> MockClient:
    def responder(system: str, user: str) -> str:
        tool = re.search(r"^Scanner: (\w+)", user, re.M).group(1)
        rule = re.search(r"^Rule: (\S+)", user, re.M).group(1)
        file = re.search(r"^File: (\S+)", user, re.M).group(1)
        line = int(re.search(r"^Flagged line: (\d+)", user, re.M).group(1))
        fid = f"{tool}:{rule}:{file}:{line}"
        flagged = next(ln for ln in user.splitlines() if ln.startswith(">>"))
        quote = flagged.split("|", 1)[1].strip() or "x"
        is_vuln = labels[fid]
        fault = ORACLE_FAULTS.get(fid)
        verdict = "true_positive" if is_vuln else "false_positive"
        if fault == "dismiss":
            verdict = "false_positive"
        if fault == "hallucinate":
            quote = "os.popen(expression)"
        return json.dumps(
            {
                "verdict": verdict,
                "confidence": 0.8,
                "reason": f"oracle simulation ({fault or 'correct'})",
                "evidence_quote": quote,
                "evidence_line": line,
                "suggested_fix": "",
            }
        )

    return MockClient(responder, model="oracle-simulation")


def render_markdown(report: dict, provider: str, model: str) -> str:
    rows = [
        ("scanner-only", report["scanner_only"]),
        ("llm-raw", report["llm_raw"]),
        ("llm-validated", report["llm_validated"]),
    ]
    out = [
        "# Evaluation results",
        "",
        f"- Provider: `{provider}`  Model: `{model}`",
        f"- Findings: {report['n_findings']}  Real vulnerabilities: {report['n_true_vulns']}",
        "",
        "| Strategy | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, m in rows:
        out.append(
            f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} "
            f"| {m['tp']} | {m['fp']} | {m['fn']} |"
        )
    out += [
        "",
        f"- Real vulnerabilities dismissed (raw LLM): {report['dangerous_dismissals_raw']}",
        f"- Real vulnerabilities dismissed (validated): {report['dangerous_dismissals_validated']}",
        f"- Findings flagged by validation: {len(report['validation_flagged'])}",
    ]
    out += [f"  - {x}" for x in report["validation_flagged"]]
    if provider == "oracle":
        out += ["", "> **Simulation:** the `oracle` provider answers from the labels with planted "
                "mistakes. These numbers test the harness, not any real model."]  # fmt: skip
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--provider", choices=["xai", "oracle"], default="oracle")
    ap.add_argument("--model", default=None)
    ap.add_argument("--max-findings", type=int, default=None)
    ap.add_argument("--out-dir", default=str(HERE / "results"))
    args = ap.parse_args(argv)

    labels = load_labels()
    findings = collect_findings()
    client: LLMClient = (
        oracle_client(labels) if args.provider == "oracle" else OpenAICompatClient(model=args.model)
    )
    print(f"[*] {len(findings)} findings, provider={args.provider}, model={client.model}",
          file=sys.stderr)  # fmt: skip
    results = triage_findings(client, findings, APP_DIR, max_findings=args.max_findings)
    report = evaluate(results, labels)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"eval-{args.provider}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = render_markdown(report, args.provider, client.model)
    (out / f"eval-{args.provider}.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
