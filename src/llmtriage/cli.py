"""CLI: `llmtriage triage` and `llmtriage summarize`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .context import SourceError
from .llm import LLMAuthError, LLMClient, MockClient, OpenAICompatClient
from .models import Finding
from .parsers import ReportError, parse_bandit, parse_semgrep
from .reporters import WRITERS, summary_counts
from .triage import triage_findings

DISCLAIMER = (
    "Note: your source code excerpts are sent to the configured LLM provider. "
    "Do not use this on code you are not allowed to share with a third party."
)


def dry_run_client() -> MockClient:
    """Offline client: answers 'needs_review' quoting the flagged line. Proves the pipeline
    works end to end without any API key or network."""

    def responder(system: str, user: str) -> str:
        flagged = next((ln for ln in user.splitlines() if ln.startswith(">>")), ">>   1 | ")
        number, _, code = flagged[2:].partition("|")
        return json.dumps(
            {
                "verdict": "needs_review",
                "confidence": 0.0,
                "reason": "dry-run: no model was called",
                "evidence_quote": code.strip() or "x",
                "evidence_line": int(number.strip() or 1),
                "suggested_fix": "",
            }
        )

    return MockClient(responder, model="dry-run")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llmtriage",
        description="Triage Semgrep/Bandit findings with an LLM and validate every claim.",
        epilog=DISCLAIMER,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("triage", help="triage scanner findings")
    t.add_argument("--bandit", help="Bandit JSON report (bandit -f json)")
    t.add_argument("--semgrep", help="Semgrep JSON report (semgrep --json)")
    t.add_argument("--source-root", required=True, help="directory the reports' paths refer to")
    t.add_argument("--out-dir", default="reports")
    t.add_argument("--format", default="json,md,sarif")
    t.add_argument("--max-findings", type=int, default=None, help="cap API calls")
    t.add_argument("--cache-dir", default=".triage-cache", help="reuse past LLM replies")
    t.add_argument("--no-cache", action="store_true")
    t.add_argument("--model", default=None, help="overrides XAI_MODEL")
    t.add_argument("--dry-run", action="store_true", help="no API calls; offline mock model")

    s = sub.add_parser("summarize", help="LLM security summary of one file, with validation")
    s.add_argument("--file", required=True, help="path relative to --source-root")
    s.add_argument("--source-root", required=True)
    s.add_argument("--bandit")
    s.add_argument("--semgrep")
    s.add_argument("--model", default=None)
    return p


def _load_findings(args: argparse.Namespace, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if args.bandit:
        findings += parse_bandit(args.bandit, root)
    if args.semgrep:
        findings += parse_semgrep(args.semgrep, root)
    return findings


def _client(args: argparse.Namespace) -> LLMClient:
    if getattr(args, "dry_run", False):
        return dry_run_client()
    return OpenAICompatClient(model=args.model)


def cmd_triage(args: argparse.Namespace) -> int:
    root = Path(args.source_root)
    findings = _load_findings(args, root)
    if not findings:
        print("no findings to triage (pass --bandit and/or --semgrep)", file=sys.stderr)
        return 2
    client = _client(args)
    print(f"[*] {len(findings)} finding(s); model={client.model}", file=sys.stderr)
    if not args.dry_run:
        print(DISCLAIMER, file=sys.stderr)

    def progress(i: int, n: int, f: Finding) -> None:
        print(f"[{i}/{n}] {f.rule_id} {f.file}:{f.line}", file=sys.stderr)

    results = triage_findings(
        client,
        findings,
        root,
        cache_dir=None if args.no_cache or args.dry_run else Path(args.cache_dir),
        max_findings=args.max_findings,
        on_progress=progress,
    )
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fmt in [x.strip() for x in args.format.split(",") if x.strip()]:
        if fmt not in WRITERS:
            raise SystemExit(f"unknown format: {fmt}")
        writer, ext = WRITERS[fmt]
        (out / f"triage.{ext}").write_text(writer(results, client.model), encoding="utf-8")
    print(f"[+] {summary_counts(results)}", file=sys.stderr)
    print(f"[+] reports written to {out}", file=sys.stderr)
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    from .summarize import summarize_file

    root = Path(args.source_root)
    findings = _load_findings(args, root)
    client = _client(args)
    resp, issues, err = summarize_file(client, root, args.file, findings)
    if resp is None:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(resp.summary, "\n")
    for v in issues:
        mark = {"corroborated": "[OK]", "unverified": "[??]", "hallucinated": "[XX]"}[v.status]
        print(f"{mark} line {v.item.line}: {v.item.title} ({v.item.severity}) - {v.status}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return cmd_triage(args) if args.command == "triage" else cmd_summarize(args)
    except (LLMAuthError, ReportError, SourceError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
