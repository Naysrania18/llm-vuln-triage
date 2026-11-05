# PLAN: llm-vuln-triage

Python CLI that uses an LLM API (xAI Grok by default) to triage Semgrep and Bandit findings and summarize code risk, with strict validation so LLM hallucinations are flagged instead of trusted.

## Real AppSec work this maps to
SAST triage: deciding which scanner findings are real. This is the biggest time sink on AppSec teams. The tool shows safe use of an LLM in a security workflow.

## Features
1. **Input parsers**: Semgrep JSON/SARIF and Bandit JSON into one internal `Finding` model (file, line, rule, severity, message).
2. **Context extraction**: reads the actual code lines around each finding.
3. **LLM triage**: per finding, ask for a verdict (`true_positive` / `false_positive` / `needs_review`), a reason, a quoted code snippet as evidence, and a suggested fix. Response must be **JSON** matching a schema.
4. **Validation layer** (the core of the project):
   - JSON schema check (pydantic); invalid output is retried once, then marked `invalid`.
   - Quoted evidence must actually appear in the source file at/near the stated lines, otherwise `hallucination_flag`.
   - Any file, line or rule the LLM cites must exist in the scanner results or the code.
   - If a finding the LLM calls a false positive has high-severity/high-confidence scanner output, mark `disagreement` for human review.
   - LLM "new findings" (not from the scanners) are kept in a separate unverified list.
5. **Summarize mode**: LLM code summary for possible vulnerabilities, validated the same way.
6. **Output**: JSON, Markdown, SARIF (with triage status as a property).
7. **Secrets**: API key from `XAI_API_KEY` env var only (model via `XAI_MODEL`, endpoint via `XAI_BASE_URL`); provider-agnostic client so other OpenAI-compatible APIs work; `.env.example`; never committed. Dry-run mode with a mock LLM client for tests and CI.
8. **Evaluation**: `eval/` contains a deliberately vulnerable sample app (my own small Python code with known, labeled bugs plus labeled safe lookalikes), ground-truth labels, and `evaluate.py` that runs Semgrep + Bandit + triage and reports precision/recall/F1 and hallucination rate.

## How it differs from references
- PyRIT / garak / CyberSecEval evaluate or attack models; this applies an LLM to a defender's task and borrows their structure (target, scorer, dataset) for the eval harness.
- Semgrep and Bandit find issues but do not judge them; this adds a judged, validated layer on top.

## Industry tool integration
Reads Semgrep and Bandit output directly, writes SARIF, runs in GitHub Actions.

## Layout
`src/llmtriage/{models.py,parsers/,llm.py,validate.py,triage.py,reporters/,cli.py}`, `eval/{vulnerable_app/,labels.json,evaluate.py}`, `tests/`, `.env.example`, CI (pytest with mock LLM, ruff, bandit).

## Credits
Microsoft PyRIT, Meta Purple Llama / CyberSecEval, NVIDIA garak, Semgrep, Bandit.

## Risks / limits
- Real eval runs cost API tokens; the sample app is kept small. The author supplies their own xAI key; the assistant never sees it and runs no live calls.
- Semgrep CLI on Windows can be awkward (may need WSL); fallback is Bandit plus pre-generated Semgrep JSON fixtures. To be confirmed at build time.
- The eval set is small and written by me, so the precision/recall numbers are indicative, not a benchmark. The README will say so.
