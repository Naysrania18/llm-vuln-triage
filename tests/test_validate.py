"""The validation layer is the core of this project: every kind of bad LLM output must be
caught and downgraded to needs_review instead of being trusted."""

from __future__ import annotations

from conftest import make_reply
from llmtriage.validate import find_quote_lines, normalize, validate_verdict


def test_honest_reply_is_trusted(shell_finding, lines):
    r = validate_verdict(make_reply(), shell_finding, lines)
    assert r.trusted and r.flags == []
    assert r.final_status == "true_positive"


def test_fenced_json_and_prose_are_tolerated(shell_finding, lines):
    raw = "Sure! Here you go:\n```json\n" + make_reply() + "\n```"
    assert validate_verdict(raw, shell_finding, lines).trusted


def test_hallucinated_quote_is_flagged(shell_finding, lines):
    raw = make_reply(evidence_quote="os.system(request.args['cmd'])")
    r = validate_verdict(raw, shell_finding, lines)
    assert "quote_not_found" in r.flags
    assert not r.trusted and r.final_status == "needs_review"
    assert r.llm.verdict == "true_positive"  # original claim kept for the human, not trusted


def test_line_beyond_end_of_file_is_flagged(shell_finding, lines):
    r = validate_verdict(make_reply(evidence_line=999), shell_finding, lines)
    assert "line_out_of_range" in r.flags and not r.trusted


def test_real_quote_wrong_line_is_flagged(shell_finding, lines):
    r = validate_verdict(make_reply(evidence_line=2), shell_finding, lines)
    assert "line_mismatch" in r.flags


def test_quote_far_from_flagged_line_is_flagged(shell_finding, lines):
    far = [*lines, *[""] * 30, "danger = eval(x)"]
    raw = make_reply(evidence_quote="danger = eval(x)", evidence_line=len(far))
    r = validate_verdict(raw, shell_finding, far)
    assert "quote_far_from_finding" in r.flags


def test_false_positive_on_high_high_finding_disagrees_with_scanner(shell_finding, lines):
    r = validate_verdict(make_reply(verdict="false_positive"), shell_finding, lines)
    assert r.flags == ["disagrees_with_scanner"]
    assert r.final_status == "needs_review"


def test_false_positive_on_low_confidence_finding_is_trusted(shell_finding, lines):
    shell_finding.severity, shell_finding.confidence = "low", "low"
    r = validate_verdict(
        make_reply(verdict="false_positive", reason="constant command"), shell_finding, lines
    )
    assert r.trusted and r.final_status == "false_positive"


def test_not_json_is_schema_invalid(shell_finding, lines):
    r = validate_verdict("I think this is a vulnerability.", shell_finding, lines)
    assert r.flags == ["schema_invalid"] and r.llm is None and not r.trusted


def test_extra_keys_rejected(shell_finding, lines):
    raw = make_reply(rule_id="B999")  # unknown key
    assert validate_verdict(raw, shell_finding, lines).flags == ["schema_invalid"]


def test_bad_types_and_ranges_rejected(shell_finding, lines):
    for bad in ({"confidence": 1.7}, {"verdict": "maybe"}, {"evidence_line": 0}, {"reason": ""}):
        r = validate_verdict(make_reply(**bad), shell_finding, lines)
        assert r.flags == ["schema_invalid"], bad


def test_missing_key_rejected(shell_finding, lines):
    import json

    d = json.loads(make_reply())
    del d["evidence_quote"]
    assert validate_verdict(json.dumps(d), shell_finding, lines).flags == ["schema_invalid"]


def test_whitespace_insensitive_quote_match():
    lines = ["    x  =   foo(  a,b )"]
    assert find_quote_lines("x = foo( a,b )", lines) == [1]
    assert normalize("a \t b\n c") == "a b c"


def test_multiline_quote_must_be_consecutive():
    lines = ["a = 1", "b = 2", "c = 3"]
    assert find_quote_lines("a = 1\nb = 2", lines) == [1]
    assert find_quote_lines("a = 1\nc = 3", lines) == []
