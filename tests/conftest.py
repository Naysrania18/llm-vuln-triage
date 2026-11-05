from __future__ import annotations

import json

import pytest

from llmtriage.models import Finding

SOURCE = """import subprocess
import hashlib


def run(user_cmd):
    subprocess.call(user_cmd, shell=True)


def cache_key(name):
    return hashlib.md5(name.encode()).hexdigest()
"""


@pytest.fixture()
def src_root(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def lines():
    return SOURCE.splitlines()


@pytest.fixture()
def shell_finding():
    # line 6 = subprocess.call(user_cmd, shell=True)
    return Finding(
        id="bandit:B602:app.py:6",
        tool="bandit",
        rule_id="B602",
        file="app.py",
        line=6,
        severity="high",
        confidence="high",
        message="subprocess call with shell=True identified, security issue.",
    )


def make_reply(**overrides) -> str:
    base = {
        "verdict": "true_positive",
        "confidence": 0.9,
        "reason": "user input reaches a shell",
        "evidence_quote": "subprocess.call(user_cmd, shell=True)",
        "evidence_line": 6,
        "suggested_fix": "pass an argument list and shell=False",
    }
    base.update(overrides)
    return json.dumps(base)
