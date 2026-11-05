"""Sample code for evaluating the triage tool. DELIBERATELY VULNERABLE. Never deploy."""

import pickle
import random

import requests


def fetch(url: str) -> str:
    return requests.get(url, verify=False, timeout=5).text


def backoff_delay(attempt: int) -> float:
    return (2**attempt) + random.random()


def restore_session(blob: bytes):
    return pickle.loads(blob)


def calculate(expression: str):
    return eval(expression)


def save_report(text: str) -> None:
    with open("/tmp/report.txt", "w") as fh:
        fh.write(text)


def check_positive(value: int) -> int:
    assert value > 0, "internal invariant"
    return value
