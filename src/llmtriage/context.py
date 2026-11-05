"""Safe access to the source files that findings point at."""

from __future__ import annotations

from pathlib import Path

MAX_FILE_BYTES = 1_000_000


class SourceError(ValueError):
    pass


def read_lines(root: Path, rel_path: str) -> list[str]:
    """Read a source file as lines. Refuses paths that escape `root` (path traversal guard):
    scanner reports are untrusted input and must not make us read arbitrary files."""
    root = root.resolve()
    target = (root / rel_path).resolve()
    if root != target and root not in target.parents:
        raise SourceError(f"path escapes source root: {rel_path}")
    if not target.is_file():
        raise SourceError(f"source file not found: {rel_path}")
    if target.stat().st_size > MAX_FILE_BYTES:
        raise SourceError(f"file too large to analyze: {rel_path}")
    return target.read_text(encoding="utf-8", errors="replace").splitlines()


def numbered_window(lines: list[str], line: int, radius: int = 12) -> str:
    """Return lines around `line` (1-based) as 'NNN | code', marking the flagged line."""
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    out = []
    for n in range(start, end + 1):
        marker = ">>" if n == line else "  "
        out.append(f"{marker}{n:4d} | {lines[n - 1]}")
    return "\n".join(out)
