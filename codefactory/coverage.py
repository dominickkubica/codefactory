"""Measured test coverage, when the repository has a coverage report: which functions ran under the tests.

Static reachability ("a test calls something that calls it") guesses; a coverage report knows. Read, in order:
coverage/lcov.info and other lcov files (Jest, Vitest, c8, pytest-cov --cov-report=lcov, Go and Rust tools),
coverage/coverage-final.json (Istanbul: Jest, Vitest, nyc) and coverage.json (coverage.py's `coverage json`).
A function counts as covered when a line of its body ran; its first line doesn't count, because in Python the `def`
line runs on import whether or not the function is ever called.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

CANDIDATES = (
    "coverage/lcov.info",
    "lcov.info",
    "coverage.lcov",
    "coverage/coverage-final.json",
    "coverage.json",
    "htmlcov/coverage.json",
)


@dataclass
class Coverage:
    covered: set[str]  # function ids
    source: str  # the report, relative to the root
    written: str  # its date, YYYY-MM-DD
    seen: set[str]  # source files the report has data for (others fall back to the static estimate)


def _rel(root: Path, path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(root.resolve())
        except ValueError:
            return path.replace("\\", "/")
    return p.as_posix()


def _lcov(text: str, root: Path) -> dict[str, set[int]]:
    lines: dict[str, set[int]] = defaultdict(set)
    current = None
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            current = _rel(root, raw[3:].strip())
        elif raw.startswith("DA:") and current:
            parts = raw[3:].split(",")
            if len(parts) >= 2 and parts[1].strip().isdigit() and int(parts[1]) > 0:
                lines[current].add(int(parts[0]))
        elif raw.startswith("end_of_record"):
            current = None
    return lines


def _istanbul(data: dict, root: Path) -> dict[str, set[int]]:
    lines: dict[str, set[int]] = defaultdict(set)
    for path, cov in data.items():
        if not isinstance(cov, dict) or "statementMap" not in cov:
            continue
        rel = _rel(root, cov.get("path", path))
        for sid, hits in cov.get("s", {}).items():
            loc = cov["statementMap"].get(sid)
            if hits and loc:
                lines[rel].update(range(loc["start"]["line"], loc["end"]["line"] + 1))
    return lines


def _coverage_py(data: dict, root: Path) -> dict[str, set[int]]:
    return {_rel(root, p): set(f.get("executed_lines", [])) for p, f in data.get("files", {}).items()}


def _body(f: dict) -> range:
    """The lines that run only when the function is called (a one-line function: its only line)."""
    return range(f["line"] + 1, f["end"] + 1) if f["end"] > f["line"] else range(f["line"], f["line"] + 1)


def measured(root: Path, functions: list[dict]) -> Coverage | None:
    """The covered functions per the first coverage report found, or None if there is none (or it can't be read)."""
    for name in CANDIDATES:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            if name.endswith(".json"):
                data = json.loads(text)
                lines = _coverage_py(data, root) if "files" in data and "meta" in data else _istanbul(data, root)
            else:
                lines = _lcov(text, root)
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if not lines:
            continue
        covered = {f["id"] for f in functions if f["kind"] != "module" and any(n in lines.get(f["file"], ()) for n in _body(f))}
        written = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d")
        return Coverage(covered, name, written, set(lines))
    return None
