"""Optional per-repo settings from factory.toml: layer globs, forbidden layer pairs, thresholds, ignores."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORE = [
    ".git", ".hg", "node_modules", ".venv", "venv", "env", "__pycache__", "build", "dist", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages", ".eggs",
]


@dataclass
class Config:
    layers: dict[str, list[str]] = field(default_factory=dict)  # layer name -> glob patterns
    forbid: list[tuple[str, str]] = field(default_factory=list)
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE))
    large_file: int = 400
    long_function: int = 60
    duplicate_min_lines: int = 6
    hub_callers: int = 12
    queries: list[dict] = field(default_factory=list)  # saved SQL checks that become flags


def parse_rule(rule: str) -> tuple[str, str]:
    left, sep, right = rule.partition("->")
    if not sep or not left.strip() or not right.strip():
        raise ValueError(f"Bad rule {rule!r}: write it as 'ui -> db'")
    return left.strip(), right.strip()


def load_config(root: Path) -> Config:
    path = root / "factory.toml"
    cfg = Config()
    if not path.is_file():
        return cfg
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    layers = data.get("layers", {})
    cfg.layers = {name: [globs] if isinstance(globs, str) else list(globs) for name, globs in layers.items()}
    cfg.forbid = [parse_rule(r) for r in data.get("rules", {}).get("forbid", [])]
    cfg.ignore += list(data.get("ignore", []))
    t = data.get("thresholds", {})
    cfg.large_file = int(t.get("large_file", cfg.large_file))
    cfg.long_function = int(t.get("long_function", cfg.long_function))
    cfg.duplicate_min_lines = int(t.get("duplicate_min_lines", cfg.duplicate_min_lines))
    cfg.hub_callers = int(t.get("hub_callers", cfg.hub_callers))
    for q in data.get("queries", []):
        if not q.get("name") or not q.get("sql"):
            raise ValueError("Each [[queries]] entry in factory.toml needs a name and sql")
        if q.get("severity", "warn") not in ("high", "warn", "info"):
            raise ValueError(f"Query {q['name']!r}: severity must be high, warn or info")
        cfg.queries.append({k: q[k] for k in ("name", "sql", "severity", "message") if k in q})
    return cfg
