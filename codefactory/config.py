"""Optional per-repo settings from factory.toml: layer globs, forbidden layer pairs, thresholds, ignores."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IGNORE = [
    ".git",
    ".hg",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    ".eggs",
    ".codefactory",
    ".expo",
    "coverage",
]


@dataclass
class Config:
    layers: dict[str, list[str]] = field(default_factory=dict)  # layer name -> glob patterns
    forbid: list[tuple[str, str]] = field(default_factory=list)
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE))
    large_file: int = 400
    long_function: int = 60
    duplicate_min_lines: int = 6
    similar_threshold: float = 0.75  # near-duplicates: share of structure in common (0-1)
    hub_callers: int = 12
    queries: list[dict] = field(default_factory=list)  # saved SQL checks that become flags
    silence: list[dict] = field(default_factory=list)  # [[silence]] kind / where (glob) / reason (+ by, on)
    rules: list[dict] = field(default_factory=list)  # [[rule]] custom pattern checks: id, pattern, files, severity…
    profile: dict = field(default_factory=dict)  # [profile] corrections to the detected project profile


def parse_rule(rule: str) -> tuple[str, str]:
    left, sep, right = rule.partition("->")
    if not sep or not left.strip() or not right.strip():
        raise ValueError(f"Bad rule {rule!r}: write it as 'ui -> db'")
    return left.strip(), right.strip()


def _read(path: Path, seen: tuple = ()) -> dict:
    """factory.toml, merged over the policy it `extends` (an organisation's shared file): tables merge, lists append,
    so a team adds to the shared rules and thresholds rather than replacing them."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"{path.name} isn't valid TOML: {e}") from None
    except OSError as e:
        raise ValueError(f"can't read {path}: {e.strerror}") from None
    parent = data.pop("extends", None)
    if not parent:
        return data
    base_path = (path.parent / parent).resolve()
    if base_path in seen:
        raise ValueError(f"factory.toml `extends` loops back to {base_path}")
    merged = _read(base_path, (*seen, path.resolve()))
    for key, value in data.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        elif isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged


def load_config(root: Path) -> Config:
    path = root / "factory.toml"
    cfg = Config()
    if not path.is_file():
        return cfg
    data = _read(path)
    layers = data.get("layers", {})
    cfg.layers = {name: [globs] if isinstance(globs, str) else list(globs) for name, globs in layers.items()}
    cfg.forbid = [parse_rule(r) for r in data.get("rules", {}).get("forbid", [])]
    cfg.ignore += list(data.get("ignore", []))
    t = data.get("thresholds", {})
    cfg.large_file = int(t.get("large_file", cfg.large_file))
    cfg.long_function = int(t.get("long_function", cfg.long_function))
    cfg.duplicate_min_lines = int(t.get("duplicate_min_lines", cfg.duplicate_min_lines))
    cfg.similar_threshold = float(t.get("similar", cfg.similar_threshold))
    cfg.hub_callers = int(t.get("hub_callers", cfg.hub_callers))
    for q in data.get("queries", []):
        if not q.get("name") or not q.get("sql"):
            raise ValueError("Each [[queries]] entry in factory.toml needs a name and sql")
        if q.get("severity", "warn") not in ("high", "warn", "info"):
            raise ValueError(f"Query {q['name']!r}: severity must be high, warn or info")
        cfg.queries.append({k: q[k] for k in ("name", "sql", "severity", "message") if k in q})
    for rule in data.get("silence", []):
        if not rule.get("where"):
            raise ValueError("Each [[silence]] entry in factory.toml needs `where` (a file or file::function glob)")
        reason = rule.get("reason", "")
        if rule.get("by") or rule.get("on"):  # who accepted it, and when (written by `codefactory accept`)
            by = f" by {rule['by']}" if rule.get("by") else ""
            on = f" on {rule['on']}" if rule.get("on") else ""
            reason += f" (accepted{by}{on})"
        cfg.silence.append({"kind": rule.get("kind", "*"), "where": rule["where"], "reason": reason})
    for r in data.get("rule", []):
        if not r.get("id") or not r.get("pattern"):
            raise ValueError("Each [[rule]] entry in factory.toml needs an id and a pattern (a regular expression)")
        if r.get("severity", "warn") not in ("high", "warn", "info"):
            raise ValueError(f"Rule {r['id']!r}: severity must be high, warn or info")
        try:
            regex = re.compile(r["pattern"])
        except re.error as e:
            raise ValueError(f"Rule {r['id']!r}: the pattern isn't a valid regular expression ({e})") from None
        files = r.get("files", ["**/*"])
        cfg.rules.append({
            "id": r["id"], "regex": regex, "files": [files] if isinstance(files, str) else list(files),
            "severity": r.get("severity", "warn"), "message": r.get("message", r["id"]), "fix": r.get("fix", ""),
        })  # fmt: skip
    cfg.profile = _profile(data.get("profile", {}))
    return cfg


PROFILE_KEYS = {
    "kind": ("mobile app", "web app", "web service", "desktop app", "web front-end", "static website",
             "command-line tool", "data pipeline", "library"),
    "deployment": ("local-first", "client app", "local server", "LAN server", "network server", "deployed server",
                   "user's machine", "browser", "static hosting"),
    "users": ("single user", "multi-user", "no sign-in"),
}  # fmt: skip


def _profile(data: dict) -> dict:
    """[profile] in factory.toml: what the detection got wrong. Values are checked so a typo can't silently do nothing."""
    from .profile import SENSITIVE

    out: dict = {}
    for key, value in data.items():
        if key == "sensitive":
            values = [value] if isinstance(value, str) else list(value)
            bad = [v for v in values if v not in SENSITIVE and v != "none"]
            if bad:
                raise ValueError(f'[profile] sensitive: {bad[0]!r} isn\'t one of {", ".join(SENSITIVE)} (or "none")')
            out[key] = [v for v in values if v != "none"]
        elif key in PROFILE_KEYS:
            if value not in PROFILE_KEYS[key]:
                raise ValueError(f"[profile] {key}: {value!r} isn't one of {', '.join(PROFILE_KEYS[key])}")
            out[key] = value
        else:
            raise ValueError(f"[profile] has no setting {key!r} (kind, deployment, users, sensitive)")
    return out
