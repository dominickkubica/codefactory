"""Known vulnerabilities in dependencies, from OSV.dev (Google's free, open vulnerability database).

Off unless asked for (`--online`): it's the one check that leaves the machine. It sends package names and versions,
nothing else: no code, no file names, no repository name. Versions come from lockfiles, so they're exactly what's
installed: package-lock.json, yarn.lock (v1), pnpm-lock.yaml, poetry.lock, uv.lock, Pipfile.lock, pinned
requirements files, Cargo.lock, go.sum, Gemfile.lock and composer.lock.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

API = "https://api.osv.dev/v1"
BATCH = 500
DETAILS = 60  # vulnerabilities whose details are fetched (summary, severity, fixed version); the rest are counted


@dataclass(frozen=True)
class Package:
    ecosystem: str  # OSV's names: npm, PyPI, crates.io, Go, RubyGems, Packagist
    name: str
    version: str
    source: str  # the lockfile
    dev: bool = False  # a development-only dependency (tests, builds): not shipped


@dataclass
class Vulnerability:
    package: Package
    id: str
    summary: str = ""
    severity: str = ""  # CRITICAL | HIGH | MODERATE | LOW | ""
    fixed: str = ""  # the first fixed version, when OSV gives one


def _npm_lock(text: str, src: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for path, info in (data.get("packages") or {}).items():
        if path and info.get("version") and not info.get("link"):
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            out.append(Package("npm", name, info["version"], src, bool(info.get("dev"))))
    for name, info in (data.get("dependencies") or {}).items():  # lockfile v1
        if info.get("version") and not data.get("packages"):
            out.append(Package("npm", name, info["version"], src))
    return out


def _yarn_lock(text: str, src: str) -> list[Package]:
    out, names = [], []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            names = [re.sub(r"@[^@]*$", "", s.strip().strip('"')) for s in line.rstrip(":").split(",")]
        elif (m := re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)) and names:
            out += [Package("npm", n, m.group(1), src) for n in dict.fromkeys(names) if n]
            names = []
    return out


def _pnpm_lock(text: str, src: str) -> list[Package]:
    found = re.findall(r"^\s{2}/?((?:@[^/@\s]+/)?[^/@\s:]+)[@/](\d[^\s:(]*)", text, re.M)
    return [Package("npm", n, v, src) for n, v in dict.fromkeys(found)]


def _toml_packages(text: str, src: str, eco: str) -> list[Package]:
    import tomllib

    data = tomllib.loads(text)
    return [Package(eco, p["name"], p["version"], src) for p in data.get("package", []) if p.get("name") and p.get("version")]


def _pipfile_lock(text: str, src: str) -> list[Package]:
    data = json.loads(text)
    return [
        Package("PyPI", n, info["version"].lstrip("="), src)
        for section in ("default", "develop")
        for n, info in (data.get(section) or {}).items()
        if str(info.get("version", "")).startswith("==")
    ]


def _requirements(text: str, src: str) -> list[Package]:
    return [
        Package("PyPI", m.group(1), m.group(2), src)
        for m in re.finditer(r"^\s*([\w.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.!+\-]+)", text, re.M)
    ]


def _go_sum(text: str, src: str) -> list[Package]:
    found = re.findall(r"^(\S+) (v[^\s/]+?)(?:/go\.mod)? ", text, re.M)
    return [Package("Go", n, v.removeprefix("v"), src) for n, v in dict.fromkeys(found)]


def _gemfile_lock(text: str, src: str) -> list[Package]:
    return [Package("RubyGems", n, v, src) for n, v in re.findall(r"^    ([\w.\-]+) \(([\w.\-]+)\)$", text, re.M)]


def _composer_lock(text: str, src: str) -> list[Package]:
    data = json.loads(text)
    return [
        Package("Packagist", p["name"], str(p["version"]).lstrip("v"), src)
        for section in ("packages", "packages-dev")
        for p in data.get(section) or []
        if p.get("name") and p.get("version")
    ]


READERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "poetry.lock": lambda t, s: _toml_packages(t, s, "PyPI"),
    "uv.lock": lambda t, s: _toml_packages(t, s, "PyPI"),
    "Pipfile.lock": _pipfile_lock,
    "Cargo.lock": lambda t, s: _toml_packages(t, s, "crates.io"),
    "go.sum": _go_sum,
    "Gemfile.lock": _gemfile_lock,
    "composer.lock": _composer_lock,
}


def packages(root: Path) -> list[Package]:
    """Every pinned dependency in the repository's lockfiles (at the root and one level down, for monorepos)."""
    out: list[Package] = []
    candidates = [root / n for n in READERS] + [p for p in root.glob("*/*") if p.name in READERS]
    candidates += (
        sorted(root.glob("requirements*.txt")) + sorted(root.glob("requirements/*.txt")) + sorted(root.glob("constraints*.txt"))
    )
    for path in candidates:
        if not path.is_file() or "node_modules" in path.relative_to(root).parts:
            continue
        reader = READERS.get(path.name, _requirements)
        try:
            out += reader(path.read_text(encoding="utf-8", errors="replace"), path.relative_to(root).as_posix())
        except (ValueError, KeyError, TypeError):
            continue  # an unreadable lockfile: skip it rather than fail the review
    return list(dict.fromkeys(out))


def _post(url: str, body: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (a fixed https URL)
        return json.loads(r.read())


def _get(url: str, timeout: int) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
        return json.loads(r.read())


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "": 4}


def vulnerabilities(pkgs: list[Package], timeout: int = 30) -> list[Vulnerability]:
    """Known vulnerabilities of these exact versions. Raises OSError when OSV can't be reached."""
    found: list[Vulnerability] = []
    for i in range(0, len(pkgs), BATCH):
        chunk = pkgs[i : i + BATCH]
        queries = [{"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version} for p in chunk]
        # codefactory: ignore io_in_loop — one request per 500 packages, OSV's batch size
        results = _post(f"{API}/querybatch", {"queries": queries}, timeout).get("results", [])
        for p, res in zip(chunk, results, strict=False):
            found += [Vulnerability(p, v["id"]) for v in res.get("vulns") or []]
    for v in found[:DETAILS]:
        try:
            # codefactory: ignore io_in_loop — OSV has no batch endpoint for details; capped at DETAILS requests
            d = _get(f"{API}/vulns/{v.id}", timeout)
        except (OSError, ValueError):
            continue
        v.summary = (d.get("summary") or d.get("details", "").split("\n")[0])[:160]
        v.severity = str((d.get("database_specific") or {}).get("severity") or "").upper()
        for a in d.get("affected", []):
            if a.get("package", {}).get("name") == v.package.name:
                fixes = [e["fixed"] for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e]
                v.fixed = ", ".join(dict.fromkeys(fixes))
    found.sort(key=lambda v: (SEVERITY_ORDER.get(v.severity, 4), v.package.name))
    return found
