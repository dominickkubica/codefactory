# codefactory: ignore-file secret, eval, shell, tls_off, raw_html, plain_http, swallowed — the patterns themselves
"""Repository and source checks for the review: security, reliability, delivery, dependencies, docs, testing.

Pattern checks read the source text (any comment style, both languages); repository checks read manifests and CI
files. Each returns Evidence: where (file:line), what was seen, and a short excerpt, so a reader can verify it.
"""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .brief import View
from .paths import is_test
from .suppress import MARK
from .suppress import _parse as parse_mark

SRC_EXT = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


@dataclass
class Evidence:
    file: str
    line: int
    text: str  # the line, trimmed

    def at(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class Check:
    key: str
    hits: list[Evidence] = field(default_factory=list)
    data: dict = field(default_factory=dict)


# ---- source patterns ------------------------------------------------------------------------------------------------

PATTERNS: dict[str, list[re.Pattern]] = {
    "secret": [
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b"),
        re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"),
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"),
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        re.compile(r"""(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|auth)\w*\s*[:=]\s*['"][A-Za-z0-9+/_\-]{20,}['"]"""),
    ],
    "eval": [
        re.compile(r"(?<![\w.])eval\s*\("),
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"(?<![\w.])exec\s*\(\s*[^)]"),
        re.compile(r"\bpickle\.loads?\s*\("),
        re.compile(r"\byaml\.load\s*\((?![^)]*SafeLoader)"),
    ],
    "shell": [
        re.compile(r"shell\s*=\s*True"),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bexecSync\s*\(\s*`[^`]*\$\{"),
        re.compile(r"\bchild_process\b.*\bexec\s*\("),
    ],
    "tls_off": [
        re.compile(r"verify\s*=\s*False"),
        re.compile(r"rejectUnauthorized\s*:\s*false"),
        re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED"),
        re.compile(r"ssl\._create_unverified_context"),
        re.compile(r"CERT_NONE"),
    ],
    "raw_html": [
        re.compile(r"dangerouslySetInnerHTML"),
        re.compile(r"\.innerHTML\s*=(?!=)"),
        re.compile(r"\bv-html\b"),
        re.compile(r"\|\s*safe\b"),
        re.compile(r"\bmark_safe\s*\("),
    ],
    "plain_http": [
        re.compile(r"""['"`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|schemas\.|www\.w3\.org|xmlns)[^'"`\s]+""")
    ],
    "swallowed": [
        re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
        re.compile(r"\.catch\(\s*\(\s*\)\s*=>\s*(?:\{\s*\}|undefined|null)\s*\)"),
        re.compile(r"except(?:\s+[\w.(), ]+)?\s*:\s*pass\b"),
    ],
}
SQL_CALL = re.compile(
    r"(?:execute|executemany|executescript|query|raw|getAllAsync|getFirstAsync|runAsync|execAsync|"
    r"prepareAsync|getAllSync|runSync)\s*\(\s*(f['\"]|`|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))"
)
HOST = re.compile(r"""['"`]https?://([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?[/'"`?]""", re.I)
SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WHERE|FROM)\b", re.I)
INTERP = re.compile(r"\$\{([^}]+)\}|\{([^}:!]+)[^}]*\}")
CONSTANT = re.compile(r"^[A-Z0-9_]+$|^\w+\.length$|^\w+\.map\(\(\) => ['\"]\?['\"]\)\.join\(['\"], ?['\"]\)$")


def _excerpt(line: str) -> str:
    t = line.strip()
    return t if len(t) <= 140 else t[:137] + "…"


def _ignored(lines: list[str], i: int, key: str, file_kinds: set[str] | None) -> bool:
    """`codefactory: ignore <check>` on the line or the one above, or `ignore-file` for the file (no kinds = all)."""
    if file_kinds is not None and (not file_kinds or key in file_kinds):
        return True
    for ln in (i, i - 1):
        if 1 <= ln <= len(lines) and (m := MARK.search(lines[ln - 1])) and not m.group(1):
            kinds, _ = parse_mark(m.group(2))
            if not kinds or key in kinds:
                return True
    return False


def scan_sources(root: Path, files: list[str]) -> dict[str, Check]:
    out = {k: Check(k) for k in [*PATTERNS, "sql_built", "module_state", "fetch_no_timeout", "hosts", "error_boundary"]}
    for fid in files:
        if not fid.endswith(SRC_EXT):
            continue
        try:
            text = (root / fid).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        test = is_test(fid)
        lines = text.splitlines()
        marks = [parse_mark(m.group(2))[0] for ln in lines if (m := MARK.search(ln)) and m.group(1)]
        file_kinds = set().union(*marks) if marks and all(marks) else (set() if marks else None)

        def hit(key: str, i: int, lines=lines, file_kinds=file_kinds) -> bool:  # bound to this file's lines
            return not _ignored(lines, i, key, file_kinds)

        for i, line in enumerate(lines, 1):
            if len(line) > 2000:  # minified or data
                continue
            for key, pats in PATTERNS.items():
                if test and key != "secret":  # tests may do anything on purpose; a leaked key is still leaked
                    continue
                if any(p.search(line) for p in pats) and hit(key, i):
                    if key == "secret" and re.search(r"(?i)example|placeholder|dummy|xxxx|your[_-]|changeme|<", line):
                        continue
                    out[key].hits.append(Evidence(fid, i, _excerpt(line)))
            if not test and (m := SQL_CALL.search(line)) and hit("sql_built", i):
                stmt = " ".join(lines[i - 1 : i + 4])
                if SQL_WORD.search(stmt):
                    names = [a or b for a, b in INTERP.findall(stmt[m.start() : m.start() + 600])]
                    risky = [n for n in names if not CONSTANT.match(n.strip())]
                    if risky or m.group(1).endswith(("%", "+")) or ".format" in m.group(1):
                        out["sql_built"].hits.append(Evidence(fid, i, _excerpt(line)))
                        out["sql_built"].data.setdefault(f"{fid}:{i}", risky[:4])
            if not test and not re.match(r"\s*(//|#|\*|/\*)", line):  # hosts the code uses, not ones a comment mentions
                for host in HOST.findall(line):
                    if host not in out["hosts"].data and not re.search(r"example\.|localhost|w3\.org|schema", host):
                        out["hosts"].data[host] = f"{fid}:{i}"
            if re.search(r"ErrorBoundary|componentDidCatch|getDerivedStateFromError", line):
                out["error_boundary"].hits.append(Evidence(fid, i, _excerpt(line)))
            if (
                not test
                and fid.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs"))
                and re.match(r"^(?:export\s+)?let\s+\w+", line)
                and hit("module_state", i)
            ):
                out["module_state"].hits.append(Evidence(fid, i, _excerpt(line)))
        if (
            not test
            and re.search(r"(?<![\w.])fetch\s*\(", text)
            and not re.search(r"\bsignal\b|AbortSignal\.timeout|timeout", text)
        ):
            ln = next(i for i, text in enumerate(lines, 1) if re.search(r"(?<![\w.])fetch\s*\(", text))
            out["fetch_no_timeout"].hits.append(Evidence(fid, ln, _excerpt(lines[ln - 1])))
        if not test and fid.endswith(".py"):
            for i, line in enumerate(lines, 1):
                if re.search(r"\brequests\.(get|post|put|patch|delete|head)\s*\(", line) and "timeout" not in " ".join(
                    lines[i - 1 : i + 3]
                ):
                    out["fetch_no_timeout"].hits.append(Evidence(fid, i, _excerpt(line)))
                if re.match(r"^\s+global\s+\w+", line):
                    out["module_state"].hits.append(Evidence(fid, i, _excerpt(line)))
    return out


# ---- repository ----------------------------------------------------------------------------------------------------

CI_FILES = [
    ".github/workflows",
    ".gitlab-ci.yml",
    ".circleci",
    "azure-pipelines.yml",
    "Jenkinsfile",
    ".travis.yml",
    "bitbucket-pipelines.yml",
    ".buildkite",
]
LOCKS = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "requirements.lock",
    "Cargo.lock",
    "go.sum",
]


def scan_repo(root: Path) -> dict:
    info: dict = {
        "ci": [],
        "ci_steps": set(),
        "ci_on_push": False,
        "locks": [],
        "manifests": [],
        "floating": [],
        "unpinned_py": [],
        "runtime_pin": [],
        "readme": None,
        "license": None,
        "env_files": [],
        "frameworks": set(),
        "deps": {},
        "deploy": [],
    }
    for c in CI_FILES:
        p = root / c
        if p.is_dir():
            info["ci"] += [str(f.relative_to(root)).replace("\\", "/") for f in sorted(p.glob("*.y*ml"))]
        elif p.is_file():
            info["ci"].append(c)
    for f in info["ci"]:
        try:
            t = (root / f).read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for step, words in {
            "tests": ["test", "pytest", "jest", "vitest", "unittest"],
            "lint": ["lint", "ruff", "flake8", "eslint"],
            "typecheck": ["tsc", "mypy", "pyright", "typecheck"],
            "build": ["build"],
        }.items():
            if any(w in t for w in words):
                info["ci_steps"].add(step)
        if re.search(r"\bpush\s*:", t) or re.search(r"on:\s*\[?\s*push", t):
            info["ci_on_push"] = True
    info["locks"] = [name for name in LOCKS if (root / name).exists()]
    pkg = root / "package.json"
    if pkg.is_file():
        info["manifests"].append("package.json")
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        info["deps"].update(deps)
        info["floating"] = [
            f"{k}@{v}" for k, v in deps.items() if v in ("*", "latest", "") or v.startswith(("git", "http", "github:"))
        ]
        if "engines" in data:
            info["runtime_pin"].append("package.json engines")
        for name, fw in (
            ("react-native", "React Native"),
            ("expo", "Expo"),
            ("react", "React"),
            ("next", "Next.js"),
            ("vue", "Vue"),
            ("express", "Express"),
            ("@nestjs/core", "NestJS"),
            ("svelte", "Svelte"),
        ):
            if name in deps:
                info["frameworks"].add(fw)
        info["deploy"] += [k for k in data.get("scripts", {}) if re.search(r"deploy|release|publish|ota", k)]
    for req in ("requirements.txt", "requirements-dev.txt"):
        p = root / req
        if p.is_file():
            info["manifests"].append(req)
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.split("#")[0].strip()
                if s and not s.startswith("-") and "==" not in s and "@" not in s:
                    info["unpinned_py"].append(s)
    if (root / "pyproject.toml").is_file():
        info["manifests"].append("pyproject.toml")
        t = (root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        for name, fw in (("django", "Django"), ("flask", "Flask"), ("fastapi", "FastAPI"), ("sqlalchemy", "SQLAlchemy")):
            if re.search(rf"\b{name}\b", t, re.I):
                info["frameworks"].add(fw)
        if "requires-python" in t:
            info["runtime_pin"].append("requires-python")
    for f in (".nvmrc", ".node-version", ".python-version", ".tool-versions", "runtime.txt"):
        if (root / f).exists():
            info["runtime_pin"].append(f)
    info["readme"] = next((f for f in ("README.md", "README.rst", "README.txt", "README") if (root / f).exists()), None)
    info["license"] = next((f for f in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING") if (root / f).exists()), None)
    info["env_files"] = [
        p.name for p in root.glob(".env*") if p.is_file() and not p.name.endswith((".example", ".sample", ".template"))
    ]
    if info["readme"]:
        t = (root / info["readme"]).read_text(encoding="utf-8", errors="replace").lower()
        info["readme_run"] = bool(re.search(r"install|npm |pip |yarn |make |cargo |go run|docker", t))
    return info


# ---- testing -------------------------------------------------------------------------------------------------------


def test_reach(v: View) -> set[str]:
    """Functions a test calls or hands on (a callback), directly or through others."""
    out_edges: dict[str, list[str]] = {}
    for e in v.g["edges"]:
        if e["kind"] in ("call", "ref"):
            out_edges.setdefault(e["src"], []).append(e["dst"])
    start = [fid for fid, f in v.fn.items() if is_test(f["file"])]
    seen, q = set(start), deque(start)
    while q:
        for nxt in out_edges.get(q.popleft(), []):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return seen
