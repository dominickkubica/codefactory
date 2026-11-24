"""`codefactory review`: a technical review of a repository, written without an AI, in the structure of a principal
engineer's review (executive summary, system map, findings by severity, what works, testing and release gaps, open
questions, review limits). Every finding cites file:line evidence. `--for-ai` adds an evidence pack: the findings plus
the riskiest code, so an AI can make the judgement calls by reading a few thousand tokens instead of the whole repo.
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .brief import View
from .checks import scan_repo, scan_sources, test_reach
from .paths import is_script, is_test
from .plan import make_plan

SEV = ["Critical", "High", "Medium", "Low"]
POINTS = {"Critical": 30, "High": 10, "Medium": 3, "Low": 1}
CAPS = {"Medium": 24, "Low": 6}  # many small issues shouldn't outweigh one serious one
TS_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
OTHER_CODE = {
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".cs": "C#",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".cpp": "C++",
    ".c": "C",
    ".php": "PHP",
    ".scala": "Scala",
    ".dart": "Dart",
    ".sql": "SQL",
    ".tf": "Terraform",
    ".sh": "shell",
}


@dataclass
class Finding:
    title: str
    severity: str
    area: str
    evidence: list[str]
    impact: str
    fix: str
    effort: str
    more: int = 0
    data: dict = field(default_factory=dict)


def _ev(items, n: int = 6) -> tuple[list[str], int]:
    shown = [f"`{e.at()}` {e.text}" if hasattr(e, "at") else e for e in items[:n]]
    return shown, max(0, len(items) - n)


CLIENT_APPS = {"React", "React Native", "Expo", "Vue", "Svelte"}  # a UI process serves one user


def _n(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _effort(count: int, files: int) -> str:
    return "S" if count <= 3 and files <= 2 else "M" if count <= 15 and files <= 8 else "L"


class Review:
    def __init__(self, g: dict, root: Path):
        self.g, self.root, self.v = g, root, View(g)
        self.repo = scan_repo(root)
        self.scan = scan_sources(root, [f["id"] for f in g["files"]])
        self.reached = test_reach(self.v)
        self.tasks = make_plan(g)
        self.findings: list[Finding] = []
        self.by_kind = defaultdict(list)
        for f in g["flags"]:
            self.by_kind[f["kind"]].append(f)
        self.code_fns = [f for f in g["functions"] if f["kind"] != "module" and not is_test(f["file"])]
        self._strengths: list[str] | None = None

    def add(self, *a, **k) -> None:
        self.findings.append(Finding(*a, **k))

    def where(self, flag: dict) -> str:
        fn = self.v.fn.get(flag["target"])
        return (
            f"`{fn['file']}:{flag.get('line') or fn['line']}` {fn['qualname'] if fn['kind'] != 'module' else ''}".rstrip()
            if fn
            else f"`{flag['target']}`"
        )

    # ---- findings ----------------------------------------------------------------------------------------------
    def security(self) -> None:
        s = self.scan
        if s["secret"].hits:
            ev, more = _ev(s["secret"].hits)
            self.add(
                "Credentials committed in source",
                "Critical",
                "Security",
                ev,
                "Anyone with read access to the repository (or its history, forks and CI logs) can use them.",
                "Rotate each credential now, remove it from the code (and history), and load it from the environment "
                "or a secret store at runtime.",
                "S",
                more,
            )
        tracked = self._tracked(self.repo["env_files"])
        if tracked:
            self.add(
                "Environment files committed",
                "High",
                "Security",
                [f"`{f}`" for f in tracked],
                "Environment files usually hold secrets and per-machine settings.",
                "Remove them from git, add `.env*` to .gitignore (keep a `.env.example`), and rotate anything in them.",
                "S",
            )
        if s["sql_built"].hits:
            ev = [
                f"`{e.at()}` {e.text}"
                + (
                    f"  (interpolates: {', '.join(s['sql_built'].data.get(e.at(), []))})"
                    if s["sql_built"].data.get(e.at())
                    else ""
                )
                for e in s["sql_built"].hits[:6]
            ]
            self.add(
                "SQL assembled from strings",
                "Medium",
                "Security",
                ev,
                "If any interpolated value can come from a user, a file or the network, this is SQL injection. "
                "Constants and whitelisted identifiers are safe, but nothing enforces that they stay so.",
                "Pass values as bound parameters (`?` / `%s`); for table or column names, check them against a fixed "
                "list right where the SQL is built.",
                _effort(len(s["sql_built"].hits), len({e.file for e in s["sql_built"].hits})),
                max(0, len(s["sql_built"].hits) - 6),
            )
        for key, title, sev, impact, fix in [
            (
                "eval",
                "Dynamic code execution (eval / exec / pickle / unsafe YAML)",
                "High",
                "Running text as code: if that text can be influenced from outside, it's remote code execution.",
                "Replace with explicit parsing (JSON, a lookup table); never unpickle or yaml.load untrusted data "
                "(use SafeLoader).",
            ),
            (
                "shell",
                "Shell commands built at runtime",
                "High",
                "A shell interprets its input: values with spaces, quotes or `;` change the command.",
                "Pass arguments as a list without a shell (subprocess.run([...]), execFile/spawn), never a formatted string.",
            ),
            (
                "tls_off",
                "TLS certificate checks turned off",
                "High",
                "Connections can be intercepted and altered without any error.",
                "Remove the override; if a private CA is needed, configure it as a trusted root instead.",
            ),
            (
                "raw_html",
                "Raw HTML injected into pages",
                "Medium",
                "HTML from data that isn't fully trusted is cross-site scripting.",
                "Render as text, or sanitize with a maintained library (e.g. DOMPurify) right before inserting.",
            ),
            (
                "plain_http",
                "Plain-HTTP URLs in code",
                "Low",
                "Traffic to these hosts can be read and changed in transit.",
                "Use https:// where the host supports it.",
            ),
        ]:
            hits = s[key].hits
            if hits:
                ev, more = _ev(hits)
                self.add(title, sev, "Security", ev, impact, fix, _effort(len(hits), len({e.file for e in hits})), more)

    def reliability(self) -> None:
        s = self.scan
        sw = s["swallowed"].hits
        if len(sw) >= 3:
            ev, more = _ev(sw)
            self.add(
                f"{_n(len(sw), 'error')} silently swallowed",
                "High" if len(sw) >= 10 else "Medium",
                "Reliability",
                ev,
                "Failures leave no trace: users see something half-done, and nobody can tell why.",
                "Route every caught error through one helper that records it (a log, a local error file, crash "
                "reporting) and only then recovers; keep empty catches for genuinely expected cases, with a comment.",
                _effort(len(sw), len({e.file for e in sw})),
                more,
            )
        fw = self.repo["frameworks"]
        if fw & {"React", "React Native", "Expo", "Next.js"} and not s["error_boundary"].hits:
            self.add(
                "No error boundary around the UI",
                "Medium",
                "Reliability",
                [f"React-based ({', '.join(sorted(fw))}); no ErrorBoundary / componentDidCatch found in the source"],
                "One rendering error blanks the whole app with nothing recorded.",
                "Add an error boundary at the root (and around risky screens) that shows a recovery screen and records "
                "the error.",
                "S",
            )
        nt = [e for e in s["fetch_no_timeout"].hits if not is_script(e.file)]
        if nt:
            s["fetch_no_timeout"].hits = nt
            ev, more = _ev(nt)
            self.add(
                "Network calls without a timeout",
                "Medium",
                "Reliability",
                ev,
                "A slow or hanging server stalls the caller indefinitely.",
                "Give every request a deadline (AbortSignal.timeout(ms) / requests' timeout=) and handle it.",
                _effort(len(s["fetch_no_timeout"].hits), len({e.file for e in s["fetch_no_timeout"].hits})),
                more,
            )
        ms = s["module_state"].hits
        if fw & CLIENT_APPS:  # one user per process: module singletons are a normal design; exported mutable bindings aren't
            ms = s["module_state"].hits = [e for e in ms if e.text.startswith("export")]
        if len(ms) >= 3:
            ev, more = _ev(ms)
            self.add(
                f"Module-level mutable state ({len(ms)} places)",
                "Medium" if len(ms) >= 6 else "Low",
                "Reliability",
                ev,
                "State held in module variables is shared by everything that imports it, survives no reload, and "
                "makes order of calls matter in ways tests rarely cover.",
                "Keep it in an owner with a clear lifecycle (a store, a context, a class instance, the database) and "
                "pass it explicitly.",
                _effort(len(ms), len({e.file for e in ms})),
                more,
            )
        reads = [f for f in self.by_kind["io_in_loop"] if f["severity"] == "warn" and not self._script(f)]
        if reads:
            self.add(
                f"Queries or requests inside loops (N+1) in {_n(len(reads), 'place')}",
                "Medium",
                "Performance",
                [f"{self.where(f)}: {f['message'].split(':')[0]}" for f in reads[:6]],
                "Cost grows with the data: one round trip per item instead of one for all.",
                "Load everything a loop needs with one batched query (WHERE id IN (…), a JOIN) or request before the "
                "loop (`codefactory plan` lists each with steps).",
                _effort(len(reads), len(reads)),
                max(0, len(reads) - 6),
            )
        writes = [
            f
            for f in self.by_kind["io_in_loop"]
            if f["severity"] == "info" and not self._script(f) and not is_test(self._file(f))
        ]
        if writes:
            self.add(
                f"Writes inside loops in {_n(len(writes), 'place')}",
                "Low",
                "Performance",
                [self.where(f) for f in writes[:6]],
                "Fine inside one transaction for small loops; slow for large ones.",
                "Confirm each runs inside one transaction; batch the ones that can grow.",
                "M",
                max(0, len(writes) - 6),
            )

    def architecture(self) -> None:
        cycles = {frozenset([f["target"], *f.get("related", [])]) for f in self.by_kind["cycle"]}
        if cycles:
            biggest = max(len(c) for c in cycles)
            self.add(
                f"Import loops ({len(cycles)})",
                "High" if biggest >= 3 else "Medium",
                "Architecture",
                [" → ".join(sorted(c)) for c in list(cycles)[:4]],
                "Files in a loop load in a fragile order and can't be understood, tested or moved alone.",
                "Move what both sides need into a module that imports neither, or pass the dependency in.",
                _effort(len(cycles), biggest),
            )
        lv = self.by_kind["layer_violation"]
        if lv:
            self.add(
                f"Layer rule violations ({len(lv)})",
                "High",
                "Architecture",
                [f["message"] for f in lv[:6]],
                "The architecture factory.toml describes isn't the one the code has.",
                "Move the code into an allowed layer or invert the dependency.",
                _effort(len(lv), len(lv)),
                max(0, len(lv) - 6),
            )
        rank = {name: i for i, name in enumerate(self.g["layers"])}
        layer_of = {f["id"]: f["layer"] for f in self.g["files"]}
        back = Counter()
        for e in self.g["edges"]:
            if e["kind"] == "import":
                a, b = layer_of.get(e["src"]), layer_of.get(e["dst"])
                if a and b and "tests" not in (a, b) and rank.get(b, 0) < rank.get(a, 0):
                    back[(a, b)] += 1
        if back:
            self.add(
                "Dependencies against the layer order",
                "Low",
                "Architecture",
                [f"{a} imports {b} ({n} files)" for (a, b), n in back.most_common(5)],
                "A lower layer reaching up into a higher one blurs who depends on whom.",
                "Check each is intended; if not, move the shared piece down or pass it in. Make the rule explicit in "
                "factory.toml ([rules] forbid).",
                "S",
            )
        copies = [t for t in self.tasks if self._copied(t)]
        if copies:
            saved = sum(int(m.group(1)) for t in copies if (m := re.search(r"~(\d+) lines", t["title"])))
            self.add(
                f"Copied logic in {_n(len(copies), 'group')} (~{saved} lines)",
                "Medium" if len(copies) >= 3 else "Low",
                "Maintainability",
                [f"{t['title']}: " + ", ".join(f"`{w['file']}:{w['line']}`" for w in t["where"][:3]) for t in copies[:6]],
                "A fix applied to one copy silently misses the others.",
                "Merge each group into one function in the lowest layer its callers share (`codefactory plan` has "
                "per-group steps).",
                _effort(len(copies), len(copies) * 2),
                max(0, len(copies) - 6),
            )
        # the hardest to follow first: branches (decisions) weigh more than length, so a long but flat table of
        # options or a big layout ranks below a shorter function full of conditions
        long = sorted((f for f in self.code_fns if f["loc"] > 80), key=lambda f: -(f.get("branches", 0) * 4 + f["loc"] / 10))
        if long:
            self.add(
                f"Very long functions ({_n(len(long), 'function')} over 80 lines)",
                "Low",
                "Maintainability",
                [
                    f"`{f['file']}:{f['line']}` {f['qualname']}: {f['loc']} lines"
                    + (f", {f['branches']} decision points" if f.get("branches") else "")
                    for f in long[:6]
                ],
                "Hard to read, test and change safely; often several responsibilities in one place.",
                "Extract the parts that have names of their own.",
                "M",
                max(0, len(long) - 6),
            )
        unused = [f for f in self.by_kind["unused"] if not is_test(self._file(f))]
        if unused:
            self.add(
                f"Unused code ({_n(len(unused), 'function')})",
                "Low",
                "Maintainability",
                [self.where(f) for f in unused[:6]],
                "Dead code costs reading time and keeps dependencies alive.",
                "Verify (frameworks may call by name), then delete.",
                "S",
                max(0, len(unused) - 6),
            )
        scans = [f for f in self.by_kind["quadratic_scan"] if not self._script(f)]
        if len(scans) >= 5:
            self.add(
                f"Array searches inside loops ({len(scans)})",
                "Low",
                "Performance",
                [self.where(f) for f in scans[:5]],
                "O(n²): invisible on small lists, slow on long ones.",
                "Where a list can grow, build a Map/Set once before the loop.",
                "M",
                max(0, len(scans) - 5),
            )

    def testing(self) -> None:
        tests = [f for f in self.g["files"] if is_test(f["id"])]
        code = [f for f in self.code_fns]
        if not tests:
            self.add(
                "No automated tests",
                "High",
                "Testing",
                ["no test files found (tests/, __tests__/, *.test.*, test_*.py)"],
                "Every change is verified by hand, if at all; refactoring is risky.",
                "Start with tests for the most-used and data-writing functions listed in this report.",
                "L",
            )
            return
        pct = round(100 * sum(1 for f in code if f["id"] in self.reached) / max(1, len(code)))
        self.test_pct = pct
        callers = {f["id"]: {self.v.fn[e["src"]]["file"] for e in self.v.callers[f["id"]] if e["src"] in self.v.fn} for f in code}
        risky = [
            f
            for f in code
            if f["id"] not in self.reached and (f.get("io") or len(callers[f["id"]]) >= 8) and not is_script(f["file"])
        ]
        risky.sort(key=lambda f: (-bool(f.get("io")), -len(callers[f["id"]])))
        if risky:
            self.add(
                f"Important code no test reaches ({_n(len(risky), 'function')})",
                "Medium",
                "Testing",
                [
                    f"`{f['file']}:{f['line']}` {f['qualname']}"
                    + (f": does I/O ({', '.join(f['io'][:2])})" if f.get("io") else "")
                    + (f", called from {len(callers[f['id']])} files" if len(callers[f["id"]]) >= 2 else "")
                    for f in risky[:8]
                ],
                f"Tests reach {pct}% of functions, but not these: code that talks to storage or the network, or that "
                "much of the app depends on.",
                "Add tests that call these (against a real or in-memory store), starting with the ones that write data.",
                _effort(len(risky), len({f["file"] for f in risky})),
                max(0, len(risky) - 8),
            )
        if self.repo["ci"] and "tests" not in self.repo["ci_steps"]:
            self.add(
                "CI doesn't run the tests",
                "Medium",
                "Delivery",
                [f"`{c}`" for c in self.repo["ci"]],
                "Tests that don't run on every change stop being trusted.",
                "Add the test command to CI.",
                "S",
            )

    def delivery(self) -> None:
        r = self.repo
        if not r["ci"]:
            self.add(
                "No continuous integration",
                "High",
                "Delivery",
                ["no CI configuration found (" + ", ".join(c for c in CI_HINT) + ")"],
                "Nothing checks a change before it ships.",
                "Add a CI workflow that installs from the lockfile and runs "
                "typecheck, lint and tests on every pull request and push to the main branch.",
                "S",
            )
        elif not r["ci_on_push"]:
            self.add(
                "CI doesn't run on pushes to the main branch",
                "Low",
                "Delivery",
                [f"`{c}`" for c in r["ci"]],
                "Direct pushes skip every check.",
                "Also trigger on push to the main branch.",
                "S",
            )
        if r["manifests"] and not r["locks"] and any(m == "package.json" for m in r["manifests"]):
            self.add(
                "No lockfile",
                "High",
                "Dependencies",
                [", ".join(r["manifests"])],
                "Every install can resolve different versions: builds aren't reproducible.",
                "Commit the lockfile your package manager writes, and install with it in CI (npm ci / pnpm i --frozen-lockfile).",
                "S",
            )
        if r["floating"]:
            self.add(
                "Dependencies on moving targets",
                "Medium",
                "Dependencies",
                r["floating"][:8],
                "`*`, `latest` or a git branch changes under you without a code change.",
                "Pin versions (or commits).",
                "S",
            )
        if r["unpinned_py"]:
            self.add(
                "Unpinned Python requirements",
                "Medium",
                "Dependencies",
                r["unpinned_py"][:8],
                "Installs drift over time.",
                "Pin with == (or use a lock tool: uv, pip-tools, poetry).",
                "S",
            )
        if r["manifests"] and not r["runtime_pin"]:
            self.add(
                "Runtime version not pinned",
                "Low",
                "Delivery",
                ["no engines / .nvmrc / .python-version / requires-python"],
                "Developers, CI and production can run different Node/Python versions.",
                "Declare the version (package.json engines + .nvmrc, or requires-python + .python-version).",
                "S",
            )
        if not r["readme"]:
            self.add(
                "No README",
                "Medium",
                "Docs",
                ["no README at the repository root"],
                "A new engineer can't run or change it from the repo alone.",
                "Add one: what it is, how to run, test and ship.",
                "S",
            )
        elif not r.get("readme_run"):
            self.add(
                "README doesn't say how to run it",
                "Low",
                "Docs",
                [f"`{r['readme']}`"],
                "Setup knowledge lives in people's heads.",
                "Add install, run and test commands.",
                "S",
            )

    # ---- helpers -----------------------------------------------------------------------------------------------
    def _file(self, flag: dict) -> str:
        fn = self.v.fn.get(flag["target"])
        return fn["file"] if fn else flag["target"]

    def _script(self, flag: dict) -> bool:
        return is_script(self._file(flag))

    def _tracked(self, names: list[str]) -> list[str]:
        if not names:
            return []
        try:
            out = subprocess.run(["git", "ls-files", *names], cwd=self.root, capture_output=True, text=True, timeout=20)
            return out.stdout.split() if out.returncode == 0 else names
        except (OSError, subprocess.SubprocessError):
            return names

    # ---- report ------------------------------------------------------------------------------------------------
    def run(self) -> None:
        self.test_pct = None
        self.security()
        self.reliability()
        self.architecture()
        self.testing()
        self.delivery()
        self.findings.sort(key=lambda f: (SEV.index(f.severity), -len(f.evidence) - f.more))

    def health(self) -> tuple[str, list[Finding]]:
        score = 100
        for sev in SEV:
            pts = sum(POINTS[sev] for f in self.findings if f.severity == sev)
            score -= min(CAPS.get(sev, pts), pts)
        grade = "Strong" if score >= 85 else "Adequate" if score >= 65 else "Fragile" if score >= 40 else "At risk"
        return grade, [f for f in self.findings if f.severity in ("Critical", "High")]

    def stores(self) -> list[str]:
        sinks = " ".join(" ".join(f.get("io", [])) for f in self.g["functions"])
        deps = self.repo["deps"]
        out = []
        if "expo-sqlite" in deps:
            out.append("SQLite (expo-sqlite)")
        elif re.search(r"sqlite3|getAllAsync|runAsync", sinks):
            out.append("SQLite")
        for pat, name in (
            (r"psycopg|asyncpg|pg\b", "PostgreSQL"),
            (r"duckdb", "DuckDB"),
            (r"pyarrow|fastparquet|\.parquet|to_parquet|read_parquet", "Parquet files"),
            (r"sqlalchemy", "SQLAlchemy"),
            (r"mysql|pymysql", "MySQL"),
            (r"elasticsearch|opensearch", "Elasticsearch"),
            (r"boto3|@aws-sdk/client-s3", "Amazon S3 / AWS"),
            (r"pymongo|mongoose", "MongoDB"),
            (r"redis", "Redis"),
            (r"AsyncStorage", "AsyncStorage"),
            (r"SecureStore|getItemAsync", "secure key store"),
            (r"prisma", "Prisma ORM"),
            (r"objects\.", "Django ORM"),
            (r"readFile|writeFile|read_text|write_text|AsStringAsync", "local files"),
        ):
            if re.search(pat, sinks) or any(re.search(pat, d) for d in deps):
                out.append(name)
        return out

    def markdown(self, for_ai: bool = False) -> str:
        g, r = self.g, self.repo
        name = g["root"].replace("\\", "/").rstrip("/").split("/")[-1]
        code_files = [f for f in g["files"] if not is_test(f["id"])]
        lines_total = sum(f["loc"] for f in code_files)
        entry = [f for f in code_files if not self.v.importers.get(f["id"])]
        layers = [(name, sum(1 for f in code_files if f["layer"] == name)) for name in g["layers"] if name != "tests"]
        hosts = self.scan["hosts"].data
        grade, drivers = self.health()
        frameworks = r["frameworks"]
        fw = (
            "Expo / React Native"
            if "Expo" in frameworks
            else "React Native"
            if "React Native" in frameworks
            else ", ".join(sorted(frameworks)) or g["language"]
        )
        article = "an" if fw[:1].lower() in "aeiou" else "a"
        out = [
            f"# Technical review: {name}",
            "",
            f"_Generated by codefactory {self._version()} from static analysis (no code was run, no AI). Every finding "
            "cites file:line; verify before acting on anything marked as a hint._",
            "",
            "## 1. Executive summary",
            "",
            f"- **What it is:** {article} {fw} codebase ({g['language']}): {len(code_files)} source files, "
            f"{lines_total:,} lines, in "
            f"{_n(len(layers), 'layer')} ({', '.join(f'{name} {n}' for name, n in sorted(layers, key=lambda x: -x[1])[:5])}).",
            f"- **Entry points:** {len(entry)} files nothing imports (screens, routes, scripts, configs).",
            f"- **Data:** {', '.join(self.stores()) or 'no data store detected'}.",
            f"- **External services:** {', '.join(sorted(hosts)[:8]) or 'none found in the code'}"
            + (f" (+{len(hosts) - 8} more)" if len(hosts) > 8 else "")
            + ".",
            f"- **Tests:** {len([f for f in g['files'] if is_test(f['id'])])} test files"
            + (f", reaching {self.test_pct}% of functions" if self.test_pct is not None else "")
            + ".",
            f"- **CI:** {', '.join(r['ci']) if r['ci'] else 'none'}"
            + (f" (runs {', '.join(sorted(r['ci_steps']))})" if r["ci_steps"] else "")
            + ".",
            "",
            f"**Overall health: {grade}.** " + self._justify(grade, drivers),
            "",
            "**Top 5 actions, by leverage**",
            "",
            "| # | Action | Effort | Why |",
            "|---|---|---|---|",
        ]
        for i, f in enumerate(self.findings[:5], 1):
            action = re.split(r"[;:]\s|\.\s", f.fix)[0].rstrip(".")
            why = re.split(r"[;:]\s|\.\s", f.impact)[0].rstrip(".")
            out.append(f"| {i} | **{f.title}**: {action} | {f.effort} | {why} |")
        out += ["", "## 2. System map", "", "| Layer | Files | Lines | Calls into |", "|---|---|---|---|"]
        layer_of = {f["id"]: f["layer"] for f in g["files"]}
        fn_file = {f["id"]: f["file"] for f in g["functions"]}
        deps = defaultdict(Counter)
        for e in g["edges"]:
            if e["kind"] == "call":
                a, b = layer_of.get(fn_file.get(e["src"])), layer_of.get(fn_file.get(e["dst"]))
                if a and b and a != b:
                    deps[a][b] += e["count"]
        for layer in g["layers"]:
            members = [f for f in g["files"] if f["layer"] == layer]
            out.append(
                f"| {layer} | {len(members)} | {sum(f['loc'] for f in members):,} | "
                f"{', '.join(f'{k} ({n})' for k, n in deps[layer].most_common(4)) or '-'} |"
            )
        out += [
            "",
            "**Trust boundaries:** "
            + "; ".join(
                filter(
                    None,
                    [
                        f"network ({_n(len(hosts), 'host')}: {', '.join(sorted(hosts)[:5])})" if hosts else "",
                        "the data store" if self.stores() else "",
                        "files the user opens or imports"
                        if re.search(
                            r"DocumentPicker|open\(|readFile|FileReader",
                            " ".join(" ".join(f.get("io", [])) for f in g["functions"]),
                        )
                        else "",
                    ],
                )
            )
            or "none detected.",
            "",
        ]
        hub = sorted(
            self.code_fns,
            key=lambda f: -len({self.v.fn[e["src"]]["file"] for e in self.v.callers[f["id"]] if e["src"] in self.v.fn}),
        )[:5]
        out += ["**Most depended-on code:** " + ", ".join(f"`{f['file']}:{f['line']}` {f['qualname']}" for f in hub), ""]
        out += ["## 3. Findings", ""]
        for sev in SEV:
            group = [f for f in self.findings if f.severity == sev]
            out += [f"### {sev}", ""]
            if not group:
                out += ["None found.", ""]
                continue
            for f in group:
                out += [f"**{f.title}** · {f.area} · effort {f.effort}", "", "- Evidence:"] + [f"  - {e}" for e in f.evidence]
                if f.more:
                    out.append(f"  - … {f.more} more")
                out += [f"- Impact: {f.impact}", f"- Fix: {f.fix}", ""]
        out += ["## 4. What is working", ""] + [f"- {w}" for w in self.strengths()] + [""]
        out += ["## 5. Testing and release gaps", ""]
        gaps = [f for f in self.findings if f.area in ("Testing", "Delivery", "Dependencies")]
        out += [f"- **{f.title}.** {f.fix}" for f in gaps] or ["- None found by these checks."]
        out += ["", "## 6. Open questions", ""] + [f"- {q}" for q in self.questions()]
        out += ["", "## Review limits", ""] + [f"- {x}" for x in self.limits()]
        if for_ai:
            out += ["", self.evidence_pack()]
        return "\n".join(out) + "\n"

    def _justify(self, grade: str, drivers: list[Finding]) -> str:
        crit = [f.title for f in drivers]
        good = len(self.strengths())
        if not crit:
            return f"No critical or high-severity findings; {good} strengths below. The medium items are real debt, not blockers."
        return (
            f"Driven by {_n(len(crit), 'critical/high finding')}: {'; '.join(crit[:3])}"
            + (" …" if len(crit) > 3 else "")
            + f". {good} things are working well (section 4)."
        )

    def strengths(self) -> list[str]:
        if self._strengths is None:
            self._strengths = self._find_strengths()
        return self._strengths

    def _find_strengths(self) -> list[str]:
        r, s, out = self.repo, self.scan, []
        if not self.by_kind["cycle"]:
            out.append("No import loops: every module can be loaded and understood on its own.")
        if not s["secret"].hits:
            out.append("No credentials found in the source.")
        if not s["sql_built"].hits and re.search(
            r"Async|execute", " ".join(" ".join(f.get("io", [])) for f in self.g["functions"])
        ):
            out.append("SQL is parameterized: no queries built from strings were found.")
        if not (s["eval"].hits or s["shell"].hits or s["tls_off"].hits):
            out.append("No eval, shell-string execution or disabled TLS checks.")
        if self.test_pct is not None and self.test_pct >= 50:
            out.append(f"Tests reach {self.test_pct}% of functions.")
        if r["ci"] and {"tests"} <= r["ci_steps"]:
            out.append(f"CI runs {', '.join(sorted(r['ci_steps']))}.")
        if r["locks"]:
            out.append(f"Reproducible installs: {', '.join(r['locks'])} committed.")
        if r["runtime_pin"]:
            out.append(f"Runtime version pinned ({', '.join(r['runtime_pin'])}).")
        dup_targets = {x["target"] for x in self.by_kind["duplicate"] + self.by_kind["similar"]}
        copied = sum(f["loc"] for f in self.code_fns if f["id"] in dup_targets)
        total = max(1, sum(f["loc"] for f in self.code_fns))
        if copied / total < 0.02:
            out.append(f"Little copied code ({round(100 * copied / total, 1)}% of function lines).")
        if len(s["swallowed"].hits) < 3:
            out.append("Errors are rarely swallowed silently.")
        if r["readme"] and r.get("readme_run"):
            out.append(f"{r['readme']} explains how to run it.")
        return out

    def questions(self) -> list[str]:
        q = [
            "What scale is this built for (users, data volume, requests per second), and what are the uptime or latency targets?",
            "Which data is sensitive (personal, payment, health), and which compliance rules apply?",
        ]
        if self.scan["hosts"].data:
            q.append(
                f"What should happen when {', '.join(sorted(self.scan['hosts'].data)[:3])} "
                f"{'is' if len(self.scan['hosts'].data) == 1 else 'are'} slow or down?"
            )
        if self.stores():
            q.append(f"How is {self.stores()[0]} backed up and restored, and has a restore been tested?")
        if self.repo["deploy"]:
            q.append(
                f"Who can run {', '.join(f'`{d}`' for d in self.repo['deploy'][:3])}, what checks run first, "
                "and how is a bad release rolled back?"
            )
        if not self.repo["ci"]:
            q.append("How is the code built and released today?")
        q.append(
            "Which findings above are known and accepted? Silence them (`codefactory: ignore <kind> — why`) "
            "so the next review shows only what's new."
        )
        return q

    @staticmethod
    def _copied(task: dict) -> bool:
        """Copies worth merging: identical or nearly so (≥85%), and not a test restating code it checks (an oracle).
        Below 85% the pair is usually a deliberate variant (unticking a set vs deleting it, "45 sec" vs "45s")."""
        if task["kind"] not in ("duplicate", "similar") or any(is_test(w["file"]) for w in task["where"]):
            return False
        m = re.search(r"(\d+)% similar", task["title"])
        return not m or int(m.group(1)) >= 85

    def limits(self) -> list[str]:
        analyzed = Counter(Path(f["id"]).suffix for f in self.g["files"])
        seen = {f["id"] for f in self.g["files"]}
        other = Counter()
        skip = {".git", "node_modules", ".venv", "venv", "dist", "build", ".codefactory", "__pycache__", ".expo", "Pods"}
        for p in self.root.rglob("*"):
            rel = p.relative_to(self.root)
            if p.is_file() and p.suffix in OTHER_CODE and not (set(rel.parts) & skip) and rel.as_posix() not in seen:
                other[OTHER_CODE[p.suffix]] += 1
        out = [
            f"Analyzed {len(self.g['files'])} files ({', '.join(f'{n} {ext}' for ext, n in analyzed.most_common(6))}) "
            "statically: call graph, imports, structure and text patterns. Nothing was executed."
        ]
        if ok := self.scan["swallowed_ok"].hits:
            kinds = Counter(e.text for e in ok)
            why = {"explained": "a comment says why", "cleanup": "best-effort cleanup", "fallback": "a fallback value"}
            out.append(
                f"{_n(len(ok), 'empty catch block')} treated as deliberate, not reported ("
                + ", ".join(f"{n}: {why[k]}" for k, n in kinds.most_common())
                + ")."
            )
        if other:
            from .analyzers.generic import available

            why = (
                "generated, too large or not parseable"
                if available()
                else 'install the language pack to include them: pip install "codefactory[languages]"'
            )
            out.append(f"Not analyzed ({why}): " + ", ".join(f"{n} {lang}" for lang, n in other.most_common()) + ".")
        if any(Path(f["id"]).suffix not in (".py", *TS_EXT) for f in self.g["files"]):
            out.append(
                "Languages other than Python and TypeScript/JavaScript are analyzed by tree-sitter, matching calls by "
                "name: their unused-code and call findings are hints."
            )
        out += [
            "Calls through dynamic dispatch (callbacks in variables, getattr, untyped objects) can be missing, so "
            "'unused' and 'no test reaches it' are hints.",
            "Not checked: runtime behaviour, concurrency and transaction semantics, business logic, dependency "
            "vulnerabilities (no network lookups), infrastructure-as-code, git history.",
            "Severity is set by rules, not by knowing the product: re-rank with what you know about users and data.",
        ]
        return out

    def evidence_pack(self) -> str:
        """For an AI reviewer: what to confirm, and the riskiest code to read, in a few thousand tokens."""
        risky = []
        wipe = re.compile(
            r"deleteDatabase|DROP TABLE|\brmSync\b|\bunlink(Sync)?\(|\brmdir|shutil\.rmtree|os\.remove\(|"
            r"\bdeleteAsync\(|\b\w*(?:file|File|dir|Dir)\w*(?:\(\))?\.delete\(|\bTRUNCATE\b"
        )  # databases or files
        rows = re.compile(r"DELETE FROM|\.destroy\(|objects\.\w+\(.*\)\.delete\(|session\.delete\(", re.I)
        for f in self.code_fns:
            if f["loc"] < 8 or f["loc"] > 160 or is_script(f["file"]):
                continue  # one-liners have nowhere to hide a failure mode; huge ones won't fit
            try:
                lines = (
                    (self.root / f["file"]).read_text(encoding="utf-8", errors="replace").splitlines()[f["line"] - 1 : f["end"]]
                )
            except OSError:
                continue
            # code only: words in comments ("unlinks", "truncate") aren't operations
            body = "\n".join(re.sub(r"(^|\s)(//|#).*$", "", ln) for ln in lines)
            body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
            score, reasons = 0, []
            if wipe.search(body):
                score += 6
                reasons.append("deletes a database or files")
            elif rows.search(body):
                score += 2
                reasons.append("deletes rows")
            swallowed = len(
                re.findall(
                    r"catch\s*(?:\([^)]*\))?\s*\{\s*(?://[^\n]*)?\s*\}|\.catch\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)|except[^:]*:\s*pass",
                    body,
                )
            )
            if swallowed:
                score += min(6, 2 + swallowed)
                reasons.append(f"swallows {_n(swallowed, 'error')}")
            if f.get("io"):
                score += 1
                reasons.append("does I/O")
            if f["id"] not in self.reached:
                score += 2
                reasons.append("no test reaches it")
            if re.search(r"withTransaction|BEGIN|transaction|lock|mutex|Promise\.all", body):
                score += 1
                reasons.append("transactions or concurrency")
            branches = len(re.findall(r"\bif\b|\?\s|\bcatch\b|\bexcept\b|\|\||&&", body))
            score += min(4, branches // 4)
            if branches >= 8:
                reasons.append(f"{branches} branches")
            if score >= 7:
                risky.append((score, f, reasons, lines))
        risky.sort(key=lambda x: -x[0])
        out = [
            "---",
            "",
            "## Evidence pack for an AI reviewer",
            "",
            "You are finishing this review. Everything above was produced by static rules. Your job:",
            "1. For each Critical/High/Medium finding: confirm it from the cited lines (open only those), or reject it "
            "with the reason. Adjust severity using what the code and README say about the product.",
            "2. Read the risky functions below. For each, decide whether there's a real failure mode (data loss, a "
            "user locked out, a race between writers, a misleading error) and add findings for the real ones.",
            "3. Rewrite sections 1 and 3 with your conclusions. Keep file:line evidence. Don't read other files "
            "unless a finding needs one more caller (`codefactory context <name>` lists them).",
            "",
            "### Riskiest code (deletes data, does I/O, untested, swallows errors)",
            "",
        ]
        for _score, f, reasons, lines in risky[:6]:
            ext = Path(f["file"]).suffix.lstrip(".") or "text"
            out += (
                [f"**`{f['file']}:{f['line']}` {f['qualname']}** ({', '.join(reasons)})", "", f"```{ext}"]
                + lines[:60]
                + ["```", ""]
            )
        if not risky:
            out.append("No function combines deleting data, I/O and missing tests.")
        return "\n".join(out)

    @staticmethod
    def _version() -> str:
        from . import __version__

        return __version__


CI_HINT = [".github/workflows", ".gitlab-ci.yml", ".circleci", "Jenkinsfile"]


def review_markdown(g: dict, root: Path, for_ai: bool = False) -> str:
    r = Review(g, root)
    r.run()
    return r.markdown(for_ai)
