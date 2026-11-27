"""`codefactory review`: a technical review of a repository, written without an AI, in the structure of a principal
engineer's review (executive summary, system map, findings by severity, what works, testing and release gaps, open
questions, review limits). Every finding cites file:line evidence. `--for-ai` adds an evidence pack: the findings plus
the riskiest code, so an AI can make the judgement calls by reading a few thousand tokens instead of the whole repo.
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from . import hotspots, rerank
from .apple import scan as apple_scan
from .audit import current_secrets
from .audit import scan as audit_scan
from .brief import View
from .checks import CI_NAMES, scan_repo, scan_sources, source_files, test_reach
from .config import load_config
from .coverage import measured
from .infra import scan as infra_scan
from .paths import deliberate_copies, is_doc_sample, is_example_code, is_script, is_test, walk
from .plan import make_plan
from .privacy import scan as privacy_scan
from .profile import detect as detect_profile
from .profile import markdown as profile_markdown
from .security import SINK_KINDS, function_at, surface, writes

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


# endpoints that have to work without being signed in: signing in, signing up, resetting a password, confirming an email
SIGN_IN = re.compile(r"log_?in|log_?out|sign_?in|sign_?up|signup|regist(?:er|ration)|password|reset|forgot|confirm|"
                     r"(?<![a-z])setup(?![a-z])|health|webhook|\bsessions?#(?:create|new)|"  # first-run setup; a webhook
                     # checks its own signature; Devise's sign-in
                     r"verify|webauthn|totp|two_?factor|2fa|oauth|callback|magic_?link|unsubscribe|check_token|login_link",
                     re.I)  # fmt: skip
CLIENT_APPS = {"React", "React Native", "Expo", "Vue", "Svelte"}  # a UI process serves one user


def _n(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _effort(count: int, files: int) -> str:
    return "S" if count <= 3 and files <= 2 else "M" if count <= 15 and files <= 8 else "L"


SEVERITIES = ["Low", "Medium", "High", "Critical"]


def _lower(sev: str) -> str:
    return SEVERITIES[max(0, SEVERITIES.index(sev) - 1)]


def _sample_severity(sev: str, hits) -> str:
    """A credential only in documentation or example code (a tutorial's sample SECRET_KEY, a docs site's public search
    key) is there to be copied, not used: Low, so it's still checked that nothing real reuses it."""

    def sample(e) -> bool:  # a docs example, or a test's fixture key (celery's RSA keys)
        return is_doc_sample(e.file) or (is_test(e.file) and "PRIVATE KEY" in e.text)

    if hits and all(sample(e) for e in hits):
        return "Low"
    if hits and all(is_test(e.file) for e in hits) and SEVERITIES.index(sev) > SEVERITIES.index("Medium"):
        return "Medium"  # a vendor-format token only in tests (n8n's redaction tests): likely a fixture, so confirm
    return sev


class Review:
    def __init__(self, g: dict, root: Path, online: bool = False, full: bool = False):
        self.full = full  # every location of every finding (the audit export), not the first few (the report)
        self.g, self.root, self.v = g, root, View(g)
        self.repo = scan_repo(root)
        pool = ThreadPoolExecutor(max_workers=1)  # git log runs while the checks below read files
        try:
            history = pool.submit(hotspots.analyze, root, g)
            sources = source_files(root, g)  # parsed or not: line checks need no parser
            self.sources = sources
            self.scan = scan_sources(root, sources)
            extra, self.history_note = audit_scan(root, current_secrets(self.scan["secret"], root))
            self.scan.update(extra)  # CI, Docker, mobile config and git history: same shape, same silencing
            self.scan.update(privacy_scan(root, sources))  # personal data, Apple privacy rules
            self.scan.update(apple_scan(root, sources))  # Swift crashes, cycles, main-thread I/O
            self.scan.update(infra_scan(root, set(load_config(root).ignore)))  # shell, Make, YAML, HTML, Pkl, patches
            self.online, self.vulns, self.deps_note = online, [], ""
            self._apply_silence(load_config(root).silence)
            self.surface = surface(root, g, self.v)
            # what kind of project: findings are ranked for it
            self.profile = detect_profile(root, g, self.surface, sources=sources)
            self.history = history.result()  # where change happens: findings there are worth fixing first
        finally:  # a failed check doesn't leave git running (and the interpreter waiting for it at exit)
            pool.shutdown(wait=False, cancel_futures=True)
        self.hot = self.history.by_path()
        self.rank_changes: list[rerank.Change] = []
        self.writers = writes(self.v)
        # (with tests left out of the results, what they reach was kept: coverage still counts them)
        static = set(g["tests"]["reached"]) if g.get("tests") else test_reach(self.v, self._tested_unlinked())
        self.coverage = measured(root, g["functions"])
        if self.coverage:  # what ran, where the report knows; the static estimate for files it doesn't cover
            seen = self.coverage.seen
            self.reached = self.coverage.covered | {fid for fid in static if self.v.fn.get(fid, {}).get("file") not in seen}
        else:
            self.reached = static
        self.tasks = make_plan(g, {path: fh.commits for path, fh in self.history.history.files.items()})
        self.findings: list[Finding] = []
        self.by_kind = defaultdict(list)
        for f in g["flags"]:
            self.by_kind[f["kind"]].append(f)
        self.code_fns = [f for f in g["functions"] if f["kind"] != "module" and not is_test(f["file"])]
        self._strengths: list[str] | None = None

    def _tested_unlinked(self) -> set[str]:
        """Functions tests run that the call graph doesn't link to them: a route's handler, when a test sends a request
        to its URL (TestClient, httptest, supertest); and in languages matched by name (Go, Java, …) a method a test
        calls on a value whose type isn't known (an interface, what a helper returns). "No test reaches it" was wrong
        for both on real repositories."""
        files = [f["id"] for f in self.g["files"] if is_test(f["id"])]
        texts = []
        for rel in files[:2000]:
            try:
                texts.append((self.root / rel).read_text(encoding="utf-8", errors="replace")[:2_000_000])
            except OSError:
                continue
        blob = "\n".join(texts)
        if not blob:
            return set()
        out = set()
        for e in self.surface.entries:
            path = e.path.rstrip("/")
            if len(path) < 2:
                continue  # "/": every URL ends somewhere
            parts = [r"[^/\"'`?]+" if re.fullmatch(r"\{[^}]*\}|<[^>]*>|:\w+|\*\w*", p) else re.escape(p) for p in path.split("/")]
            if re.search(r"[\"'`][^\"'`\s]*" + "/".join(parts) + r"/?(?:\?[^\"'`]*)?[\"'`]", blob):
                out.add(e.fn)
        called = set(re.findall(r"\.(\w+)\s*\(", blob))
        # a method a test calls by name, in any language: through a mixin, a base class or `self.session.delete()`, the
        # call graph can't tell which class's method runs, and "no test reaches it" was wrong for most of these
        out |= {fid for fid, f in self.v.fn.items() if f["kind"] == "method" and f["name"] in called
                and not is_test(f["file"])}  # fmt: skip

        # a test named for the file (ValueListItemPositionControllerTest.php, accounts_spec.rb, test_crud.py): request
        # specs and feature tests reach controllers through the router, which the call graph can't follow
        def stem(path: str, test: bool) -> str:
            s = path.rsplit("/", 1)[-1].split(".", 1)[0].lower()
            if test:
                s = re.sub(r"^test_|_test$|_spec$|tests?$|spec$|\.test$|\.spec$", "", s)
            return re.sub(r"_?controller$|_?handler$|_?view$|_?views$|_?service$", "", s.replace("-", "_"))

        tested_stems = {stem(f, True) for f in files}
        tested_stems.discard("")
        out |= {fid for fid, f in self.v.fn.items() if not is_test(f["file"]) and len(stem(f["file"], False)) > 3
                and stem(f["file"], False) in tested_stems}  # fmt: skip
        # migrations: a test run builds its database by applying them (pytest-django, Rails, Laravel)
        out |= {fid for fid, f in self.v.fn.items() if re.search(r"(?:^|/)(?:migrations|db/migrate)/", f["file"])}
        return out

    def n(self, shown: int) -> int:
        """How many locations a finding lists: a few in the report, all of them in the export."""
        return 1_000_000 if self.full else shown

    def add(self, *a, **k) -> None:
        self.findings.append(Finding(*a, **k))

    def changes(self, path: str) -> int:
        """Commits that changed this file in the last 12 months."""
        fh = self.history.history.files.get(path)
        return fh.commits if fh else 0

    def _changed(self, path: str) -> str:
        n = self.changes(path)
        return f" · changed {n}× in 12 months" if n >= 3 else ""

    def where(self, flag: dict) -> str:
        fn = self.v.fn.get(flag["target"])
        return (
            f"`{fn['file']}:{flag.get('line') or fn['line']}` {fn['qualname'] if fn['kind'] != 'module' else ''}".rstrip()
            if fn
            else f"`{flag['target']}" + (f":{flag['line']}`" if flag.get("line") else "`")
        )

    # ---- findings ----------------------------------------------------------------------------------------------
    def security(self) -> None:
        s = self.scan
        if s["secret"].hits:
            ev, more = _ev(s["secret"].hits, self.n(6))
            self.add(
                "Credentials committed in source",
                _sample_severity("Critical", s["secret"].hits),
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
            # only development settings (mastodon's .env.development): committed on purpose for contributors
            dev_only = all(re.match(r"\.env\.(?:dev|development|local\.dev)$", f) for f in tracked)
            self.add(
                "Environment files committed",
                "Low" if dev_only else "High",
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
                + self._reached_by(e)
                for e in s["sql_built"].hits[: self.n(6)]
            ]
            self.add(
                "SQL assembled from strings",
                self._by_reach("Medium", s["sql_built"].hits),
                "Security",
                ev,
                "If any interpolated value can come from a user, a file or the network, this is SQL injection. "
                "Constants and whitelisted identifiers are safe, but nothing enforces that they stay so.",
                "Pass values as bound parameters (`?` / `%s`); for table or column names, check them against a fixed "
                "list right where the SQL is built.",
                _effort(len(s["sql_built"].hits), len({e.file for e in s["sql_built"].hits})),
                max(0, len(s["sql_built"].hits) - self.n(6)),
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
                ev, more = _ev(hits, self.n(6))
                if key in SINK_KINDS:
                    ev = [line + self._reached_by(e) for line, e in zip(ev, hits, strict=False)]
                    sev = self._by_reach(sev, hits)
                    if all(is_script(e.file) or is_test(e.file) or is_doc_sample(e.file) for e in hits):
                        sev = _lower(sev)  # build scripts and docs tooling, run by the people who write them
                self.add(title, sev, "Security", ev, impact, fix, _effort(len(hits), len({e.file for e in hits})), more)
        self.endpoints()
        self.flows()
        self.config_findings()
        self.dependencies()

    def flows(self) -> None:
        """Proven data flows (Python, JavaScript, TypeScript): a request value traced, variable by variable, into a
        dangerous call."""
        flows = self.by_kind["taint"]
        if not flows:
            return
        worst = any(f.get("detail") in ("sql", "shell", "code") for f in flows)
        self.add(
            f"Request data reaches dangerous calls ({len(flows)} proven flows)",
            "Critical" if worst else "High",
            "Security",
            [f"{self.where(f)}: {f['message'].split(': ', 1)[-1]}" for f in flows[: self.n(8)]],
            "Traced through the code, not guessed from a pattern: whoever sends the request controls what reaches the "
            "call (injection into SQL or a shell, code execution, files outside the intended folder, requests to internal "
            "hosts, redirects to any site).",
            "Convert or validate the value where it enters (int(), Number(), an allow-list), or use the safe form of the "
            "call: bound SQL parameters, a command as an argument list without a shell, a fixed base URL or folder.",
            _effort(len(flows), len({self._file(f) for f in flows})),
            max(0, len(flows) - self.n(8)),
        )

    def config_findings(self) -> None:
        """Configuration, crypto, CI, containers, mobile settings and git history (the rest of a security audit)."""
        s = self.scan
        pr = s["gha_pr_target"]
        dangerous = [e for e in pr.hits if pr.data.get(e.file) == "checkout"]
        if dangerous:
            self.add(
                "Workflow runs a fork's code with this repository's secrets",
                "Critical",
                "Security",
                [f"`{e.at()}` {e.text}" for e in dangerous],
                "`pull_request_target` runs with write access and secrets; checking out the pull request's code lets "
                "anyone who opens a PR run it with both.",
                "Use `pull_request` for anything that builds or tests PR code; keep `pull_request_target` for "
                "labelling and commenting, without checking the PR out.",
                "S",
            )
        for key, title, sev, impact, fix in CONFIG_CHECKS:
            hits = s[key].hits
            if hits:
                ev, more = _ev(hits, self.n(6))
                sev = _sample_severity(sev, hits) if key == "secret_key_literal" else sev
                self.add(title, sev, "Security", ev, impact, fix, _effort(len(hits), len({e.file for e in hits})), more)
        for key, title, sev, area, impact, fix in APPLE_CHECKS + INFRA_CHECKS:
            hits = s[key].hits
            if hits:
                ev, more = _ev(hits, self.n(6))
                sev = _sample_severity(sev, hits) if key == "config_secret" else sev  # (a docs site's search key)
                self.add(title, sev, area, ev, impact, fix, _effort(len(hits), len({e.file for e in hits})), more)

    def dependencies(self) -> None:
        if not self.online:
            return
        from .deps import packages, vulnerabilities

        pkgs = packages(self.root)
        if not pkgs:
            self.deps_note = "no lockfile found, so dependencies weren't checked for known vulnerabilities"
            return
        try:
            self.vulns = vulnerabilities(pkgs)
        except (OSError, ValueError) as e:
            self.deps_note = f"OSV.dev couldn't be reached ({type(e).__name__}): dependencies not checked"
            return
        self.deps_note = f"{len(pkgs)} pinned dependencies checked against OSV.dev"
        if not self.vulns:
            return
        rank = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", ""]
        by_pkg: dict = {}
        for vuln in self.vulns:
            by_pkg.setdefault(vuln.package, []).append(vuln)
        shipped = {p: vs for p, vs in by_pkg.items() if not p.dev}
        worst = min((vuln.severity for vs in (shipped or by_pkg).values() for vuln in vs), key=rank.index)
        sev = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}.get(
            worst, "Medium"
        )
        if not shipped:  # only development tools: not in what users run
            sev = {"Critical": "High", "High": "Medium", "Medium": "Low"}.get(sev, "Low")

        def line(pkg, vs) -> str:
            vs = sorted(vs, key=lambda x: rank.index(x.severity))
            sevs = ", ".join(f"{n} {s.lower()}" for s in rank if s and (n := sum(1 for x in vs if x.severity == s)))
            fixed = sorted({f for x in vs for f in x.fixed.split(", ") if f})
            return (
                f"`{pkg.name}@{pkg.version}` ({pkg.source}{', dev only' if pkg.dev else ''}): "
                + (f"{len(vs)} vulnerability" if len(vs) == 1 else f"{len(vs)} vulnerabilities")
                + (f" ({sevs})" if sevs else "")
                + (f", e.g. {vs[0].id}: {vs[0].summary}" if vs[0].summary else f", e.g. {vs[0].id}")
                + (f"; fixed in {', '.join(fixed[:3])}" if fixed else "")
            )

        ordered = sorted(by_pkg.items(), key=lambda kv: (kv[0].dev, min(rank.index(x.severity) for x in kv[1])))
        self.add(
            f"Dependencies with known vulnerabilities ({len(self.vulns)} in {len(by_pkg)} packages"
            + (", all development-only" if not shipped else "")
            + ")",
            sev,
            "Security",
            [line(p, vs) for p, vs in ordered[: self.n(8)]],
            "Published vulnerabilities in the exact versions installed. Whether each is exploitable depends on how the "
            "package is used, but attackers scan for these first.",
            "Upgrade to a fixed version (`npm audit fix`, `pip install -U`, `cargo update`…); where there's no fix, "
            "check whether the vulnerable feature is used.",
            _effort(len(by_pkg), len(by_pkg)),
            max(0, len(by_pkg) - self.n(8)),
        )

    # -- the attack surface --------------------------------------------------------------------------------------
    def _reached_by(self, hit) -> str:
        """`  ← POST /orders → create_order → save` when a request reaches the line."""
        if not self.surface.entries:
            return ""
        fid = function_at(self.v, hit.file, hit.line)
        chain = self.surface.chain(fid, self.v) if fid else ""
        return f"  ← reached from `{chain}`" if chain else "  (no endpoint reaches it)"

    def _by_reach(self, sev: str, hits) -> str:
        """Severity from reachability: a risky line a request reaches is evidence (one level up); when the code has
        endpoints and none reaches it, it's a lead (one level down). Without endpoints (a library, a client app), as is."""
        if not self.surface.entries:
            return sev
        reached = any(self.surface.chain(f, self.v) for e in hits if (f := function_at(self.v, e.file, e.line)))
        order = ["Low", "Medium", "High", "Critical"]
        i = order.index(sev) + (1 if reached else -1)
        return order[max(0, min(len(order) - 1, i))]

    def _writing_entries(self) -> list[tuple]:
        """(entry, the first function it reaches that changes data) for endpoints that change data."""
        out_edges: dict[str, list[str]] = {}
        for e in self.g["edges"]:
            if e["kind"] in ("call", "ref"):
                out_edges.setdefault(e["src"], []).append(e["dst"])
        found, seen_routes = [], set()
        for entry in self.surface.entries:
            key = (entry.method, entry.path, entry.fn)
            if key in seen_routes or is_example_code(entry.file) or is_test(entry.file):
                continue  # (an example server's routes show how to use the project; they aren't its own)
            if entry.method in ("GET", "HEAD", "OPTIONS"):
                continue  # a read: what it writes on the way (a cache, a lock, a derived file) isn't the caller's change
            if self._comment_line(entry.file, entry.line):
                continue  # a route in a doc comment (a rustdoc or JSDoc example)
            seen_routes.add(key)
            seen, q = {entry.fn}, [entry.fn]
            while q:
                cur = q.pop(0)
                if cur in self.writers:
                    found.append((entry, cur))
                    break
                for nxt in out_edges.get(cur, ()):
                    if nxt not in seen:
                        seen.add(nxt)
                        q.append(nxt)
        return found

    def _comment_line(self, file: str, line: int) -> bool:
        try:
            text = (self.root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return False
        if not 0 < line <= len(text):
            return False
        if file.endswith(".rs") and any(re.match(r"\s*#\[cfg\(test\)\]", ln) for ln in text[: line - 1]):
            return True  # inside a `#[cfg(test)]` module: a test's router, compiled only for tests
        return re.match(r"\s*(?://|#|\*|/\*)", text[line - 1]) is not None

    def endpoints(self) -> None:
        entries = self.surface.entries
        if not entries:
            return
        writing = self._writing_entries()
        open_writes = [(e, w) for e, w in writing if not e.auth and not SIGN_IN.search(f"{e.path} {e.fn}")]
        if not open_writes:
            return
        authed = [e for e in entries if e.auth]
        exp, why = self.surface.exposure, self.surface.exposure_evidence
        if authed:
            sev, impact = (
                "High",
                (
                    f"Other endpoints check who's asking ({len(authed)} of {len(entries)}), these don't: likely a missing check, "
                    "so anyone who can reach the server can change this data."
                ),
            )
        elif exp == "local":
            sev, impact = (
                "Low",
                (
                    f"No endpoint checks who's asking, and the server listens only on this machine ({why}): fine for a local "
                    "tool, as long as it never listens on the network."
                ),
            )
        elif exp == "configurable":
            sev, impact = (
                "Medium",
                (
                    f"No endpoint checks who's asking. The server listens locally by default but can be opened to the network "
                    f"({why}): then anyone on that network can change data."
                ),
            )
        else:
            sev, impact = (
                ("High" if exp == "open" else "Medium"),
                (
                    "No endpoint checks who's asking"
                    + (f", and the server listens on every interface ({why})" if exp == "open" else "")
                    + ": anyone who can reach it can change data."
                ),
            )
        self.add(
            f"Endpoints that change data without an auth check ({len(open_writes)})",
            sev,
            "Security",
            [
                f"`{e.method} {e.path}` (`{e.file}:{e.line}`) → changes data in `{self.v.fn[w]['qualname']}` "
                f"(`{', '.join(self.v.fn[w]['io'][:2])}`)"
                for e, w in open_writes[: self.n(8)]
            ],
            impact + " Pattern-based: an auth check done elsewhere (a gateway, a proxy, an unusual decorator) isn't seen.",
            "Require authentication on each (a dependency, decorator or middleware), or document why it's open and "
            "`codefactory accept` it.",
            _effort(len(open_writes), len({e.file for e, _ in open_writes})),
            max(0, len(open_writes) - self.n(8)),
        )

    def surface_line(self) -> str:
        entries = self.surface.entries
        if not entries:
            return ""
        frameworks = sorted({e.framework for e in entries})
        authed = sum(1 for e in entries if e.auth)
        writing = len(self._writing_entries())
        exp = {
            "local": "listens only on this machine",
            "configurable": "listens locally by default, can be opened to the network",
            "open": "listens on every interface",
            "unknown": "listening address not found",
        }[self.surface.exposure]
        return (
            f"- **Attack surface:** {_n(len(entries), 'HTTP endpoint')} ({', '.join(frameworks)}); {authed} check auth; "
            f"{writing} change data; {exp}."
        )

    def reliability(self) -> None:
        s = self.scan
        sw = s["swallowed"].hits
        if len(sw) >= 3:
            ev, more = _ev(sw, self.n(6))
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
            ev, more = _ev(nt, self.n(6))
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
            ev, more = _ev(ms, self.n(6))
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
                [f"{self.where(f)}: {f['message'].split(':')[0]}" for f in reads[: self.n(6)]],
                "Cost grows with the data: one round trip per item instead of one for all.",
                "Load everything a loop needs with one batched query (WHERE id IN (…), a JOIN) or request before the "
                "loop (`codefactory plan` lists each with steps).",
                _effort(len(reads), len(reads)),
                max(0, len(reads) - self.n(6)),
            )
        product = [f for f in self.by_kind["io_in_loop"] if not self._script(f) and not is_test(self._file(f))]
        writes = [f for f in product if f.get("detail") == "write"]  # loops that can grow; fixed ones are fine as is
        files = [f for f in product if f.get("detail") in ("file", "process")]
        if writes:
            self.add(
                f"Writes inside loops in {_n(len(writes), 'place')}",
                "Low",
                "Performance",
                [self.where(f) for f in writes[: self.n(6)]],
                "One write per item: fine for a few, slow for many, and partial if it fails halfway outside a transaction.",
                "Wrap each loop in one transaction (or have the caller do so); for loops that can grow, write all rows "
                "with one multi-row INSERT/UPDATE.",
                "M",
                max(0, len(writes) - self.n(6)),
            )
        if files:
            self.add(
                f"File or program operations inside loops in {_n(len(files), 'place')}",
                "Low",
                "Performance",
                [self.where(f) for f in files[: self.n(6)]],
                "One file read, write, copy or directory walk (or program run) per item: normal when each item is its "
                "own file, slow when it's the same file or folder every time.",
                "Where it's the same file or folder each round, read it once before the loop and look items up in memory.",
                "S",
                max(0, len(files) - self.n(6)),
            )

    def architecture(self) -> None:
        cycles = {frozenset([f["target"], *f.get("related", [])]) for f in self.by_kind["cycle"]}
        chain = {frozenset([f["target"], *f.get("related", [])]): f.get("detail", "") for f in self.by_kind["cycle"]}
        if cycles:
            biggest = max(len(c) for c in cycles)
            load_order = any(f["severity"] == "high" for f in self.by_kind["cycle"])  # modules that run on import
            self.add(
                f"{'Import' if load_order else 'Dependency'} loops ({len(cycles)})",
                ("High" if biggest >= 3 else "Medium") if load_order else ("Medium" if biggest >= 3 else "Low"),
                "Architecture",
                [
                    (chain[c] or " → ".join(sorted(c)))
                    + (f" ({len(c)} files in the loop)" if len(c) > chain[c].count(" → ") else "")
                    for c in sorted(cycles, key=lambda c: (-len(c), sorted(c)))[: self.n(4)]
                ],
                "Files in a loop load in a fragile order and can't be understood, tested or moved alone."
                if load_order
                else "Classes in a loop work at runtime, but can't be understood, tested, reused or moved apart.",
                "Move what both sides need into a module that imports neither, or pass the dependency in.",
                _effort(len(cycles), biggest),
            )
        lv = self.by_kind["layer_violation"]
        if lv:
            self.add(
                f"Layer rule violations ({len(lv)})",
                "High",
                "Architecture",
                [f["message"] for f in lv[: self.n(6)]],
                "The architecture factory.toml describes isn't the one the code has.",
                "Move the code into an allowed layer or invert the dependency.",
                _effort(len(lv), len(lv)),
                max(0, len(lv) - self.n(6)),
            )
        rank = {name: i for i, name in enumerate(self.g["layers"])}
        layer_of = {f["id"]: f["layer"] for f in self.g["files"]}
        back, example = Counter(), {}
        for e in self.g["edges"]:
            if e["kind"] == "import" and not is_test(e["src"]) and not is_test(e["dst"]):  # (Go's _test.go: same folder)
                a, b = layer_of.get(e["src"]), layer_of.get(e["dst"])
                if a and b and "tests" not in (a, b) and rank.get(b, 0) < rank.get(a, 0) and not ROOT_LAYER.match(a):
                    back[(a, b)] += 1
                    example.setdefault((a, b), (e["src"], e["dst"]))
        if back:
            self.add(
                "Dependencies against the layer order",
                "Low",
                "Architecture",
                [
                    f"{a} imports {b} ({_n(n, 'import')}, e.g. `{example[(a, b)][0]}` → `{example[(a, b)][1]}`)"
                    for (a, b), n in back.most_common(self.n(5))
                ],  # fmt: skip
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
                [
                    f"{t['title']}: " + ", ".join(f"`{w['file']}:{w['line']}`" for w in t["where"][: self.n(3)])
                    for t in copies[: self.n(6)]
                ],
                "A fix applied to one copy silently misses the others.",
                "Merge each group into one function in the lowest layer its callers share (`codefactory plan` has "
                "per-group steps).",
                _effort(len(copies), len(copies) * 2),
                max(0, len(copies) - self.n(6)),
            )
        # the hardest to follow first: branches (decisions) weigh more than length, so a long but flat table of
        # options or a big layout ranks below a shorter function full of conditions
        # ...and among those, the ones in files that keep changing: a tangled function nobody touches costs little
        long = sorted(
            (f for f in self.code_fns if f["loc"] > 80),
            key=lambda f: -(f.get("branches", 0) * 4 + f["loc"] / 10) * (1 + self.changes(f["file"]) / 4),
        )
        if long:
            self.add(
                f"Very long functions ({_n(len(long), 'function')} over 80 lines)",
                "Low",
                "Maintainability",
                [
                    f"`{f['file']}:{f['line']}` {f['qualname']}: {f['loc']} lines"
                    + (f", {f['branches']} decision points" if f.get("branches") else "")
                    + self._changed(f["file"])
                    for f in long[: self.n(6)]
                ],
                "Hard to read, test and change safely; often several responsibilities in one place.",
                "Extract the parts that have names of their own.",
                "M",
                max(0, len(long) - self.n(6)),
            )
        # functions nothing calls; a method with no callers found is only a hint (an override, an interface's method,
        # a trait impl, a framework hook are called through the base type), never reported as dead
        unused = [f for f in self.by_kind["unused"] if f["severity"] != "info" and not is_test(self._file(f))]
        if unused:
            self.add(
                f"Unused code ({_n(len(unused), 'function')})",
                "Low",
                "Maintainability",
                [self.where(f) for f in unused[: self.n(6)]],
                "Dead code costs reading time and keeps dependencies alive.",
                "Verify (frameworks may call by name), then delete.",
                "S",
                max(0, len(unused) - self.n(6)),
            )
        # only where the lists plausibly grow: the function loads data itself or through what it calls. A search in
        # a loop over a handful of UI items or a fixed table costs nothing, and listing 50 of them hides the few
        # that matter
        loads = self._loads_data()
        scans = [f for f in self.by_kind["quadratic_scan"] if not self._script(f) and f["target"] in loads]
        if scans:
            self.add(
                f"Array searches inside loops over loaded data ({len(scans)})",
                "Low",
                "Performance",
                [self.where(f) for f in scans[: self.n(5)]],
                "O(n²) on data that comes from storage or the network: fine at today's size, slow as it grows.",
                "Build a Map/Set (dict/set) from the list once before the loop, and look items up in it.",
                "M",
                max(0, len(scans) - self.n(5)),
            )

    def testing(self) -> None:
        tests = (
            [f for f in self.g["files"] if is_test(f["id"])]
            or (self.g.get("tests") or {}).get("files", [])
            or [f for f in getattr(self, "sources", []) if is_test(f)]  # on disk, though not analyzed: tests all the same
        )
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
            if f["id"] not in self.reached
            and (f.get("io") or len(callers[f["id"]]) >= 8)
            and not is_script(f["file"])
            and not self._di_provider(f)
        ]
        # writes first (a wrong one loses data), then I/O, then code that keeps changing, then the most depended-on
        risky.sort(
            key=lambda f: (
                -bool(rerank.WRITE_WORDS.search(" ".join(f.get("io", [])))),
                -bool(f.get("io")),
                -min(self.changes(f["file"]), 10),
                -len(callers[f["id"]]),
            )
        )
        if risky:
            self.add(
                f"Important code no test reaches ({_n(len(risky), 'function')})",
                "Medium",
                "Testing",
                [
                    f"`{f['file']}:{f['line']}` {f['qualname']}"
                    + (f": does I/O ({', '.join(f['io'][:2])})" if f.get("io") else "")
                    + (f", called from {len(callers[f['id']])} files" if len(callers[f["id"]]) >= 2 else "")
                    + self._changed(f["file"])
                    for f in risky[: self.n(8)]
                ],
                f"Tests reach {pct}% of functions, but not these: code that talks to storage or the network, or that "
                "much of the app depends on." + self._coverage_note(),
                "Add tests that call these (against a real or in-memory store), starting with the ones that write data.",
                _effort(len(risky), len({f["file"] for f in risky})),
                max(0, len(risky) - self.n(8)),
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

    def custom(self) -> None:
        """The team's own rules from factory.toml, one finding per rule."""
        by_rule: dict[str, list[dict]] = {}
        for f in self.by_kind["custom"]:
            by_rule.setdefault(f.get("detail") or "custom", []).append(f)
        for rule, flags in sorted(by_rule.items()):
            sev = {"high": "High", "warn": "Medium", "info": "Low"}[
                min((f["severity"] for f in flags), key=["high", "warn", "info"].index)
            ]
            message = flags[0]["message"].split("] ", 1)[-1]
            self.add(f"Custom rule {rule} ({len(flags)})", sev, "Custom", [self.where(f) for f in flags[: self.n(6)]], message,
                     "See the rule in factory.toml.", _effort(len(flags), len({self._file(f) for f in flags})),
                     max(0, len(flags) - self.n(6)))  # fmt: skip

    def _by_owner(self) -> list[str]:
        """Findings per owning team, from CODEOWNERS: who has the most to act on."""
        from .owners import load

        owners = load(self.root)
        if not owners:
            return []
        counts: dict[str, Counter] = {}
        files = [(self._file(f), f["severity"]) for f in self.g["flags"]]
        files += [(e.file, "warn") for k, c in self.scan.items() if k in SECURITY_KEYS for e in c.hits]
        for file, sev in files:
            for who in owners.of(file) or ["(no owner)"]:
                counts.setdefault(who, Counter())[sev] += 1
        rows = sorted(counts.items(), key=lambda kv: (-kv[1]["high"], -kv[1]["warn"], -sum(kv[1].values())))
        out = [f"### By owner ({owners.source})", "", "| Owner | High | Warn | Info |", "|---|---|---|---|"]
        out += [f"| {who} | {c['high']} | {c['warn']} | {c['info']} |" for who, c in rows[:15]]
        return [*out, ""]

    def delivery(self) -> None:
        r = self.repo
        if not r["ci"]:
            self.add(
                "No continuous integration",
                "High",
                "Delivery",
                [
                    f"no CI configuration found here or above, up to the repository's top (looked for {CI_NAMES}); "
                    'if yours is another system, name its file in factory.toml: ci = ["path"]'
                ],
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
            dev = r.get("npm_dev_only")
            library = getattr(getattr(self, "profile", None), "kind", "") == "library"  # npm libraries don't ship one
            self.add(
                "No lockfile",
                "Low" if dev or library else "High",
                "Dependencies",
                [", ".join(r["manifests"]) + (" (development tools only)" if dev else "")],
                "Development tools can resolve different versions between installs, so a lint or test run can change "
                "without a code change."
                if dev
                else "Every install can resolve different versions: builds aren't reproducible.",
                "Commit the lockfile your package manager writes, and install with it in CI (npm ci / pnpm i --frozen-lockfile).",
                "S",
            )
        if r["floating"]:
            self.add(
                "Dependencies on moving targets",
                "Medium",
                "Dependencies",
                r["floating"][: self.n(8)],
                "`*`, `latest` or a git branch changes under you without a code change.",
                "Pin versions (or commits).",
                "S",
            )
        if r["unpinned_py"]:
            self.add(
                "Unpinned Python requirements",
                "Medium",
                "Dependencies",
                r["unpinned_py"][: self.n(8)],
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
        self.custom()
        if self.surface.entries:
            self.profile.open_writes = sum(1 for e, _ in self._writing_entries() if not e.auth)
        self.rank_changes = rerank.rerank(self.findings, self.profile)
        for f in self.findings:  # findings in hotspots: the same severity, but worth doing first
            hot = sorted({p for e in f.evidence for p in re.findall(r"`([^`\s]+?):\d+`", e) if p in self.hot},
                         key=lambda p: -self.hot[p].score)  # fmt: skip
            if hot:
                f.data["hotspot"] = hot
        self.findings.sort(key=lambda f: (SEV.index(f.severity), not f.data.get("hotspot"), -len(f.evidence) - f.more))

    def _test_files(self) -> int:
        on_disk = sum(1 for f in getattr(self, "sources", []) if is_test(f))
        return max(sum(1 for f in self.g["files"] if is_test(f["id"])), on_disk)

    def unanalyzed(self) -> list[str]:
        """Source files on disk the analyzers couldn't read (TypeScript without a compiler, other languages without the
        language pack): the line checks ran on them, the call graph and its findings didn't."""
        seen = {f["id"] for f in self.g["files"]}
        return [f for f in getattr(self, "sources", []) if f not in seen and not is_test(f)]

    def health(self) -> tuple[str, list[Finding]]:
        missing, code = self.unanalyzed(), [f for f in getattr(self, "sources", []) if not is_test(f)]
        if code and len(missing) * 2 > len(code):  # most of the code wasn't analyzed: a grade would be about nothing
            return "Not assessed", [f for f in self.findings if f.severity in ("Critical", "High")]
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
            f"- **Profile:** {self.profile.summary()} (section 2; findings are ranked for it).",
            f"- **Entry points:** {len(entry)} files nothing imports (screens, routes, scripts, configs).",
            f"- **Data:** {', '.join(self.stores()) or 'no data store detected'}.",
            f"- **External services:** {', '.join(sorted(hosts)[:8]) or 'none found in the code'}"
            + (f" (+{len(hosts) - 8} more)" if len(hosts) > 8 else "")
            + ".",
            *([line] if (line := self.surface_line()) else []),
            f"- **Tests:** {self._test_files()} test files"
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
        out += ["", "## 2. Project profile", ""] + profile_markdown(self.profile)
        out += ["", "**Ranked for this project**", ""] + rerank.markdown(self.rank_changes)
        out += ["## 3. System map", "", "| Layer | Files | Lines | Calls into |", "|---|---|---|---|"]
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
        by_file: dict[str, list[str]] = defaultdict(list)
        for f in self.findings:
            for path in f.data.get("hotspot", []):
                by_file[path].append(f.title.split(" (")[0])
        out += ["## 4. Where change happens", ""] + hotspots.markdown(self.history, by_file)
        out += ["## 5. Findings", ""]
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
                out += [f"- Impact: {f.impact}", f"- Fix: {f.fix}"]
                if ranked := f.data.get("ranked"):
                    out.append(f"- Ranked {f.severity} for this project (default {ranked['from']}): {ranked['why']}")
                if hot := f.data.get("hotspot"):
                    x = self.hot[hot[0]]
                    out.append(
                        f"- In a hotspot: `{x.path}` changed {x.commits} times in 12 months"
                        + (f" ({x.recent} in the last 3)" if x.recent and x.recent != x.commits else "")
                        + (f", and {len(hot) - 1} more hotspot file{'s' if len(hot) > 2 else ''}" if len(hot) > 1 else "")
                        + ": fixing it here pays off soonest."
                    )
                out.append("")
        out += self._by_owner()
        out += ["## 6. What is working", ""] + [f"- {w}" for w in self.strengths()] + [""]
        out += ["## 7. Testing and release gaps", ""]
        gaps = [f for f in self.findings if f.area in ("Testing", "Delivery", "Dependencies")]
        out += [f"- **{f.title}.** {f.fix}" for f in gaps] or ["- None found by these checks."]
        out += ["", "## 8. Open questions", ""] + [f"- {q}" for q in self.questions()]
        out += ["", "## Review limits", ""] + [f"- {x}" for x in self.limits()]
        if for_ai:
            out += ["", self.evidence_pack()]
        return "\n".join(out) + "\n"

    def _justify(self, grade: str, drivers: list[Finding]) -> str:
        if grade == "Not assessed":
            missing = self.unanalyzed()
            return (f"{len(missing):,} of the source files weren't analyzed, so this review can't grade the code: "
                    + _how_to_analyze(missing) + " Then run it again.")  # fmt: skip
        crit = [f.title for f in drivers]
        good = len(self.strengths())
        if not crit:
            return f"No critical or high-severity findings; {good} strengths below. The medium items are real debt, not blockers."
        return (
            f"Driven by {_n(len(crit), 'critical/high finding')}: {'; '.join(crit[:3])}"
            + (" …" if len(crit) > 3 else "")
            + f". {good} things are working well (section 6)."
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
        p = self.profile
        q = [
            "What scale is this built for (users, data volume, requests per second), and what are the uptime or latency targets?"
            if p.server
            else "How many people use it, and how much data does one of them build up over a year?",
            (
                f"It holds {', '.join(p.sensitive)} data: which rules apply (GDPR, HIPAA, PCI DSS, the app stores' privacy "
                "labels), and is that data ever sent off the device or server?"
            )
            if p.sensitive
            else "Is any of its data sensitive (personal, payment, health) in ways the code doesn't show?",
        ]
        if p.kind == "unknown":
            q.insert(0, "What kind of project is this (app, service, tool, library)? Set it in factory.toml `[profile]` "
                     "so findings are ranked for it.")  # fmt: skip
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
            "Which findings above are known and accepted? Mark them (`codefactory accept <kind> <file> --why …` or a "
            "`codefactory: ignore <kind> — why` comment) "
            "so the next review shows only what's new."
        )
        return q

    def _apply_silence(self, rules: list[dict]) -> None:
        """[[silence]] rules in factory.toml (written by `codefactory accept`) apply to the review's own checks too."""
        for key, check in self.scan.items():
            check.hits = [
                e for e in check.hits
                if not any(r["kind"] in ("*", key) and (fnmatch(e.file, r["where"]) or fnmatch(f"{e.file}:{e.line}", r["where"]))
                           for r in rules)
            ]  # fmt: skip

    def _coverage_note(self) -> str:
        if self.coverage:
            return (
                f" Measured from {self.coverage.source} ({self.coverage.written}); rerun the tests with coverage to refresh it."
            )
        return " Estimated from which functions tests call (no coverage report found: coverage/lcov.info, coverage.json)."

    def _loads_data(self) -> set[str]:
        """Functions that read from a database, the network or files, themselves or through a function they call."""
        io = {fid for fid, f in self.v.fn.items() if f.get("io")}
        out = set(io)
        for e in self.g["edges"]:
            if e["kind"] == "call" and e["dst"] in io:
                out.add(e["src"])
        return out

    @staticmethod
    def _copied(task: dict) -> bool:
        """Copies worth merging: identical or nearly so (≥85%), and not a test restating code it checks (an oracle).
        Below 85% the pair is usually a deliberate variant (unticking a set vs deleting it, "45 sec" vs "45s")."""
        if task["kind"] not in ("duplicate", "similar") or any(is_test(w["file"]) for w in task["where"]):
            return False
        if all(is_doc_sample(w["file"]) for w in task["where"]):
            return False  # samples and tutorials repeat their setup on purpose: each stands alone
        if deliberate_copies([w["file"] for w in task["where"]]):
            return False  # frozen versions, build outputs, vendored code, standalone examples
        m = re.search(r"(\d+)% similar", task["title"])
        lines = re.search(r"~(\d+) lines", task["title"])
        # a near copy of a few lines is boilerplate more often than logic (a DI constructor, a one-line action):
        # measured on 76 repositories, small identical copies were real and small edited ones weren't
        if m and lines and int(lines.group(1)) < 12:
            return False
        return not m or int(m.group(1)) >= 85

    def _di_provider(self, f: dict) -> bool:
        """A dependency-injection provider (Dagger/Hilt `@Provides`, Spring `@Bean`): one line of wiring the framework
        calls, tested through what it builds, not on its own (Now in Android's DaosModule)."""
        if not f["file"].endswith((".kt", ".java", ".scala")):
            return False
        try:
            lines = (self.root / f["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return False
        # its own annotations: the definition's line (an analyzer may start it at the annotation) and the annotation
        # lines right above it
        i = min(f["line"], len(lines)) - 1
        own = [lines[i]] if i >= 0 else []
        while i > 0 and lines[i - 1].strip().startswith("@"):
            i -= 1
            own.append(lines[i])
        return bool(re.search(r"@(?:Provides|Binds|BindsInstance|Bean|Produces)\b", " ".join(own)))

    def limits(self) -> list[str]:
        analyzed = Counter(Path(f["id"]).suffix for f in self.g["files"])
        seen = {f["id"] for f in self.g["files"]}
        other = Counter()
        for rel in walk(self.root, suffixes=tuple(OTHER_CODE)):
            if rel not in seen:
                other[OTHER_CODE[Path(rel).suffix]] += 1
        out = [
            f"Analyzed {len(self.g['files'])} files ({', '.join(f'{n} {ext}' for ext, n in analyzed.most_common(6))}) "
            "statically: call graph, imports, structure and text patterns. Nothing was executed."
        ]
        if ok := self.scan["swallowed_ok"].hits:
            kinds = Counter(e.text for e in ok)
            why = {"explained": "a comment says why", "cleanup": "best-effort cleanup", "fallback": "a fallback value",
                   "fire and forget": "a promise deliberately not awaited (`void …`)"}  # fmt: skip
            out.append(
                f"{_n(len(ok), 'empty catch block')} treated as deliberate, not reported ("
                + ", ".join(f"{n}: {why.get(k, k)}" for k, n in kinds.most_common())
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
            (
                f"Dependencies: {self.deps_note}."
                if self.online
                else "Dependencies weren't checked for known vulnerabilities: `--online` does it (sends package names "
                "and versions to OSV.dev, nothing else)."
            ),
            *([f"Git history: {self.history_note}."] if self.history_note else []),
            "Not checked: runtime behaviour, concurrency and transaction semantics, business logic, infrastructure "
            "beyond Dockerfiles and CI workflows.",
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
            "1. Check the project profile (section 2) against the README: it decides how findings are ranked. If it's "
            "wrong, say so and suggest the `[profile]` lines for factory.toml.",
            "2. For each Critical/High/Medium finding: confirm it from the cited lines (open only those), or reject it "
            "with the reason. Adjust severity using what the code and README say about the product.",
            "3. Read the risky functions below. For each, decide whether there's a real failure mode (data loss, a "
            "user locked out, a race between writers, a misleading error) and add findings for the real ones. Weigh "
            "those in hotspots (section 4) higher: that code changes every week.",
            "4. Rewrite sections 1 and 5 with your conclusions. Keep file:line evidence. Don't read other files "
            "unless a finding needs one more caller (`codefactory context <name>` lists them).",
            "",
            f"Profile: {self.profile.summary()}."
            + (f" Hotspots: {', '.join(f'`{x.path}`' for x in self.history.hot[:5])}." if self.history.hot else ""),
            "",
            "### Riskiest code (deletes data, does I/O, untested, swallows errors)",
            "",
        ]
        out += self._surface_pack()
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

    def _surface_pack(self) -> list[str]:
        """The attack surface for the AI: every endpoint with its auth check and what it changes, so it judges
        authorization (can user A reach user B's data?) and input handling on the paths that matter."""
        entries = self.surface.entries
        if not entries:
            return []
        writing = {(e.method, e.path): self.v.fn[w]["qualname"] for e, w in self._writing_entries()}
        out = [
            "### Attack surface",
            "",
            f"Listening: {self.surface.exposure}"
            + (f" ({self.surface.exposure_evidence})" if self.surface.exposure_evidence else "")
            + ".",
            "For each endpoint that changes data, check that it verifies who's asking and that the caller may change "
            "*that* record (an id from the request must belong to them), and that its inputs are validated.",
            "",
            "| Endpoint | Handler | Auth found | Changes data in |",
            "|---|---|---|---|",
        ]
        for e in entries[:40]:
            out.append(
                f"| `{e.method} {e.path}` | `{e.file}:{e.line}` | {e.auth or 'none'} | {writing.get((e.method, e.path), '')} |"
            )
        if len(entries) > 40:
            out.append(f"| … {len(entries) - 40} more (`codefactory surface`) | | | |")
        return [*out, ""]

    @staticmethod
    def _version() -> str:
        from . import __version__

        return __version__


def _how_to_analyze(files: list[str]) -> str:
    js = sum(f.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")) for f in files)
    other = len(files) - js
    parts = []
    if js:
        parts.append(f"{js:,} TypeScript/JavaScript files need a TypeScript compiler (`npm install -g typescript@5`; "
                     "codefactory never runs the project's own)")  # fmt: skip
    if other:
        parts.append(f'{other:,} files need the language pack (`pip install "codefactory-cli[languages]"`)')
    return "; ".join(parts) + "."


# a composition root: where the program is wired together, so importing every layer is its job
ROOT_LAYER = re.compile(r"(?i)^(?:cmd|boot|bootstrap|main|app|server|wire|wiring|entry|entrypoints?)$")
SECURITY_KEYS = {"secret", "eval", "shell", "tls_off", "raw_html", "sql_built", "history_secret", "secret_key_literal",
                 "jwt_unverified", "weak_cipher", "weak_hash", "weak_random", "cors_any", "insecure_cookie", "debug_on",
                 "sensitive_storage", "docker_secret", "gha_injection"}  # fmt: skip

INFRA_CHECKS = [
    ("config_secret", "Credentials in configuration files", "Critical", "Security",
     "YAML, Makefiles, Pkl, Terraform and other config files are shared, copied into images and pasted into tickets; a "
     "key in one is as leaked as one in the code.",
     "Rotate it, then read it from the environment or a secret manager (Pkl: `read(\"env:NAME\")`; Compose and "
     "Kubernetes: secrets)."),
    ("ci_test_secret", "Passwords for CI services written into workflows", "Low", "Security",
     "Usually throwaway credentials for the run's own test services; if any guards something real, it's leaked.",
     "Use repository secrets (`${{ secrets.NAME }}`) for anything that isn't a throwaway test value."),
    ("compose_secret", "Passwords written into docker-compose", "Medium", "Security",
     "Everyone with the repository has them, and the same file tends to reach staging and production.",
     "Use an `.env` file that isn't committed, `${VAR}` substitution, or Compose `secrets:`."),
    ("k8s_secret", "Kubernetes Secrets committed with their values", "High", "Security",
     "A Secret's `data` is only base64: anyone with the repository can read it.",
     "Keep the values out of git: Sealed Secrets, SOPS, External Secrets, or create them at deploy time."),
    ("shell_pipe", "Downloads piped straight into a shell", "Medium", "Security",
     "Runs whatever the server sends at that moment, with no checksum: a compromised or spoofed host runs code on "
     "every machine that runs this.",
     "Download to a file, check its checksum or signature, then run it; or use a package manager."),
    ("html_no_sri", "Third-party scripts without integrity hashes", "Medium", "Security",
     "If the CDN is compromised or the file changes, the page runs the new code with your users' sessions.",
     "Add `integrity=\"sha384-…\"` and `crossorigin=\"anonymous\"`, or serve the file yourself."),
    ("html_mixed", "Pages loading scripts, styles or forms over plain HTTP", "Medium", "Security",
     "Anyone on the network can change them in transit; browsers block most of it on HTTPS pages, so it also breaks.",
     "Use https:// (or a relative URL)."),
    ("compose_exposed", "Databases published on every interface (docker-compose)", "Medium", "Security",
     "`5432:5432` listens on all of the host's addresses, not just this machine: on a server or a laptop on public "
     "Wi-Fi, the database is reachable by others.",
     "Bind to localhost (`127.0.0.1:5432:5432`), or don't publish the port and let services talk on the Compose network."),
    ("compose_privileged", "Privileged containers or the host's network (docker-compose)", "Medium", "Security",
     "A privileged container (or one on the host network) can reach the host itself: a break-in goes straight through.",
     "Drop `privileged`/`network_mode: host`; grant only the capabilities it needs (`cap_add`)."),
    ("k8s_privileged", "Privileged or root containers (Kubernetes)", "Medium", "Security",
     "A break-in in the container becomes root on the node.",
     "Set `privileged: false`, `allowPrivilegeEscalation: false`, `runAsNonRoot: true`."),
    ("k8s_host", "Pods using the node's network, processes or files (Kubernetes)", "Medium", "Security",
     "hostNetwork, hostPID, hostIPC and hostPath give the pod a view into the node and everything else on it.",
     "Remove them unless the workload is a node agent that truly needs them."),
    ("shell_rm_var", "`rm -rf` on a variable that may be empty", "Medium", "Reliability",
     "If the variable is unset or empty, `rm -rf \"$DIR/\"` deletes from the filesystem root.",
     "Use `\"${DIR:?}/\"` (fails when empty), or `set -u` at the top of the script."),
    ("shell_eval", "Shell `eval` of a variable", "Medium", "Security",
     "Whatever the variable holds is run as shell code: spaces, `;` and `$(…)` in it all execute.",
     "Call the command directly with its arguments, or use an array."),
    ("go_server_timeout", "HTTP servers without timeouts (Go)", "Low", "Reliability",
     "`http.ListenAndServe` and a bare `http.Server` never time out: slow clients hold connections open until the "
     "server runs out (Slowloris).",
     "Use an `http.Server` with `ReadHeaderTimeout` (and Read/Write/IdleTimeout)."),
    ("config_http", "Plain-HTTP URLs in configuration (Pkl, TOML, Terraform…)", "Low", "Security",
     "Packages, endpoints or registries fetched over HTTP can be swapped in transit.",
     "Use https://."),
]  # fmt: skip

APPLE_CHECKS = [
    ("main_thread_io", "Disk or database work on the main thread (Swift)", "Medium", "Performance",
     "The UI freezes while it runs; long enough and the watchdog kills the app.",
     "Move it off the main thread (a Task, an actor, a background queue) and update the UI when it's done."),
    ("swift_retain_cycle", "Possible retain cycles: closures kept by self that capture self strongly", "Medium", "Reliability",
     "The object and its closure keep each other alive: memory grows, and observers or timers keep firing after the "
     "screen is gone.",
     "Capture `[weak self]` (or `[unowned self]` when the lifetime is certain) in closures self keeps."),
    ("swift_force", "`try!` / `as!` that crash on failure (Swift)", "Low", "Reliability",
     "An unexpected error or type ends the app instead of being handled.",
     "Use `try` with `do/catch`, `try?` with a fallback, or `as?` with a guard."),
    ("entitlement_weakened", "Code-signing protections turned off (entitlements)", "Medium", "Security",
     "Library validation, executable-memory or debugging protections are off: easier to inject code into the app.",
     "Remove the entitlement unless a dependency truly needs it, and keep get-task-allow out of release builds."),
]  # fmt: skip

# (check, title, severity, impact, fix) for the configuration, crypto, CI, container, mobile and history checks
CONFIG_CHECKS = [
    ("history_secret", "Credentials in git history (deleted, still leaked)", "High",
     "Anyone with a clone, a fork or an old CI log has them, even though the current files don't.",
     "Rotate each one now; rewriting history doesn't help once it has been pushed."),
    ("ios_usage_missing", "iOS permission used without its usage description", "High",
     "App Review rejects the app, and iOS terminates it the moment it asks for that permission.",
     "Add the Info.plist key with a sentence saying why (in Expo: `ios.infoPlist` in app.json, or the library's config "
     "plugin option)."),
    ("ios_privacy_manifest", "Required-reason API without a privacy manifest", "High",
     "Since May 2024 App Store Connect rejects uploads that use these APIs without declaring why.",
     "Add PrivacyInfo.xcprivacy with NSPrivacyAccessedAPITypes and the approved reason codes (in Expo: "
     "`ios.privacyManifests` in app.json)."),
    ("privacy_analytics", "Personal data sent to analytics or crash reporting", "High",
     "A third party receives it: it needs consent, a privacy-policy entry and App Store privacy labels, and it's hard to "
     "take back.",
     "Send an opaque id or a coarse value instead (age band, city), or drop the field."),
    ("privacy_log", "Personal data written to logs", "Medium",
     "Logs are copied to consoles, crash reports and log services, kept for long, and readable by more people than the "
     "data itself.",
     "Log an id or a redacted value instead (`***@domain`), or nothing."),
    ("privacy_storage", "Personal data in unencrypted storage", "Medium",
     "AsyncStorage, localStorage, UserDefaults and SharedPreferences are plain files, included in backups.",
     "Keep it in the database you protect, or the platform's encrypted store."),
    ("secret_key_literal", "Signing key written in the code", "High",
     "Whoever reads the code can forge sessions, tokens or signed links.",
     "Load it from the environment or a secret store, and rotate the one that was committed."),
    ("jwt_unverified", "JWT checks turned off", "High",
     "A token that isn't verified (signature, algorithm or expiry) can be forged or reused.",
     "Always verify the signature with an explicit algorithm list, and keep expiry checks on."),
    ("weak_cipher", "Broken encryption mode or cipher (ECB, DES, RC4)", "High",
     "Patterns in the data survive encryption (ECB), or the cipher can be broken (DES, RC4).",
     "Use an authenticated mode such as AES-GCM (or a library like libsodium / Fernet)."),
    ("docker_secret", "Secrets baked into a container image", "High",
     "Every layer of an image is readable by anyone who can pull it.",
     "Pass secrets at runtime (environment, mounted secret, build secret), never in ENV/ARG."),
    ("gha_injection", "Untrusted text run as a shell command in CI", "High",
     "A PR or issue title or body is pasted into a `run:` script: whoever writes it can run commands with the "
     "workflow's secrets.",
     "Pass it through an environment variable (`env: TITLE: ${{ … }}`) and quote it in the script."),
    ("weak_hash", "MD5 / SHA-1 used for security", "Medium",
     "Both are broken for passwords and signatures: fast to brute-force, and collisions can be forged.",
     "Passwords: bcrypt, scrypt or argon2. Signatures and tokens: HMAC-SHA-256 or better."),
    ("weak_random", "Predictable random numbers for secrets", "Medium",
     "`random` / `Math.random()` can be predicted from earlier outputs; tokens made with them can be guessed.",
     "Use `secrets` (Python), `crypto.randomBytes` / `crypto.getRandomValues` (JavaScript)."),
    ("cors_any", "Any website may call this API (CORS *)", "Medium",
     "Every site a user visits can read this API's responses in their browser.",
     "List the origins that need access."),
    ("insecure_cookie", "Session cookies without Secure / HttpOnly", "Medium",
     "Cookies can travel over plain HTTP, or be read by injected scripts.",
     "Set Secure and HttpOnly (and SameSite) on session and auth cookies."),
    ("debug_on", "Debug mode switched on in code", "Medium",
     "Debug pages show code, settings and sometimes a console to whoever triggers an error.",
     "Turn it on from the environment for development only."),
    ("sensitive_storage", "Tokens or passwords in unencrypted storage", "Medium",
     "AsyncStorage / localStorage are plain files or readable by any script on the page.",
     "Use the platform's secure store (Keychain / Keystore via SecureStore, or an HttpOnly cookie on the web)."),
    ("mobile_cleartext", "App allows unencrypted HTTP", "Medium",
     "Traffic can be read or changed on public Wi-Fi.",
     "Remove the exception, or limit it to the hosts that need it."),
    ("docker_root", "Container runs as root", "Medium",
     "A break-in through the app gets root inside the container, one step from the host.",
     "Add a non-root `USER` after installing packages."),
    ("gha_unpinned", "Third-party CI actions not pinned to a commit", "Low",
     "A tag can be moved: a compromised action then runs in your CI with its secrets.",
     "Pin third-party actions to a full commit SHA (keep the tag in a comment)."),
    ("docker_latest", "Container base image not pinned", "Low",
     "`latest` or no tag changes under you: builds aren't reproducible and can pick up a bad release.",
     "Pin a version tag (or a digest)."),
]  # fmt: skip


def review_markdown(g: dict, root: Path, for_ai: bool = False, online: bool = False) -> str:
    r = Review(g, root, online)
    r.run()
    return r.markdown(for_ai)
