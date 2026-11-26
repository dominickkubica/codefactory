"""Where change happens, from git history: the code that is both complex and changed often (hotspots), files that
change together without importing each other (hidden coupling), and code only one person changes.

The idea is behavioural code analysis (Adam Tornhill's "Your Code as a Crime Scene"): of all the debt in a codebase,
the part that costs money is the part people keep working in. A long function nobody has touched in two years is a
curiosity; one changed every week is where bugs and slow reviews come from. Findings in hotspots are ranked first.

One `git log` over the last 12 months (at most 5,000 commits, 60 seconds), read once per review. Merges and commits
touching more than 50 files (formatting, renames, vendoring) don't count. Bots (Dependabot, Renovate…) count as
changes but not as people, so "only one person changes this" isn't fooled by them. An AI assistant's commits count
for whoever commits under that name: someone drove them.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .paths import is_test

MONTHS = 12
MAX_COMMITS = 5000
BIG_COMMIT = 50  # files: past this a commit is a sweep (formatting, renames), not a change to the code's behaviour
BOTS = re.compile(r"\[bot\]|dependabot|renovate|github-actions|pre-commit-ci|snyk-bot|greenkeeper", re.I)


@dataclass
class FileHistory:
    path: str
    commits: int = 0
    recent: int = 0  # commits in the last 3 months
    churn: int = 0  # lines added + deleted
    authors: Counter = field(default_factory=Counter)  # person -> commits (bots excluded)
    last: int = 0  # epoch seconds


@dataclass
class History:
    files: dict[str, FileHistory] = field(default_factory=dict)
    pairs: Counter = field(default_factory=Counter)  # (a, b) -> commits changing both
    commits: int = 0
    people: Counter = field(default_factory=Counter)
    first: int = 0
    last: int = 0
    note: str = ""  # why history is missing or partial


@dataclass
class Hotspot:
    path: str
    commits: int
    recent: int
    churn: int
    complexity: int  # decision points in the file's functions
    loc: int
    score: float  # 0-1: change frequency x complexity, relative to this repository
    top_author_share: float
    people: int


@dataclass
class Coupling:
    a: str
    b: str
    together: int
    share: float  # of the less-changed file's commits, how many also changed the other
    linked: bool  # one imports the other


def _person(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def read(root: Path, months: int = MONTHS, max_commits: int = MAX_COMMITS, timeout: int = 60) -> History:
    """The history, from a cache keyed by the HEAD commit (the log only changes when HEAD does), else from git."""
    try:
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD", "--show-prefix"], capture_output=True,
                              text=True, timeout=10).stdout.split()  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        head = []
    key = f"{'/'.join(head)}|{months}|{max_commits}|{time.strftime('%Y-%m-%d')}" if head else ""  # a day later, the window moves
    from .paths import cache_dir

    folder = cache_dir(root)
    key = key if folder else ""  # an untrusted cache folder: read git each time
    path = folder / "history.json" if folder else None
    if key:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("key") == key:
                return _from_json(data["history"])
        except (OSError, ValueError, KeyError, TypeError):
            pass
    h = _read(root, months, max_commits, timeout)
    if key and h.commits:
        try:
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"key": key, "history": _to_json(h)}), encoding="utf-8")
        except OSError:
            pass  # read-only checkout
    return h


def _to_json(h: History) -> dict:
    return {"files": {p: [f.commits, f.recent, f.churn, dict(f.authors), f.last] for p, f in h.files.items()},
            "pairs": [[a, b, n] for (a, b), n in h.pairs.items()], "commits": h.commits, "people": dict(h.people),
            "first": h.first, "last": h.last, "note": h.note}  # fmt: skip


def _from_json(d: dict) -> History:
    h = History(commits=d["commits"], people=Counter(d["people"]), first=d["first"], last=d["last"], note=d["note"])
    h.files = {p: FileHistory(p, c, r, ch, Counter(a), last) for p, (c, r, ch, a, last) in d["files"].items()}
    h.pairs = Counter({(a, b): n for a, b, n in d["pairs"]})
    return h


def _read(root: Path, months: int, max_commits: int, timeout: int) -> History:
    h = History()
    git = ["git", "-C", str(root)]
    try:
        inside = subprocess.run([*git, "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True, timeout=10)
        if inside.stdout.strip() != "true":
            h.note = "not a git repository: no history to read"
            return h
        if subprocess.run([*git, "rev-parse", "--is-shallow-repository"], capture_output=True, text=True,
                          timeout=10).stdout.strip() == "true":  # fmt: skip
            # partial only if the clone stops inside the window (`--shallow-since` older than it is complete enough)
            oldest = subprocess.run([*git, "log", "--reverse", "--format=%at", "--max-parents=0"], capture_output=True,
                                    text=True, timeout=30).stdout.split()  # fmt: skip
            if not oldest or int(oldest[0]) > time.time() - months * 30.5 * 86400:
                h.note = "a shallow clone (CI checks out one commit by default): history is partial; `fetch-depth: 0` reads all"
        proc = subprocess.run(
            [*git, "log", "--no-merges", "--no-renames", "--numstat", f"--since={months}.months", f"-n{max_commits}",
             "--format=%x1e%aN%x1f%at", "--relative", "--", "."],  # this folder's history, its paths relative to it
            capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
        )  # fmt: skip
    except (OSError, subprocess.SubprocessError):
        h.note = "git isn't available or took too long: history not read"
        return h
    recent_cut = time.time() - 90 * 86400
    for block in proc.stdout.split("\x1e")[1:]:
        head, _, body = block.partition("\n")
        name, _, ts = head.partition("\x1f")
        try:
            when = int(ts)
        except ValueError:
            continue
        changed = []
        for line in body.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                added, deleted, path = parts
                lines = (int(added) if added.isdigit() else 0) + (int(deleted) if deleted.isdigit() else 0)
                changed.append((path, lines))
        if not changed or len(changed) > BIG_COMMIT:
            continue
        h.commits += 1
        h.first = min(h.first or when, when)
        h.last = max(h.last, when)
        person = None if BOTS.search(name) else _person(name)
        if person:
            h.people[person] += 1
        for path, lines in changed:
            fh = h.files.setdefault(path, FileHistory(path))
            fh.commits += 1
            fh.churn += lines
            fh.recent += when >= recent_cut
            fh.last = max(fh.last, when)
            if person:
                fh.authors[person] += 1
        paths = sorted({p for p, _ in changed})
        if 2 <= len(paths) <= 30:
            for i, a in enumerate(paths):
                for b in paths[i + 1 :]:
                    h.pairs[(a, b)] += 1
    if h.commits >= max_commits:
        h.note = h.note or f"read the latest {max_commits:,} commits only"
    return h


GENERATED = re.compile(
    r"(?:^|[/_.-])generated[_.-]|(?:^|/)(?:vendor|vendored|third_party|external)/|"
    r"(?:^|/)(?:jquery|datatables|bootstrap|lodash|moment|chart|d3|highlight)(?:[.-][\w.-]*)?\.js$|"
    r"(?:^|/)(?:generated|__generated__|gen)/|\.(?:gen|generated|g|pb|pb\.gw)\.\w+$|_pb2(?:_grpc)?\.py$|\.pb\.go$|"
    r"(?:^|/)(?:openapi|swagger)[\w.-]*\.(?:ts|js|py)$|\.min\.js$"
)


def generated(path: str) -> bool:
    """Made by a tool: it changes when its source does, and nobody untangles it by hand."""
    return bool(GENERATED.search(path))


def hotspots(h: History, g: dict, limit: int = 10) -> list[Hotspot]:
    """Source files that are both complex and changed often, most costly first."""
    code = {f["id"]: f for f in g["files"] if not is_test(f["id"])}
    complexity: Counter = Counter()
    for fn in g["functions"]:
        if fn["file"] in code and fn["kind"] != "module":
            complexity[fn["file"]] += max(1, fn.get("branches", 0))
    rows = [(path, fh) for path, fh in h.files.items() if path in code and fh.commits >= 3 and not generated(path)]
    if not rows:
        return []
    top_commits = max(fh.commits for _, fh in rows)
    top_complexity = max((complexity[p] or code[p]["loc"] // 10 or 1) for p, _ in rows)
    out = []
    for path, fh in rows:
        cx = complexity[path] or code[path]["loc"] // 10 or 1
        score = (fh.commits / top_commits) * (cx / top_complexity)
        total = sum(fh.authors.values())
        out.append(Hotspot(path, fh.commits, fh.recent, fh.churn, cx, code[path]["loc"], round(score, 3),
                           (fh.authors.most_common(1)[0][1] / total) if total else 0.0, len(fh.authors)))  # fmt: skip
    out.sort(key=lambda x: (-x.score, -x.commits))
    return [x for x in out if x.score >= 0.05][:limit]


PACKAGE_LANGS = (".go", ".kt", ".java", ".scala", ".swift", ".cs", ".rs")  # .rs: sibling modules of one crate
# translations change together by design: adding a string touches every language
TRANSLATIONS = re.compile(r"(?:^|/)(?:i18n|l10n|locales?|translations?|lang)/", re.I)


def _same_package(a: str, b: str) -> bool:
    """Go, Kotlin, Java, Swift… files in one folder share a package (or module) and use each other without imports."""
    return a.rsplit("/", 1)[0] == b.rsplit("/", 1)[0] and a.endswith(PACKAGE_LANGS) and b.endswith(PACKAGE_LANGS)


def coupling(h: History, g: dict, limit: int = 8) -> list[Coupling]:
    """Pairs of files that keep changing in the same commits. Those with no import between them are hidden coupling:
    a change in one needs a change in the other, and nothing in the code says so."""
    from .checks import SRC_EXT

    known = {f["id"] for f in g["files"]} | {p for p in h.files if p.endswith(SRC_EXT)}  # parsed or not
    imports = set()
    file_of = {fn["id"]: fn["file"] for fn in g["functions"]}
    for e in g["edges"]:
        a, b = file_of.get(e["src"], e["src"]), file_of.get(e["dst"], e["dst"])
        if a != b:
            imports.add((a, b))
            imports.add((b, a))
    loc = {f["id"]: f["loc"] for f in g["files"]}
    magnets = {p for p, fh in h.files.items() if fh.commits >= max(6, h.commits // 2) or loc.get(p, 99) <= 15}
    out = []
    for (a, b), together in h.pairs.items():
        if together < 4 or a not in known or b not in known:
            continue
        if (is_test(a) or is_test(b) or a in magnets or b in magnets or generated(a) or generated(b)
                or TRANSLATIONS.search(a) or TRANSLATIONS.search(b)):  # fmt: skip
            continue  # tests change with their code by design; version files change with everything
        fewer = min(h.files[a].commits, h.files[b].commits)
        share = together / fewer if fewer else 0
        if share >= 0.6:
            out.append(Coupling(a, b, together, round(share, 2), (a, b) in imports or _same_package(a, b)))
    out.sort(key=lambda c: (c.linked, -c.together, -c.share))
    return out[:limit]


def knowledge(h: History, g: dict, limit: int = 8) -> list[tuple[str, str, float, int]]:
    """Busy files almost only one person changes: (path, person, share, commits). Only meaningful with a team."""
    if len([p for p, n in h.people.items() if n >= 3]) < 3:
        return []
    code = {f["id"] for f in g["files"] if not is_test(f["id"])}
    out = []
    for path, fh in h.files.items():
        total = sum(fh.authors.values())
        if path in code and total >= 6:
            person, n = fh.authors.most_common(1)[0]
            if n / total >= 0.85:
                out.append((path, person, round(n / total, 2), total))
    return sorted(out, key=lambda x: -x[3])[:limit]


@dataclass
class Summary:
    history: History
    hot: list[Hotspot]
    coupled: list[Coupling]
    owners: list[tuple[str, str, float, int]]

    def by_path(self) -> dict[str, Hotspot]:
        return {x.path: x for x in self.hot}


def analyze(root: Path, g: dict) -> Summary:
    h = read(root)
    return Summary(h, hotspots(h, g), coupling(h, g), knowledge(h, g))


FRONT = (".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".mjs", ".dart", ".swift", ".kt")


def _side(path: str) -> str:
    """Which side of an API a file is on, roughly: browser/app code, or everything else (the server)."""
    return "front" if path.endswith(FRONT) and not re.search(r"(?:^|/)(?:server|api|backend|functions)/", path) else "back"


def _span(h: History) -> str:
    if not h.commits:
        return ""
    return f"{time.strftime('%Y-%m-%d', time.gmtime(h.first))} to {time.strftime('%Y-%m-%d', time.gmtime(h.last))}"


def markdown(s: Summary, findings_by_file: dict[str, list[str]] | None = None) -> list[str]:
    h = s.history
    if not h.commits:
        return [f"No history read ({h.note or 'no commits in the last 12 months'}).", ""]
    people = len(h.people)
    out = [
        f"From {h.commits:,} commits ({_span(h)}, {people} {'person' if people == 1 else 'people'}"
        + (f"; {h.note}" if h.note else "")
        + "). A hotspot is code that is both complex and changed often: of all the debt here, it's the part that costs "
        "time every week.",
        "",
    ]
    findings_by_file = findings_by_file or {}
    if s.hot:
        out += ["| Hotspot | Changes (last 3 months) | Lines changed | Complexity | Findings here |", "|---|--:|--:|--:|---|"]
        for x in s.hot:
            found = findings_by_file.get(x.path, [])
            out.append(
                f"| `{x.path}` | {x.commits} ({x.recent}) | {x.churn:,} | {x.complexity} | "
                f"{', '.join(found[:3]) + (f' +{len(found) - 3}' if len(found) > 3 else '') if found else '-'} |"
            )
        out.append("")
    else:
        out += ["No hotspots: no file is both complex and changed often.", ""]
    hidden = [c for c in s.coupled if not c.linked]
    if hidden:
        out += ["**Change together, but neither imports the other** (a change in one needs the other, and nothing says so):", ""]
        out += [f"- `{c.a}` + `{c.b}`: {c.together} commits together ({c.share:.0%} of the rarer one's)" for c in hidden[:6]]
        if any(_side(c.a) != _side(c.b) for c in hidden[:6]):
            out.append(
                "- Front-end and back-end files move together: a contract kept by hand. Generating the client (or its "
                "types) from the API's schema (OpenAPI, GraphQL, a shared types package) makes a broken change fail the "
                "build instead of a user's screen."
            )
        out.append("")
    if s.owners:
        out += [
            "**Busy code only one person changes** (context about the team, not a problem in the code: if they're "
            "away, nobody else has worked in it):",
            "",
        ]
        out += [f"- `{p}`: {share:.0%} of {n} changes by {who}" for p, who, share, n in s.owners]
        out.append("")
    elif people == 1:
        out += ["One person makes every change, so who-knows-what isn't measured.", ""]
    return out
