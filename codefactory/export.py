"""`codefactory export`: every finding as one audit file, for another AI (or a person) to triage into fixes.

The review's findings, with every location (not the first few), each with a stable id, severity, complexity,
confidence, impact, fix and how to verify it, and the plan's ready-made fixes filed under the finding they fix.
Markdown by default (it reads well pasted into Claude), JSON with --json. Opens with instructions for the reader:
"verify each finding, then triage the real ones into individual fixes sorted by severity and complexity".
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import date
from pathlib import Path

from . import __version__

SEVERITIES = ("Critical", "High", "Medium", "Low")
COMPLEXITY = {"S": "under an hour, one place", "M": "a few hours, several places", "L": "a day or more, a design change"}
# how far to trust each finding, from what it rests on (measured on real repositories, not by how precise the rule
# sounds): exact = a fact read from the files; lead = depends on what static reading can't see (callers by name,
# tests through HTTP, guard flags, layer guesses); likely = the rest (a call chain was followed, but not its conditions)
EXACT = re.compile(
    r"(?i)^(?:credentials committed|environment files|sql assembled|no (?:"
    r"automated tests|readme|lockfile)|unpinned|runtime version|readme doesn't|ci doesn't|workflow runs|"
    r"network calls without a timeout|very long functions|dependencies on moving targets)"
)
LEAD = re.compile(
    r"(?i)^(?:endpoints that change data|important code no test reaches|unused code|dependencies against|"
    r"layer rule|copied logic|module-level mutable state)"
)
# plan tasks, by kind -> the finding they fix
TASK_OF = {
    "io_in_loop": r"inside loops", "sequential_await": r"inside loops", "duplicate": r"^Copied logic",
    "similar": r"^Copied logic", "long_function": r"^Very long functions", "unused": r"^Unused code",
    "test_only": r"^Unused code",
}  # fmt: skip
VERIFY = {
    "Security": "Read each location: can the value come from outside (a request, a file, user input)? Is it already "
    "checked or escaped before this line, or by a framework?",
    "Privacy": "Read each location: is this really personal data, and does it leave the device or land in a log?",
    "Reliability": "Read each location: what happens when this fails, and does a caller already handle it?",
    "Performance": "Read each location: can the loop grow with the data (rows, users, files), or is it bounded?",
    "Testing": "Search the tests for each name, including indirect use through other functions.",
    "Delivery": "Open the files named and the CI workflows: is it set up somewhere this check doesn't look?",
}
DEFAULT_VERIFY = "Read each location and confirm the finding says what the code does."
# what settles the main findings, by title (before the area's general question)
VERIFY_BY_TITLE = [
    (
        r"without an auth check",
        "For each endpoint: does it really write on this path (not behind a flag the route turns off, or a first-run "
        "seed that's a no-op later)? Is there an auth, CSRF or host check codefactory didn't recognize (middleware, a "
        "gateway, a custom decorator), or is it meant to be public? What makes the server listen beyond this machine?",
    ),
    (
        r"^Credentials committed|^Environment files committed",
        "Is each value a real credential (not a placeholder or "
        "test fixture)? If real, it must be rotated: removing it from the code doesn't un-leak it.",
    ),
    (
        r"^Request data reaches|^SQL assembled",
        "Follow the value from its source to the call: is it validated, parametrized or escaped on the way?",
    ),
    (
        r"inside loops",
        "Can the loop grow with the data (rows, users, files), or is it bounded by a small fixed list? "
        "Is the call inside a transaction or batch already?",
    ),
    (
        r"^Copied logic",
        "Diff the copies: do they differ on purpose (another platform, a deliberate fork)? Would one "
        "shared function need flags to cover them all?",
    ),
    (r"^Very long functions", "Is the length logic, or data (a table, a mapping, generated code) that reads fine long?"),
    (r"^Unused code", "Search for each name, including strings and config: frameworks and plugins call code by name."),
    (
        r"no test reaches",
        "Search the tests for each name and its route (tests often call handlers through an HTTP "
        "client by URL, which static reading doesn't link to the handler); a measured coverage report settles it.",
    ),
]

INSTRUCTIONS = """You are triaging a static-analysis audit of this repository. For every finding below:

1. **Verify it.** Open each cited location and decide: *Confirmed*, *False positive* (say why), or *Needs context*
   (say what would settle it). Findings marked **lead** often aren't real: confirm before acting on them.
2. **Triage the confirmed ones into individual fixes.** One fix = one change a person can review on its own; it may
   cover several locations of one finding, or one location may need its own fix. Reuse the *ready-made fixes* listed
   under a finding where they fit.
3. **Sort the fixes by severity, then complexity** (S before M before L). Re-rank severity if what you know about
   the product (who uses it, what data it holds) differs from the profile below, and say why.
4. **For each fix give:** title, finding id(s), files, the change, the tests to run, and its risk.

Don't change code while triaging: the output is the list of fixes."""


def _git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _id(f) -> str:
    """Stable across runs: the area and the title without its counts ("…in 12 places" stays the same finding)."""
    stem = re.sub(r"\s*\([^)]*\)|\b\d[\d,]*\b", "", f.title).strip().lower()
    return f"CF-{f.area[:4].upper()}-{hashlib.sha1(stem.encode()).hexdigest()[:4]}"


LOC = re.compile(r"`([^`\s]+):(\d+)`")


def _covers(task: dict, evidence: list[str]) -> bool:
    """A task belongs to a finding only where they point at the same code (the plan's long-function tasks start at
    60 lines, the finding at 80: those under 80 aren't this finding's)."""
    cited = {(m.group(1), m.group(2)) for e in evidence for m in LOC.finditer(e)}
    return not cited or any((w["file"], str(w["line"])) in cited for w in task.get("where", []))


def _located(root: Path, evidence: str, cache: dict) -> str:
    """The evidence with its line of code (when it doesn't show it already), and whether it's a script or a test."""
    from .paths import is_script, is_test

    m = LOC.match(evidence)
    if not m:
        return evidence
    file, line = m.group(1), int(m.group(2))
    if file not in cache:
        try:
            cache[file] = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[file] = []
    tag = " *(test)*" if is_test(file) else " *(script)*" if is_script(file) else ""
    from .checks import redact

    src = redact(cache[file][line - 1].strip()) if 0 < line <= len(cache[file]) else ""
    if not src or src[:40] in evidence:
        return evidence + tag  # (the evidence already shows the line)
    src = src if len(src) <= 160 else src[:157] + "…"
    fence = "``" if "`" in src else "`"
    return f"{evidence}{tag} — {fence}{src}{fence}"


def _finding_of(task: dict) -> str:
    """The finding title a plan task fixes. Loop tasks split by what's in the loop: reads go with the N+1 finding,
    writes and file work with theirs."""
    if task.get("kind") == "io_in_loop":
        return (
            r"^Queries or requests inside loops"
            if task["title"].startswith("Batch the queries")
            else (r"^(?:Writes|File or program operations) inside loops")
        )
    return TASK_OF.get(task.get("kind", ""), "")


def _verify(f) -> str:
    return next((v for rx, v in VERIFY_BY_TITLE if re.search(rx, f.title)), VERIFY.get(f.area, DEFAULT_VERIFY))


def build(r, graph: dict, root: Path) -> dict:
    """The audit as data, from a Review run with full=True."""
    tasks = getattr(r, "tasks", [])
    findings, filed, code = [], set(), {}
    order = sorted(r.findings, key=lambda f: (SEVERITIES.index(f.severity), "SML".find(f.effort or "M"), f.title))
    for f in order:
        mine = [
            t
            for t in tasks
            if (rx := _finding_of(t)) and re.search(rx, f.title) and t["id"] not in filed and _covers(t, f.evidence)
        ]
        filed |= {t["id"] for t in mine}
        findings.append({
            "id": _id(f), "severity": f.severity, "complexity": f.effort or "M", "area": f.area,
            "confidence": "exact" if EXACT.search(f.title) else "lead" if LEAD.search(f.title) else "likely",
            "title": f.title, "locations": [_located(root, e, code) for e in f.evidence] + [f"…and {f.more} more"] * bool(f.more),
            "impact": f.impact,
            "fix": f.fix, "verify": _verify(f), "ranked": f.data.get("ranked"),
            "fixes": [_task(t) for t in mine],
        })  # fmt: skip
    files = [x for x in graph["files"]]
    return {
        "tool": f"codefactory {__version__}", "repository": root.name, "date": date.today().isoformat(),
        "commit": _git(root, "rev-parse", "--short", "HEAD"), "branch": _git(root, "branch", "--show-current"),
        "uncommitted": bool(_git(root, "status", "--porcelain")), "profile": r.profile.summary(),
        "scope": {"files": len(files), "lines": sum(x["loc"] for x in files), "languages": graph.get("language", "")},
        "limits": r.limits(), "findings": findings,
        "hints": [{"title": f.title, "severity": f.severity, "area": f.area,
                   "locations": [_located(root, e, code) for e in f.evidence]} for f in getattr(r, "hints", [])],
        "other_fixes": [_task(t) for t in tasks if t["id"] not in filed],
    }  # fmt: skip


def _task(t: dict) -> dict:
    return {"task": t["id"], "title": t["title"], "where": [f"{w['file']}:{w['line']}" for w in t.get("where", [])],
            "steps": t.get("steps", []), "tests": t.get("tests", [])}  # fmt: skip


def markdown(doc: dict) -> str:
    fs = doc["findings"]
    counts = ", ".join(f"{sum(f['severity'] == s for f in fs)} {s}" for s in SEVERITIES)
    commit = (
        doc["commit"]
        + (f" ({doc['branch']})" if doc["branch"] else "")
        + (", with uncommitted changes" if doc["uncommitted"] else "")
    )
    out = [f"# Code audit: {doc['repository']}", "", "| | |", "|---|---|", f"| Commit | `{commit or 'not a git repository'}` |",
           f"| Date | {doc['date']} |", f"| Produced by | {doc['tool']}: static analysis, no code was run, no AI |",
           f"| Project | {doc['profile']} |",
           f"| Scope | {doc['scope']['files']:,} files, {doc['scope']['lines']:,} lines ({doc['scope']['languages']}) |",
           f"| Findings | {len(fs)}: {counts} |", "", "## Instructions for the reader", "", INSTRUCTIONS, "",
           "## How to read a finding", "",
           "- **Severity**: Critical, High, Medium, Low, ranked for the project above (re-ranks are noted with why).",
           "- **Complexity**: " + "; ".join(f"**{k}** {v}" for k, v in COMPLEXITY.items()) + ".",
           "- **Confidence**: **exact** = a fact read from the files (a key, a missing CI file); **likely** = a call chain "
           "was followed, but not the conditions on it (a guard flag, a loop bound); **lead** = rests on what static "
           "reading can't see (callers by name, tests through HTTP, auth done elsewhere): expect false positives.",
           "- Locations marked *(script)* or *(test)* aren't shipped code: weigh them lower.", "", "## Summary", "",
           "| ID | Severity | Complexity | Area | Confidence | Finding |", "|---|---|---|---|---|---|"]  # fmt: skip
    out += [f"| {f['id']} | {f['severity']} | {f['complexity']} | {f['area']} | {f['confidence']} | {f['title']} |" for f in fs]
    out += ["", "## Findings", ""]
    for f in fs:
        out += [f"### {f['id']} · {f['severity']} · {f['complexity']} · {f['title']}", "",
                f"**Area:** {f['area']} · **Confidence:** {f['confidence']}", "", "**Where:**", ""]  # fmt: skip
        out += [f"- {loc}" for loc in f["locations"]] or ["- (the repository as a whole)"]
        out += ["", f"**Impact:** {f['impact']}", "", f"**Suggested fix:** {f['fix']}", "", f"**Verify:** {f['verify']}"]
        if f["ranked"]:
            out += ["", f"**Ranked {f['severity']} for this project** (default {f['ranked']['from']}): {f['ranked']['why']}"]
        if f["fixes"]:
            out += [
                "",
                f"**Ready-made fixes ({len(f['fixes'])})** — `codefactory prompt <task>` prints one with its steps and tests:",
                "",
            ]
            out += [_task_md(t) for t in f["fixes"]]
        out.append("")
    if doc.get("hints"):
        out += [
            "## Hints",
            "",
            "Not findings: checks that are right less than half the time on real code, because the "
            "answer depends on what the code doesn't show (how big a list gets, whether a file deploys). Glance, don't "
            "triage.",
            "",
        ]
        out += [f"- **{h['title']}**: " + "; ".join(h["locations"][:5]) for h in doc["hints"]] + [""]
    if doc["other_fixes"]:
        out += ["## Other ready-made fixes", ""] + [_task_md(t) for t in doc["other_fixes"]] + [""]
    out += ["## What this audit didn't check", ""] + [f"- {x}" for x in doc["limits"]]
    return "\n".join(out) + "\n"


def _task_md(t: dict) -> str:
    where = ", ".join(f"`{w}`" for w in t["where"][:3]) + (f" +{len(t['where']) - 3}" if len(t["where"]) > 3 else "")
    return f"- `{t['task']}` {t['title']}: {where}"


def export(graph: dict, root: Path, as_json: bool = False, online: bool = False) -> str:
    from .review import Review

    r = Review(graph, root, online, full=True)
    r.run()
    doc = build(r, graph, root)
    return json.dumps(doc, indent=1) + "\n" if as_json else markdown(doc)
