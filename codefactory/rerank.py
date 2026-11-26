"""Ranking findings for the project they're in: the same line means different things in a local-first app, a public
API and a command-line tool.

Each rule names the findings it applies to (by title), the projects it applies to (a test on the profile), the
severity they get, and why, in words a reader can check. A finding changed by a rule says so in the review, with the
old severity and the reason; nothing is hidden. Rules only move a finding one step at a time in the direction they
name: an upgrade never lowers a finding that's already above it, and a downgrade never raises one.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .profile import Profile

SEV = ["Critical", "High", "Medium", "Low"]
HEAVY = ("health and fitness", "financial", "accounts and passwords")  # data that law and app stores treat as special
WRITE_WORDS = re.compile(r"runAsync|execAsync|executemany|INSERT|UPDATE|DELETE|\b(?:save|write|insert|update|delete)\w*\(?")


@dataclass(frozen=True)
class Rule:
    title: str  # a regular expression matched against the finding's title
    applies: Callable[[Profile], bool]
    to: str  # the severity it gets
    why: Callable[[Profile], str]
    evidence: str = ""  # optionally, a regular expression one of its evidence lines must match


def _heavy(p: Profile) -> list[str]:
    return [c for c in HEAVY if c in p.sensitive]


def _special(p: Profile) -> list[str]:
    """Health and financial data: special under GDPR, HIPAA, PCI. An app that merely has passwords isn't."""
    return [c for c in ("health and fitness", "financial") if c in p.sensitive]


def _data(p: Profile) -> str:
    cats = _heavy(p)
    return cats[0] if len(cats) == 1 else ", ".join(cats[:-1]) + " and " + cats[-1]


RULES = [
    # ---- local-first, one user: no attacker on the other end of a request
    Rule(
        r"^SQL assembled from strings", lambda p: p.local_first and p.single_user and not p.server, "Low",
        lambda p: "a local-first app with one user and no server: only what the user types or imports, or what the app "
        "itself fetches, can reach these queries. Still worth binding, but not an attack surface.",
    ),
    Rule(
        r"^Debug mode switched on in code", lambda p: p.deployment in ("user's machine", "local server"), "Low",
        lambda p: f"it runs on the user's own machine ({p.deployment}): a debug page shows the code to the person who "
        "already has it.",
    ),
    Rule(
        r"^Request data reaches dangerous calls", lambda p: p.deployment == "local server", "High",
        lambda p: "the server listens only on this machine: whoever can send it requests can already run code here. "
        "It becomes critical the day it listens on a network.",
    ),
    Rule(
        r"^(?:Shell commands built at runtime|Dynamic code execution)",
        lambda p: p.kind in ("command-line tool", "data pipeline") and not p.server, "Medium",
        lambda p: f"a {p.kind} runs with its user's own rights: this matters when it processes files or text "
        "from someone else (downloads, other people's repositories), not for the user's own input.",
    ),
    Rule(
        r"^Network calls without a timeout", lambda p: p.kind == "command-line tool" and not p.server, "Low",
        lambda p: "a command-line tool has someone watching: a hang is seen and stopped. It matters more if it runs "
        "unattended (cron, CI).",
    ),
    # ---- mobile: the platform's rules
    Rule(
        r"^Plain-HTTP URLs in code", lambda p: p.kind == "mobile app", "Medium",
        lambda p: "iOS (App Transport Security) and Android 9+ block plain HTTP by default: these requests fail in "
        "release builds unless an exception is configured, and with one they can be read on public Wi-Fi.",
    ),
    Rule(
        r"^No error boundary around the UI", lambda p: p.kind == "mobile app", "High",
        lambda p: "on a phone, an uncaught rendering error closes the screen or the app, and the user loses what they "
        "were in the middle of.",
    ),
    Rule(
        r"^App allows unencrypted HTTP", lambda p: bool(_heavy(p)), "High",
        lambda p: f"the app holds {_data(p)} data, and an exception to encrypted traffic lets it travel in the clear.",
    ),
    # ---- special data: the law and the app stores ask for more
    Rule(
        r"^Personal data sent to analytics or crash reporting", lambda p: "health and fitness" in p.sensitive, "Critical",
        lambda p: "the app holds health and fitness data: sending it to a third party can need explicit consent "
        "(GDPR special category) and, in the US, can be a reportable breach (FTC Health Breach Notification Rule).",
    ),
    Rule(
        r"^Personal data (?:written to logs|in unencrypted storage)", lambda p: bool(_special(p)), "High",
        lambda p: f"the app holds {', '.join(_special(p))} data, which privacy law treats as a special category and the "
        "app stores as needing the most care; logs and plain storage end up in backups, crash reports and support tickets.",
    ),
    Rule(
        r"^Important code no test reaches", lambda p: p.local_first, "High",
        lambda p: "local-first: the device holds the only copy of the user's data, so an untested write that goes wrong "
        "can't be restored from a server.",
        evidence=WRITE_WORDS.pattern,
    ),
    # ---- servers: who can reach them
    Rule(
        r"^Endpoints that change data without an auth check", lambda p: p.deployment == "deployed server", "High",
        lambda p: "it's set up to be deployed (" + ", ".join(e.split(" (")[0] for e in p.deployment_evidence[:2]) + "), "
        "so it runs where others can reach it, whatever address it listens on locally.",
    ),
    Rule(
        r"^Any website may call this API \(CORS \*\)",
        lambda p: p.deployment in ("local server", "LAN server") and p.open_writes > 0, "High",
        lambda p: "a server on this machine or network that allows every origin can be driven by any web page the user "
        f"opens, and {p.open_writes} of its endpoints change data without checking who's asking.",
    ),
    Rule(
        r"^Session cookies without Secure / HttpOnly", lambda p: p.users == "multi-user" and p.reachable_by_others, "High",
        lambda p: "it has user accounts and others can reach it: a session cookie read by a script or sent over plain "
        "HTTP is someone's account.",
    ),
]  # fmt: skip


@dataclass
class Change:
    title: str
    before: str
    after: str
    why: str


def rerank(findings: list, profile: Profile) -> list[Change]:
    """Re-rank the review's findings in place for this profile; return what changed."""
    changes = []
    for f in findings:
        for rule in RULES:
            if not re.search(rule.title, f.title) or not rule.applies(profile):
                continue
            if rule.evidence and not any(re.search(rule.evidence, e) for e in f.evidence):
                continue
            before, after = f.severity, rule.to
            if before == after:
                continue
            why = rule.why(profile)
            f.severity = after
            f.data["ranked"] = {"from": before, "why": why}
            changes.append(Change(f.title, before, after, why))
            break  # one rule per finding: the first that fits is the most specific
    return changes


def markdown(changes: list[Change]) -> list[str]:
    if not changes:
        return ["Nothing re-ranked: every finding keeps its default severity for this kind of project.", ""]
    out = ["| Finding | Default | For this project | Why |", "|---|---|---|---|"]
    for c in changes:
        arrow = "↑" if SEV.index(c.after) < SEV.index(c.before) else "↓"
        out.append(f"| {c.title} | {c.before} | {arrow} **{c.after}** | {c.why} |")
    return out + [""]
