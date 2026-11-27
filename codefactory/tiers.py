"""Confidence tiers within a check: the locations a check gets right less often move to a hint of the same title.

A check is right more often for some of its locations than others, and the location text says which (whether a
request reaches the line, what's interpolated). Each rule here was read off the labeled corpus (docs/ACCURACY.md):
the locations it matches were right clearly less often than the rest. They stay listed, as a hint, so nothing is
hidden; the finding keeps the ones worth acting on, and the grade counts only those.
"""

from __future__ import annotations

import re
from dataclasses import replace

# check title (prefix) -> a location that is lower confidence
LOWER = {
    # 7 of 18 right when the project has endpoints and none reaches the line (library helpers, admin-only views);
    # 11 of 17 otherwise
    "Raw HTML injected into pages": lambda loc: "(no endpoint reaches it)" in loc,
    # a flow in a script, test or dev setup (a local proxy, a seed script) isn't the product's attack surface
    "Request data reaches dangerous calls": lambda loc: re.search(r"\*\((?:script|test|dev)\b", loc) is not None,
    # a command a script or a tool runs (a formatter over a fixed path, a theme generator): dev tooling
    "Shell commands built at runtime": lambda loc: re.search(r"\*\((?:script|test|dev)\b", loc) is not None,
}
DOWN = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Low", "Info": "Info"}


def _lower(title: str, loc: str) -> bool:
    if "*(test)*" in loc and title.split(" (")[0] in SECURITY_TITLES:
        return True  # (a test module's manifest, a mocked key: shown for context, not the product's exposure)
    rule = next((r for t, r in LOWER.items() if title.startswith(t)), None)
    return bool(rule and rule(loc))


SECURITY_TITLES = {"App allows unencrypted HTTP", "Credentials committed in source", "Credentials in configuration files",
                   "Session cookies without Secure / HttpOnly", "TLS certificate checks turned off",
                   "Any website may call this API", "MD5 / SHA-1 used for security"}  # fmt: skip


def split(findings: list) -> tuple[list, list]:
    """(findings with their lower-confidence locations taken out, hints holding those locations). Exact in the export,
    which lists every location; in the short report the split covers the locations shown."""
    keep, lower = [], []
    for f in findings:
        low = [e for e in f.evidence if _lower(f.title, e)]
        if len(low) < len(f.evidence) or f.more:
            keep.append(replace(f, evidence=[e for e in f.evidence if e not in low]) if low else f)
        if low:
            hint = replace(f, evidence=low, more=0, severity=DOWN.get(f.severity, f.severity))
            hint.data = {**f.data, "tier": "lower"}
            lower.append(hint)
    return keep, lower
