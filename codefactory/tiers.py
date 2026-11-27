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
}
DOWN = {"Critical": "High", "High": "Medium", "Medium": "Low", "Low": "Low", "Info": "Info"}


def split(findings: list) -> tuple[list, list]:
    """(findings with their lower-confidence locations taken out, hints holding those locations). Exact in the export,
    which lists every location; in the short report the split covers the locations shown."""
    keep, lower = [], []
    for f in findings:
        rule = next((r for title, r in LOWER.items() if f.title.startswith(title)), None)
        low = [e for e in f.evidence if rule(e)] if rule else []
        if len(low) < len(f.evidence) or f.more:
            keep.append(replace(f, evidence=[e for e in f.evidence if e not in low]) if low else f)
        if low:
            hint = replace(f, evidence=low, more=0, severity=DOWN.get(f.severity, f.severity))
            hint.data = {**f.data, "tier": "lower"}
            lower.append(hint)
    return keep, lower
