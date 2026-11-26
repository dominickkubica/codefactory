"""Many repositories at once: a dashboard with each one's health, findings and trend, and findings per owning team.

Each run appends a snapshot to the repository's `.codefactory/history.jsonl` (one per day; a second run the same day
replaces it), so the dashboard can show whether things are getting better. The page is one self-contained HTML file.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import date
from pathlib import Path

SEVS = ("Critical", "High", "Medium", "Low")


def snapshot(root: Path, graph: dict) -> dict:
    from .owners import load as load_owners
    from .review import Review

    r = Review(graph, root)
    r.run()
    grade, _ = r.health()
    owners = load_owners(root)
    per_owner: dict[str, Counter] = {}
    if owners:
        file_of = {fn["id"]: fn["file"] for fn in graph["functions"]}
        for f in graph["flags"]:
            file = file_of.get(f["target"], f["target"])
            for who in owners.of(file):
                per_owner.setdefault(who, Counter())[f["severity"]] += 1
    code = [f for f in graph["files"]]
    return {
        "repo": root.name,
        "profile": r.profile.summary(),
        "path": str(root),
        "date": date.today().isoformat(),
        "grade": grade,
        "findings": {s: sum(1 for f in r.findings if f.severity == s) for s in SEVS},
        "flags": dict(Counter(f["severity"] for f in graph["flags"])),
        "files": len(code),
        "lines": sum(f["loc"] for f in code),
        "languages": graph["language"],
        "endpoints": len(r.surface.entries),
        "open_writes": sum(1 for e, _ in r._writing_entries() if not e.auth) if r.surface.entries else 0,
        "tests_reach": r.test_pct,
        "top": [{"severity": f.severity, "title": f.title} for f in r.findings[:3]],
        "owners": {k: dict(v) for k, v in per_owner.items()},
    }


def record(root: Path, snap: dict) -> list[dict]:
    """Append today's snapshot to the repository's history; return the history (oldest first)."""
    from .paths import cache_dir

    folder = cache_dir(root)
    if folder is None:
        return [{k: snap[k] for k in ("date", "grade", "findings", "flags")}]  # untrusted folder: no history kept
    path = folder / "history.jsonl"
    rows = []
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, ValueError):
        rows = []
    rows = [r for r in rows if r.get("date") != snap["date"]] + [{k: snap[k] for k in ("date", "grade", "findings", "flags")}]
    try:
        path.parent.mkdir(exist_ok=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in rows[-365:]), encoding="utf-8")
    except OSError:
        pass
    return rows


def _spark(history: list[dict]) -> str:
    """Critical + High + Medium findings over time, as a small inline SVG."""
    values = [sum(h["findings"].get(s, 0) for s in SEVS[:3]) for h in history[-30:]]
    if len(values) < 2:
        return ""
    hi = max(values) or 1
    pts = " ".join(f"{i * 80 / (len(values) - 1):.1f},{22 - v * 20 / hi:.1f}" for i, v in enumerate(values))
    return (
        '<svg width="80" height="24" aria-label="trend">'
        f'<polyline fill="none" stroke="currentColor" stroke-width="1.5" points="{pts}"/></svg>'
    )


def _row(s: dict, history: list[dict]) -> str:
    e = html.escape
    f = s["findings"]
    grade_class = "grade-" + s["grade"].lower().replace(" ", "-")
    top = "<br>".join(
        '<span class="sev-' + e(t["severity"].lower()) + '">' + e(t["severity"]) + "</span> " + e(t["title"]) for t in s["top"]
    )
    endpoints = str(s["endpoints"]) + (f" ({s['open_writes']} open writes)" if s["open_writes"] else "")
    reach = "" if s["tests_reach"] is None else f"{s['tests_reach']}%"
    cells = [
        f'<td><b>{e(s["repo"])}</b><div class="muted">{e(s.get("profile", ""))}</div>'
        f'<div class="muted">{e(s["languages"])} · {s["files"]:,} files · {s["lines"]:,} lines</div></td>',
        f'<td class="{grade_class}">{e(s["grade"])}</td>',
        *(f'<td class="num">{f[k]}</td>' for k in SEVS),
        f'<td class="num">{endpoints}</td>',
        f'<td class="num">{reach}</td>',
        f"<td>{_spark(history)}</td>",
        f'<td class="top">{top}</td>',
    ]
    return "<tr>" + "".join(cells) + "</tr>"


def page(snaps: list[dict], histories: dict[str, list[dict]]) -> str:
    from importlib.resources import files

    order = {"At risk": 0, "Fragile": 1, "Adequate": 2, "Strong": 3}
    snaps = sorted(snaps, key=lambda s: (order.get(s["grade"], 9), -s["findings"]["Critical"], -s["findings"]["High"]))
    owners: dict[str, Counter] = {}
    for s in snaps:
        for who, c in s["owners"].items():
            owners.setdefault(who, Counter()).update(c)
    owner_section = ""
    if owners:
        rows = [
            f'<tr><td>{html.escape(who)}</td><td class="num">{c["high"]}</td><td class="num">{c["warn"]}</td>'
            f'<td class="num">{c["info"]}</td></tr>'
            for who, c in sorted(owners.items(), key=lambda kv: (-kv[1]["high"], -kv[1]["warn"]))[:40]
        ]
        owner_section = (
            '<h2>By owner</h2><div class="wrap"><table><thead><tr><th>Owner</th><th class="num">High</th>'
            '<th class="num">Warn</th><th class="num">Info</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"
        )
    template = (files("codefactory") / "viewer" / "dashboard.html").read_text(encoding="utf-8")
    summary = f"{len(snaps)} repositories · {date.today().isoformat()} · worst first"
    return (
        template.replace("__SUMMARY__", summary)
        .replace("__ROWS__", "\n".join(_row(s, histories.get(s["path"], [])) for s in snaps))
        .replace("__OWNERS__", owner_section)
    )
