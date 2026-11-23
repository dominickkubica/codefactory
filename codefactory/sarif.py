"""SARIF 2.1.0 output, the format GitHub code scanning, VS Code (SARIF Viewer) and most CI tools read: every issue
shows on its line, in pull requests and in the editor. Also GitHub workflow annotations (`::warning file=…::`), which
appear on pull requests without code scanning.

Results carry stable fingerprints (kind, file, function, not line numbers), so GitHub tracks an alert across edits;
silenced issues are included as suppressed (with the reason), and with a baseline each result says new or unchanged.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

from . import __version__
from .baseline import issue_key
from .checks import scan_sources

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"high": "error", "warn": "warning", "info": "note"}
HOME = "https://github.com/dominickkubica/codefactory"

# rule id -> (name, short description, help, level, tags, security severity)
RULES: dict[str, tuple] = {
    "cycle": ("ImportLoop", "Files import each other in a circle",
              "Move what both sides need into a module that imports neither, or pass the dependency in.", "high", ["maintainability", "architecture"], None),
    "layer_violation": ("LayerViolation", "An import factory.toml forbids",
                        "Move the code into an allowed layer, or invert the dependency.", "high", ["architecture"], None),
    "io_in_loop": ("IoInLoop", "Database, network or file call once per loop iteration",
                   "Load everything the loop needs with one batched query (WHERE id IN (…), a JOIN) or request before "
                   "the loop. Writes: keep them in one transaction, batch if many.", "warn", ["performance"], None),
    "duplicate": ("DuplicateFunction", "Same code in more than one place",
                  "Merge into one function in the lowest layer the callers share; `codefactory plan` lists the steps.", "warn", ["maintainability"], None),
    "similar": ("NearDuplicateFunction", "A copy that was edited afterwards",
                "Compare the copies, fold the differences into parameters, and merge.", "warn", ["maintainability"], None),
    "unused": ("UnusedFunction", "Nothing calls or references this",
               "Search for the name (frameworks may call by name); delete it if unused.", "warn", ["maintainability"], None),
    "test_only": ("TestOnlyFunction", "Only tests call this",
                  "Wire it into the product, move it next to the tests, or delete both.", "info", ["maintainability"], None),
    "quadratic_scan": ("SearchInLoop", "Array search inside a loop (O(n²))",
                       "If the list can grow, build a Map or Set once before the loop.", "info", ["performance"], None),
    "sequential_await": ("AwaitInLoop", "Awaits wait for each round in turn",
                         "If the iterations are independent, run them together (Promise.all / asyncio.gather).", "info", ["performance"], None),
    "hub": ("Hub", "Called from many files", "Change carefully: check callers with `codefactory context`.", "info", ["maintainability"], None),
    "large_file": ("LargeFile", "Very large file", "Split along the responsibilities it holds.", "info", ["maintainability"], None),
    "long_function": ("LongFunction", "Very long function", "Extract the parts that have names of their own.", "info", ["maintainability"], None),
    "secret": ("CredentialInSource", "A credential is written in the source",
               "Rotate it, remove it from the code and history, load it from the environment or a secret store.", "high", ["security"], "9.0"),
    "eval": ("DynamicCodeExecution", "eval / exec / pickle / unsafe YAML",
             "Parse explicitly (JSON, a lookup table); never unpickle or yaml.load untrusted data.", "high", ["security"], "8.1"),
    "shell": ("ShellString", "A shell command built at runtime",
              "Pass arguments as a list without a shell (subprocess.run([...]), execFile/spawn).", "high", ["security"], "8.1"),
    "tls_off": ("TlsVerificationDisabled", "TLS certificate checks turned off",
                "Remove the override; trust a private CA explicitly if needed.", "high", ["security"], "7.4"),
    "sql_built": ("SqlFromStrings", "SQL assembled from strings",
                  "Bind values as parameters; check table or column names against a fixed list where the SQL is built.", "warn", ["security"], "6.5"),
    "raw_html": ("RawHtml", "Raw HTML inserted into a page",
                 "Render as text or sanitize (e.g. DOMPurify) right before inserting.", "warn", ["security"], "6.1"),
    "plain_http": ("PlainHttp", "Plain-HTTP URL", "Use https:// where the host supports it.", "info", ["security"], "4.3"),
    "swallowed": ("SwallowedError", "An error is caught and dropped",
                  "Record it (log, local error file, crash reporting) before recovering; keep empty catches only for "
                  "expected cases, with a comment.", "warn", ["reliability"], None),
    "fetch_no_timeout": ("NoTimeout", "Network call without a timeout",
                         "Give it a deadline (AbortSignal.timeout(ms) / requests' timeout=).", "warn", ["reliability"], None),
    "module_state": ("ModuleState", "Mutable state at module level",
                     "Keep it in an owner with a lifecycle (a store, a context, an instance) and pass it explicitly.", "info", ["reliability"], None),
}


def _rule(rid: str) -> dict:
    name, short, fix, sev, tags, sec = RULES.get(rid, (rid.title().replace("_", ""), f"Saved query: {rid}",
                                                         "See factory.toml [[queries]].", "warn", ["custom"], None))
    props = {"tags": tags, "precision": "medium"}
    if sec:
        props["security-severity"] = sec
    return {"id": rid, "name": name, "shortDescription": {"text": short}, "fullDescription": {"text": f"{short}. {fix}"},
            "help": {"text": fix, "markdown": f"**{short}.** {fix}\n\n[codefactory]({HOME}#what-it-flags)"},
            "helpUri": f"{HOME}#what-it-flags", "defaultConfiguration": {"level": LEVEL[sev]}, "properties": props}


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _loc(file: str, line: int, message: str | None = None, end: int | None = None) -> dict:
    region = {"startLine": max(1, line or 1)}
    if end and end >= region["startLine"]:
        region["endLine"] = end
    loc = {"physicalLocation": {"artifactLocation": {"uri": file, "uriBaseId": "%SRCROOT%"}, "region": region}}
    if message:
        loc["message"] = {"text": message}
    return loc


def build_sarif(graph: dict, root: Path | None = None, new_keys: Counter | None = None, min_level: str = "info") -> dict:
    """graph: from load_graph. root: the repo, to add the source checks (secrets, SQL from strings, …).
    new_keys: issue keys new since the baseline (baselineState); None = no baseline."""
    order = {"high": 0, "warn": 1, "info": 2}
    fns = {f["id"]: f for f in graph["functions"]}
    results, seen, used = [], Counter(), set()

    def add(rule: str, sev: str, message: str, loc: dict, key: str, related=(), suppressed: str | None = None, state=None):
        if order[sev] > order[min_level]:
            return
        seen[key] += 1
        if related:  # GitHub and VS Code turn [text](n) into links to the related locations
            links = ", ".join(f"[{rl['message']['text']}]({i})" for i, rl in enumerate(related, 1) if rl.get("message"))
            message = f"{message} See: {links}." if links else message
        r = {"ruleId": rule, "level": LEVEL[sev], "message": {"text": message}, "locations": [loc],
             "partialFingerprints": {"codefactory/v1": _fp(key, str(seen[key]))}}
        if related:
            r["relatedLocations"] = [dict(rl, id=i) for i, rl in enumerate(related, 1)]
        if suppressed is not None:
            r["suppressions"] = [{"kind": "inSource", "justification": suppressed or "marked as intended"}]
        if state:
            r["baselineState"] = state
        results.append(r)
        used.add(rule)

    new_left = Counter(new_keys) if new_keys is not None else None
    for flags, quiet in ((graph["flags"], False), (graph.get("silenced", []), True)):
        for f in flags:
            fn = fns.get(f["target"])
            file = fn["file"] if fn else f["target"]
            line = f.get("line") or (fn["line"] if fn else 1)
            related = []
            for rid in f.get("related", [])[:10]:
                other = fns.get(rid)
                if other:
                    related.append(_loc(other["file"], other["line"], f"{other['qualname']} ({other['file']}:{other['line']})"))
                elif "/" in rid:
                    related.append(_loc(rid, 1, rid))
            key = issue_key(graph, f, fns)
            state = None
            if new_left is not None and not quiet:
                state = "new" if new_left[key] > 0 else "unchanged"
                if new_left[key] > 0:
                    new_left[key] -= 1
            add(f["kind"], f["severity"], f["message"], _loc(file, line), key, related,
                f.get("reason", "") if quiet else None, state)

    if root is not None:  # line-level source checks (as in the review)
        sev_of = {k: v[3] for k, v in RULES.items()}
        for key, check in scan_sources(root, [f["id"] for f in graph["files"]]).items():
            if key not in RULES:
                continue
            for e in check.hits:
                text = {"sql_built": "SQL built from strings" + (f" (interpolates: {', '.join(check.data.get(e.at(), []))})"
                                                                 if check.data.get(e.at()) else ""),
                        }.get(key, RULES[key][1])
                add(key, sev_of[key], f"{text}: {e.text}", _loc(e.file, e.line), f"{key}|{e.file}|{e.text}")

    return {
        "$schema": SCHEMA, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "codefactory", "version": __version__, "semanticVersion": __version__,
                                "informationUri": HOME, "rules": [_rule(r) for r in sorted(used)]}},
            "automationDetails": {"id": "codefactory/"},
            **({"originalUriBaseIds": {"%SRCROOT%": {"uri": root.resolve().as_uri() + "/"}}} if root is not None else {}),
            "columnKind": "unicodeCodePoints",
            "results": results,
        }],
    }


def github_annotations(graph: dict, flags: list[dict], limit: int = 50) -> str:
    """GitHub Actions workflow commands: each issue becomes an annotation on its line in the pull request."""
    fns = {f["id"]: f for f in graph["functions"]}
    cmd = {"high": "error", "warn": "warning", "info": "notice"}
    out = []
    for f in flags[:limit]:
        fn = fns.get(f["target"])
        file = fn["file"] if fn else f["target"]
        line = f.get("line") or (fn["line"] if fn else 1)
        msg = f["message"].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        title = f"codefactory {f['kind']}".replace(",", " ").replace("::", " ")
        out.append(f"::{cmd[f['severity']]} file={file},line={line},title={title}::{msg}")
    if len(flags) > limit:
        out.append(f"::notice title=codefactory::{len(flags) - limit} more issues not annotated (codefactory flags lists all)")
    return "\n".join(out)
