"""What a published JavaScript / TypeScript package hands its users: the exports reachable from its entry points.

A function exported from `@immich/sdk` or `svelte/easing` has no caller in its own repository, and isn't unused:
its callers are the package's users. A package counts as published when its package.json has a name and isn't
`"private": true`; its public API is what its entry files export, followed through `export * from` and
`export { name } from`. A function exported from a file the entry doesn't re-export is still internal.
"""

from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path

SOURCE_EXT = (".ts", ".tsx", ".mts", ".js", ".mjs", ".jsx")
BUILT = re.compile(r"^(?:build|dist|lib|out|types|esm|cjs)/")
REEXPORT = re.compile(r"""export\s+(\*|\{[^}]*\})\s+from\s+['"](\.[^'"]+)['"]""")


def published_api(root: str, files: set[str]) -> tuple[set[str], set[tuple[str, str]]]:
    """(files whose every export is public, (file, name) pairs re-exported by name)."""
    whole: set[str] = set()
    named: set[tuple[str, str]] = set()
    for pkg in sorted(f for f in _package_jsons(root, files)):
        base = posixpath.dirname(pkg)
        try:
            meta = json.loads((Path(root) / pkg).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(meta, dict) or meta.get("private") is True or not meta.get("name"):
            continue
        targets = [v for k in ("exports", "main", "module", "browser", "types") for v in _strings(meta.get(k))]
        entries = {e for t in targets if (e := _source_of(base, t, files))}
        entries |= {e for e in (_resolve(base, "./src/index", files), _resolve(base, "./index", files)) if e}
        _follow(root, entries, files, whole, named)
    return whole, named


def _package_jsons(root: str, files: set[str]) -> set[str]:
    dirs = {posixpath.dirname(f) for f in files}
    out = set()
    for d in dirs:
        while True:
            if (Path(root) / d / "package.json").is_file():
                out.add(posixpath.join(d, "package.json") if d else "package.json")
            if not d or "node_modules" in d:
                break
            d = posixpath.dirname(d)
    return {p for p in out if "node_modules" not in p}


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _source_of(base: str, target: str, files: set[str]) -> str | None:
    """`./build/index.js` → `src/index.ts` when only the source is in the repository."""
    if "*" in target:
        return None
    rel = target[2:] if target.startswith("./") else target
    found = _resolve(base, "./" + rel, files)
    if found or not BUILT.match(rel):
        return found
    return _resolve(base, "./" + BUILT.sub("src/", rel).replace(".d.ts", ".ts"), files)


def _resolve(base: str, spec: str, files: set[str]) -> str | None:
    path = posixpath.normpath(posixpath.join(base, spec))
    stem = re.sub(r"\.(?:d\.ts|[mc]?js|jsx?)$", "", path)
    for cand in (path, *(stem + e for e in SOURCE_EXT), *(stem + "/index" + e for e in SOURCE_EXT)):
        if cand in files:
            return cand
    return None


def _follow(root: str, entries: set[str], files: set[str], whole: set[str], named: set[tuple[str, str]]) -> None:
    todo = [e for e in entries if e not in whole]
    whole.update(todo)
    while todo:
        f = todo.pop()
        try:
            text = (Path(root) / f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for what, spec in REEXPORT.findall(text):
            target = _resolve(posixpath.dirname(f), spec, files)
            if not target:
                continue
            if what == "*":
                if target not in whole:
                    whole.add(target)
                    todo.append(target)
            else:
                for item in what.strip("{} \n").split(","):
                    name = re.sub(r"^\s*type\s+", "", item).split(" as ")[0].strip()
                    if name:
                        named.add((target, name))
