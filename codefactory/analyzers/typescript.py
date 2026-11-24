"""TypeScript / JavaScript analyzer. The parsing and call resolution run in Node (ts_helper.js) with the TypeScript
compiler, because only the type checker can tell what `obj.method()` or a function from a React hook really is.

Needs Node on PATH and the `typescript` package: the analyzed repo's own (node_modules/typescript) is used first,
then a global install (npm install -g typescript), or CODEFACTORY_TYPESCRIPT pointing at one.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from importlib.resources import files as pkg_files
from pathlib import Path

from ..graph import Edge, File, Function, Graph, Site

EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


class TypeScriptUnavailable(RuntimeError):
    pass


def sources_stamp(root: Path, ignore: list[str]) -> str:
    """A fingerprint of every TypeScript/JavaScript file and tsconfig (empty when there are none)."""
    skip = set(ignore)
    h = hashlib.sha1()
    found = False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for f in sorted(filenames):
            if (f.endswith(EXTENSIONS) and not f.endswith(".d.ts")) or f.startswith(("tsconfig", "jsconfig", "package.json")):
                found = found or f.endswith(EXTENSIONS)
                try:
                    st = os.stat(os.path.join(dirpath, f))
                except OSError:
                    continue
                h.update(
                    f"{os.path.relpath(os.path.join(dirpath, f), root)}|{st.st_size}|{st.st_mtime_ns}\n".encode(
                        "utf-8", "surrogatepass"
                    )
                )
    return h.hexdigest() if found else ""


def find_typescript(root: Path, node: str) -> str:
    env = os.environ.get("CODEFACTORY_TYPESCRIPT")
    if env:
        return env
    local = root / "node_modules" / "typescript"
    if (local / "package.json").is_file():
        return str(local)
    try:
        npm_root = subprocess.run(
            ["npm", "root", "-g"], capture_output=True, text=True, timeout=30, shell=sys.platform == "win32"
        ).stdout.strip()
        if npm_root and (Path(npm_root) / "typescript" / "package.json").is_file():
            return str(Path(npm_root) / "typescript")
    except (OSError, subprocess.SubprocessError):
        pass
    raise TypeScriptUnavailable(
        "TypeScript files found, but the typescript package isn't installed. Run `npm install` in the repo, "
        "or `npm install -g typescript`, or set CODEFACTORY_TYPESCRIPT to its folder."
    )


def analyze_typescript(root: Path, ignore: list[str], cache: bool = True) -> Graph:
    g = Graph(root=str(root), language="typescript")
    stamp = sources_stamp(root, ignore)
    if not stamp:
        return g
    from .parallel import _tool_hash

    stamp = f"{stamp}|{_tool_hash()}"
    saved = root / ".codefactory" / "typescript.json"
    data = None
    if cache:
        try:
            got = json.loads(saved.read_text(encoding="utf-8"))
            data = got["data"] if got.get("stamp") == stamp else None
        except (OSError, ValueError, KeyError):
            data = None
    if data is None:
        data = _run_helper(root, ignore)
        if cache:
            try:
                saved.parent.mkdir(exist_ok=True)
                saved.write_text(json.dumps({"stamp": stamp, "data": data}), encoding="utf-8")
            except OSError:
                pass
    g.files = [File(**f) for f in data["files"]]
    g.functions = [Function(**f) for f in data["functions"]]
    g.edges = [Edge(**e) for e in data["edges"]]
    g.sites = [Site(**s) for s in data.get("sites", [])]
    return g


def _run_helper(root: Path, ignore: list[str]) -> dict:
    """Runs ts_helper.js in Node over the whole project (the type checker needs all of it at once)."""
    node = shutil.which("node")
    if not node:
        raise TypeScriptUnavailable("TypeScript files found, but Node.js isn't installed (https://nodejs.org).")
    ts_path = find_typescript(root, node)
    helper = pkg_files(__package__) / "ts_helper.js"
    proc = subprocess.run(
        [node, "--max-old-space-size=4096", str(helper), str(root), ts_path, json.dumps(ignore)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=1800,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"The TypeScript analyzer failed:\n{proc.stderr.strip()[-2000:]}")
    return json.loads(proc.stdout)
