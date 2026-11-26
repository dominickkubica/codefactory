"""TypeScript / JavaScript analyzer. The parsing and call resolution run in Node (ts_helper.js) with the TypeScript
compiler, because only the type checker can tell what `obj.method()` or a function from a React hook really is.

Needs Node on PATH and a TypeScript 5.x compiler the user installed: CODEFACTORY_TYPESCRIPT pointing at one, or a
global install (npm install -g typescript@5). Never the one inside the analyzed repository: its node_modules is the
repository's code (a pull request could commit one), and codefactory never runs the code it analyzes. The compiler
only parses and type-checks; module resolution (tsconfig paths, aliases) comes from the project's own files either way.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from importlib.resources import files as pkg_files
from pathlib import Path

from ..graph import Edge, File, Function, Graph, Site

EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


class TypeScriptUnavailable(RuntimeError):
    pass


def sources_stamp(root: Path, ignore: list[str]) -> str:
    """A fingerprint of every TypeScript/JavaScript file and tsconfig (empty when there are none; "racy" when one
    changed too recently to trust, so the result isn't reused)."""
    from ..paths import file_stamp
    from ..paths import racy as too_recent

    skip = set(ignore)
    h = hashlib.sha1()
    found = racy = False
    now_ns = time.time_ns()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for f in sorted(filenames):
            if (f.endswith(EXTENSIONS) and not f.endswith(".d.ts")) or f.startswith(("tsconfig", "jsconfig", "package.json")):
                found = found or f.endswith(EXTENSIONS)
                try:
                    st = os.stat(os.path.join(dirpath, f))
                except OSError:
                    continue
                racy = racy or too_recent(st, now_ns)
                h.update(f"{os.path.relpath(os.path.join(dirpath, f), root)}|{file_stamp(st)}\n".encode("utf-8", "surrogatepass"))
    return ("racy" if racy else h.hexdigest()) if found else ""


def has_api(folder) -> bool:
    """A TypeScript package with the JavaScript compiler API (5.x and earlier). TypeScript 7, the native rewrite, ships
    only an unstable API, so requiring it fails."""
    return (Path(folder) / "lib" / "typescript.js").is_file()


def _outside(folder: Path, root: Path) -> bool:
    """Not inside the analyzed repository (a global install can't be the repository's own code)."""
    try:
        return not folder.resolve().is_relative_to(Path(root).resolve())
    except OSError:
        return False


def find_typescript(root: Path, node: str) -> str:
    env = os.environ.get("CODEFACTORY_TYPESCRIPT")
    if env:
        if not has_api(env):
            raise TypeScriptUnavailable(f"CODEFACTORY_TYPESCRIPT ({env}) isn't a TypeScript 5.x package (no lib/typescript.js).")
        return env
    # a global install: next to node first (no subprocess); then npm, run from the home folder so the analyzed
    # repository's .npmrc (which could set `prefix` to a folder inside it) isn't read
    bin_dir = Path(node).resolve().parent if node else None
    candidates = []
    if bin_dir:  # (Linux and macOS: <prefix>/lib/node_modules; Windows: next to node.exe)
        candidates = [bin_dir.parent / "lib" / "node_modules" / "typescript", bin_dir / "node_modules" / "typescript"]
    try:
        npm_root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=30, cwd=Path.home(),
                                  shell=sys.platform == "win32").stdout.strip()  # fmt: skip
        if npm_root:
            candidates.append(Path(npm_root) / "typescript")
    except (OSError, subprocess.SubprocessError, RuntimeError):  # (RuntimeError: no home folder)
        pass
    for c in candidates:
        if has_api(c) and _outside(c, root):
            return str(c)
    raise TypeScriptUnavailable(
        "TypeScript files found, but no TypeScript compiler of your own is installed: `npm install -g typescript@5` (or "
        "set CODEFACTORY_TYPESCRIPT to its folder). codefactory never runs the one in the repository's node_modules: "
        "that's the repository's code."
    )


def analyze_typescript(root: Path, ignore: list[str], cache: bool = True) -> Graph:
    g = Graph(root=str(root), language="typescript")
    stamp = sources_stamp(root, ignore)
    if not stamp:
        return g
    from .parallel import _tool_hash

    stamp = f"{stamp}|{_tool_hash()}"
    from ..paths import cache_dir

    folder = cache_dir(root) if cache and not stamp.startswith("racy") else None  # racy: nothing to reuse or keep
    cache = folder is not None
    saved = folder / "typescript.json" if folder else None
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
