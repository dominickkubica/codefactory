"""TypeScript / JavaScript analyzer. The parsing and call resolution run in Node (ts_helper.js) with the TypeScript
compiler, because only the type checker can tell what `obj.method()` or a function from a React hook really is.

Needs Node on PATH and the `typescript` package: the analyzed repo's own (node_modules/typescript) is used first,
then a global install (npm install -g typescript), or CODEFACTORY_TYPESCRIPT pointing at one.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from importlib.resources import files as pkg_files
from pathlib import Path

from ..graph import Edge, File, Function, Graph

EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


class TypeScriptUnavailable(RuntimeError):
    pass


def has_sources(root: Path, ignore: list[str]) -> bool:
    skip = set(ignore)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        if any(f.endswith(EXTENSIONS) and not f.endswith(".d.ts") for f in filenames):
            return True
    return False


def find_typescript(root: Path, node: str) -> str:
    env = os.environ.get("CODEFACTORY_TYPESCRIPT")
    if env:
        return env
    local = root / "node_modules" / "typescript"
    if (local / "package.json").is_file():
        return str(local)
    try:
        npm_root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, timeout=30,
                                  shell=sys.platform == "win32").stdout.strip()
        if npm_root and (Path(npm_root) / "typescript" / "package.json").is_file():
            return str(Path(npm_root) / "typescript")
    except (OSError, subprocess.SubprocessError):
        pass
    raise TypeScriptUnavailable(
        "TypeScript files found, but the typescript package isn't installed. Run `npm install` in the repo, "
        "or `npm install -g typescript`, or set CODEFACTORY_TYPESCRIPT to its folder.")


def analyze_typescript(root: Path, ignore: list[str]) -> Graph:
    g = Graph(root=str(root), language="typescript")
    if not has_sources(root, ignore):
        return g
    node = shutil.which("node")
    if not node:
        raise TypeScriptUnavailable("TypeScript files found, but Node.js isn't installed (https://nodejs.org).")
    ts_path = find_typescript(root, node)
    helper = pkg_files(__package__) / "ts_helper.js"
    proc = subprocess.run([node, "--max-old-space-size=4096", str(helper), str(root), ts_path, json.dumps(ignore)],
                          capture_output=True, text=True, encoding="utf-8", timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"The TypeScript analyzer failed:\n{proc.stderr.strip()[-2000:]}")
    data = json.loads(proc.stdout)
    g.files = [File(**f) for f in data["files"]]
    g.functions = [Function(**f) for f in data["functions"]]
    g.edges = [Edge(**e) for e in data["edges"]]
    return g
