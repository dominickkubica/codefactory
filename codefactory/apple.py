"""Swift checks that matter on Apple platforms: crashes waiting to happen, retain cycles, work on the main thread,
and weakened code-signing entitlements.

All are line patterns with a little structure (a brace-matched block for "inside viewDidLoad" or "inside a closure"),
so they're leads with the exact line, ranked Low to Medium.
"""

from __future__ import annotations

import re
from pathlib import Path

from .checks import Check, Evidence
from .paths import drop_ignored, is_test

FORCE = re.compile(r"\btry!|\bas!\s")
STORED_CLOSURE = re.compile(
    r"\.sink\s*\{|\.sink\s*\(|\.subscribe\s*\{|addObserver\(forName:[^)]*\)\s*\{|scheduledTimer\([^)]*repeats:\s*true[^)]*\)\s*\{|"
    r"\bself\.\w+\s*=\s*\{|\.observe\([^)]*\)\s*\{"
)
WEAK = re.compile(r"\[\s*(?:weak|unowned)\s+self\s*\]")
MAIN_SCOPE = re.compile(
    r"func\s+(?:viewDidLoad|viewWillAppear|viewDidAppear|viewWillLayoutSubviews|layoutSubviews|draw)\s*\(|"
    r"var\s+body\s*:\s*some\s+View"
)
SYNC_IO = re.compile(
    r"Data\(contentsOf:|String\(contentsOf:|NSData\(contentsOf|FileManager\.default\.(?:contents|contentsOfDirectory|copyItem|"
    r"moveItem|removeItem)|\.write\(to:|sqlite3_(?:exec|step|prepare)|try\s+\w+\.write\(|NSString\(contentsOf"
)
WEAK_ENTITLEMENTS = re.compile(
    r"<key>(com\.apple\.security\.cs\.(?:disable-library-validation|allow-unsigned-executable-memory|allow-dyld-environment-variables|"
    r"disable-executable-page-protection)|com\.apple\.security\.get-task-allow)</key>\s*<true\s*/>"
)
KEYS = ("swift_force", "swift_retain_cycle", "main_thread_io", "entitlement_weakened")


def _block(lines: list[str], start: int) -> tuple[int, int]:
    """(first, last) line index of the brace block opening on line `start`."""
    depth, opened = 0, False
    for i in range(start, min(len(lines), start + 400)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth <= 0:
                    return start, i
    return start, min(len(lines) - 1, start + 400)


def scan(root: Path, files: list[str]) -> dict[str, Check]:
    out = {k: Check(k) for k in KEYS}
    for fid in files:
        if not fid.endswith(".swift") or is_test(fid):
            continue
        try:
            lines = (root / fid).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        code = [re.sub(r"//.*$", "", ln) for ln in lines]
        for i, ln in enumerate(code):
            if FORCE.search(ln):
                out["swift_force"].hits.append(Evidence(fid, i + 1, lines[i].strip()[:140]))
            if STORED_CLOSURE.search(ln) and not WEAK.search(ln):
                first, last = _block(code, i)
                body = "\n".join(code[first : last + 1])
                if re.search(r"\bself\.", body) and not WEAK.search(body):
                    out["swift_retain_cycle"].hits.append(Evidence(fid, i + 1, lines[i].strip()[:140]))
            if MAIN_SCOPE.search(ln):
                first, last = _block(code, i)
                for j in range(first, last + 1):
                    if SYNC_IO.search(code[j]) and "Task {" not in code[j] and "async" not in code[j]:
                        out["main_thread_io"].hits.append(Evidence(fid, j + 1, lines[j].strip()[:140]))
    for path in sorted(root.rglob("*.entitlements")):
        if {"node_modules", ".git", "Pods", ".codefactory"} & set(path.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in WEAK_ENTITLEMENTS.finditer(text):
            rel = path.relative_to(root).as_posix()
            out["entitlement_weakened"].hits.append(Evidence(rel, text.count("\n", 0, m.start()) + 1, m.group(1)))
    return drop_ignored(out, root)
