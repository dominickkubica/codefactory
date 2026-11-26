"""What kind of file a path is. One definition, used by every check, so they all agree on what's a test."""

from __future__ import annotations

import functools
import re

TEST_DIRS = ("tests", "test", "testing", "__tests__", "__mocks__", "spec")
SCRIPT_DIRS = ("scripts", "script", "tools", "bin")


def ignored(path: str, ignore: list[str]) -> bool:
    """In a folder factory.toml's `ignore` names (fixtures, vendor…): left out of every check, like the analyzers do."""
    return bool(set(path.replace("\\", "/").split("/")[:-1]) & set(ignore))


def drop_ignored(checks: dict, root) -> dict:
    """Remove evidence in ignored folders from a {key: Check} result."""
    from .config import load_config

    ignore = load_config(root).ignore
    if ignore:
        for c in checks.values():
            c.hits = [e for e in c.hits if not ignored(e.file, ignore)]
    return checks


# folders no check needs to look inside: dependencies, environments, build output, caches
NOT_SOURCE = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".codefactory",
                        "site-packages", "dist", "build", "Pods", ".expo", ".next", ".nuxt", ".gradle", "DerivedData",
                        "coverage", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "bower_components"})  # fmt: skip


def walk(root, names: tuple[str, ...] = (), suffixes: tuple[str, ...] = (), skip=NOT_SOURCE, hidden: bool = True):
    """Relative paths (posix) of the files under `root` with one of these names or suffixes (all files if neither),
    pruning `skip` folders (and hidden ones unless `hidden`) before descending: `Path.rglob` walks all of
    node_modules first and filters after, which on a JavaScript project is most of the time spent."""
    import os

    root = str(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip and (hidden or not d.startswith("."))]
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        for name in filenames:
            if (names or suffixes) and name not in names and not name.endswith(suffixes):
                continue
            yield name if rel_dir == "." else f"{rel_dir}/{name}"


@functools.lru_cache(maxsize=65536)
def is_test(path: str) -> bool:
    """tests/…, __tests__/…, test_*.py, *_test.py, *.test.ts, *.spec.js…"""
    parts = path.replace("\\", "/").split("/")
    name = parts[-1]
    return (
        any(p in TEST_DIRS for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
        or TEST_NAME.search(name) is not None
    )


# Other languages' conventions: Go's x_test.go, Ruby's x_spec.rb, Java/Kotlin/C#/Swift/Scala's FooTest(s).java
TEST_NAME = re.compile(r"_(?:test|spec|tests)\.\w+$|[a-z0-9]Tests?\.(?:java|kt|cs|swift|scala|groovy|php|m)$")


def is_script(path: str) -> bool:
    """One-off tooling (scripts/, tools/, bin/ at the top): matters less than the product's code."""
    return path.replace("\\", "/").split("/")[0] in SCRIPT_DIRS


# Platform and architecture tags in file names (Go's file_linux_amd64.go, C's io_win32.c, Python's _posix.py).
PLATFORM = re.compile(
    r"[._-](?:linux|darwin|windows|win32|win64|nt|posix|unix|bsd|freebsd|netbsd|openbsd|dragonfly|solaris|illumos|aix|"
    r"plan9|android|ios|macos|osx|wasm|wasip1|js|zos|hurd|amd64|x86_64|x64|386|x86|i386|arm|arm64|aarch64|armv7|"
    r"mips|mipsle|mips64|mips64le|ppc|ppc64|ppc64le|riscv|riscv64|s390x|loong64|sparc64|generic|noasm|purego|asm|"
    r"cgo|nocgo|other|fallback|stub|stubs|default)(?=[._-]|$)",
    re.I,
)


def platform_variants(a: str, b: str) -> bool:
    """Two files that are the same file for different platforms (their copies are on purpose)."""
    if a == b:
        return False
    da, _, na = a.rpartition("/")
    db, _, nb = b.rpartition("/")
    if da != db:
        return False
    sa, sb = PLATFORM.sub("", na.rsplit(".", 1)[0]), PLATFORM.sub("", nb.rsplit(".", 1)[0])
    return sa == sb and (sa != na.rsplit(".", 1)[0] or sb != nb.rsplit(".", 1)[0])
