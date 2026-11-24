"""What kind of file a path is. One definition, used by every check, so they all agree on what's a test."""

from __future__ import annotations

import re

TEST_DIRS = ("tests", "test", "testing", "__tests__", "__mocks__", "spec")
SCRIPT_DIRS = ("scripts", "script", "tools", "bin")


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
