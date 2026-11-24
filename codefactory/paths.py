"""What kind of file a path is. One definition, used by every check, so they all agree on what's a test."""

from __future__ import annotations

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
    )


def is_script(path: str) -> bool:
    """One-off tooling (scripts/, tools/, bin/ at the top): matters less than the product's code."""
    return path.replace("\\", "/").split("/")[0] in SCRIPT_DIRS
