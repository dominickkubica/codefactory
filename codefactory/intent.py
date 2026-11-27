# codefactory: ignore-file swallowed — the patterns themselves
"""Recognises code that looks risky to a pattern but shows its intent, so the review doesn't report it.

Each rule here came from a false positive on a real codebase. They stay narrow: when in doubt, keep reporting.
"""

from __future__ import annotations

import re

# ---- swallowed errors ----------------------------------------------------------------------------------------------

# Best-effort cleanup of something that may already be gone: failing to cancel, dismiss or delete it is expected.
# Deleting is only "cleanup" for leftovers (a stored item, a file, a cache), never for the user's records.
CLEANUP = re.compile(
    r"\b(?:(?:dismiss|cancel|unregister|unsubscribe|abort)\w*|(?:delete|remove|unlink|clear)\w*"
    r"(?:Item|File|Folder|Dir|Temp|Cache|Database|Key)\w*|unlink|close|flush|return|dispose|destroy|disconnect|"
    r"signOut|logout|kill|terminate|release|rm)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*\.catch\("
)  # best-effort cleanup: closing, flushing or deleting what may already be gone
# `const x = await load().catch(() => null)`: the failure becomes a value the next lines handle. (`() => {}` is an
# empty body, not a value, so it isn't one.)
FALLBACK = re.compile(
    r"(?<![=!<>])=(?![=>])\s*(?:await\s+)?[^;]*\.catch\(\s*\(\s*\)\s*=>\s*(?:null|undefined|\[\]|false|0|''|\"\")\s*\)"
)
TRAILING_COMMENT = re.compile(r"(?:\)|\}|;|\bpass)\s*(?://|#)\s*\S")


# calls whose one expected failure is the reason for the catch: JSON that may not be JSON, a pointer capture on an
# inactive pointer, a path that may not exist, a custom element already defined (re-run, hot reload)
EXPECTED_THROW = re.compile(
    r"JSON\.parse|(?:set|release)PointerCapture|realpath|customElements\.define|decodeURIComponent|new URL\(|"
    r"\bimport\(|require\(|\bstat(?:Sync)?\(|\baccess(?:Sync)?\(|\blstat|inspect\.signature|\.resolve\(|"
    r"\bint\(|\bfloat\(|json\.loads|\.decode\(|urlparse|resolve_?url|\bresolve\(|localStorage|sessionStorage|"
    r"clipboard|writeText|navigator\.share"
)
VALUE = r"(?:null|undefined|\[\]|\{\}|false|0|''|\"\"|None)"


def expected_failure(lines: list[str], i: int) -> str | None:
    """Why the empty catch on line i is deliberate, from the lines around it: the try only imports an optional
    dependency or makes a call whose one expected failure is handled by doing nothing; or the catch turns the failure
    into a value (`.catch(() => null)`) the statement goes on to use."""
    line = lines[i - 1]
    if re.search(r"\.catch\(", line) and EXPECTED_THROW.search(line.split(".catch(")[0]):
        return "expected failure"  # navigator.clipboard.writeText(x).catch(() => {}): a permission that may be refused
    if re.search(rf"=>\s*[^{{;]*\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*{VALUE}\s*\)", line):
        return "fallback"  # ids.map((id) => fetch(id).catch(() => undefined)): the arrow returns the value
    if re.search(rf"\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*{VALUE}\s*\)", line):
        start = i - 1
        while start > 0 and not re.search(r"[;{}]\s*$", lines[start - 1]) and i - start < 8:
            start -= 1
        stmt = " ".join(lines[start:i])
        if re.search(r"(?<![=!<>])=(?![=>])|\breturn\b|\?\?|\|\||&&|\(\s*await\b|,\s*await\b", stmt):
            return "fallback"  # the null, false or [] is the answer the code then checks
    body = []
    for back in range(i - 2, max(-1, i - 9), -1):
        ln = lines[back]
        if re.match(r"\s*(?:try\s*:|try\s*\{|\}\s*try\s*\{)\s*$", ln) or re.search(r"\btry\s*\{", ln):
            text = "\n".join(body)
            if body and re.match(r"\s*(?:import |from \S+ import )", next((b for b in body if b.strip()), "")):
                return "optional import"  # `try: import greenlet …`: probing for an optional dependency
            # (not `return JSON.parse(x)` in an empty catch: the caller gets nothing and isn't told why; nor a bare
            # `except:`, which also swallows Ctrl-C)
            bare = re.match(r"\s*except\s*:", line)
            if (
                text
                and EXPECTED_THROW.search(text)
                and len([b for b in body if b.strip()]) <= 3
                and not bare
                and not re.search(r"\breturn\b", text)
            ):
                return "expected failure"
            return None
        body.insert(0, ln)
    return None


def swallow_intent(line: str, above: str) -> str | None:
    """Why an empty catch on this line is deliberate, or None if it isn't shown to be."""
    if TRAILING_COMMENT.search(line.split("catch", 1)[-1] if "catch" in line else line) or re.match(r"\s*(?://|#)\s*\S", above):
        return "explained"
    if re.search(r"catch\s*\(\s*(?:_|ignored?|expected|unused)\b", line):  # Kotlin/Java/C#: named to say it's ignored
        return "explained"
    if CLEANUP.search(line):
        return "cleanup"
    if re.match(r"\s*void\s+\S.*\.catch\(", line):  # `void p.catch(…)`: fired off and deliberately not awaited
        return "fire and forget"
    if FALLBACK.search(line):
        return "fallback"
    return None


# ---- SQL built from strings ----------------------------------------------------------------------------------------

NUMERIC = re.compile(
    r"^(?:\d+|Math\.\w+\(.*\)|Number\(.*\)|parseInt\(.*\)|parseFloat\(.*\)|int\(.*\)|float\(.*\)|len\(.*\)|"
    r"[\w.]+\s*[-+*/%]\s*\d+|\d+\s*[-+*/%]\s*[\w.]+|[\w.]+\.length|[\w.]+\.size)$"
)
CONST_NAME = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")


def _root(expr: str) -> str:
    """`cols.join(", ")` -> `cols`; `[...order].reverse()` -> `order`; `row.name` -> `row`."""
    m = re.match(r"\s*(?:\[\s*\.\.\.)?\s*([A-Za-z_$][\w$]*)", expr)
    return m.group(1) if m else ""


def safe_names(lines: list[str], i: int, span: int = 60) -> set[str]:
    """Names that, in the lines leading up to line i, only hold values from a fixed list or that were checked
    against one: `for (const t of Object.keys(TABLES))`, `const cols = keys.filter((c) => allowed.has(c))`,
    `if (known.has(t))`, `for t in TABLES`. Followed one step through names already known to be safe."""
    safe: set[str] = set()
    window = lines[max(0, i - span) : i]
    for _ in range(2):  # a second pass picks up names derived from names the first pass found
        for ln in window:
            for m in re.finditer(r"(?:\.has|\.includes|\bin)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", ln):
                safe.add(m.group(1))
            checked_filter = re.search(r"\(\s*\(?\s*(\w+)\s*\)?\s*=>\s*[^)]*?(?:\.has\(\s*\1\s*\)|\1\s+in\s+[A-Z])", ln)
            if checked_filter and (a := re.match(r"\s*(?:const|let|var)?\s*(\w+)\s*=", ln)):
                safe.add(a.group(1))  # const cols = xs.filter((c) => allowed.has(c))
            for m in re.finditer(r"for\s*\(\s*(?:const|let|var)\s+(\w+)\s+of\s+(.+?)\)\s*\{?\s*$|for\s+(\w+)\s+in\s+(.+):", ln):
                name, src = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
                if CONST_NAME.search(src) or _root(src.replace("Object.keys(", "")) in safe:
                    safe.add(name)
            # checked to be a number first: is_numeric($amount), ctype_digit, Number.isInteger, isinstance(x, int)
            for m in re.finditer(r"(?:is_numeric|is_int|ctype_digit|Number\.isInteger|Number\.isFinite)\(\s*\$?(\w+)|"
                                 r"isinstance\(\s*(\w+)\s*,\s*int\b", ln):  # fmt: skip
                safe.add(m.group(1) or m.group(2))
            # typed as one of a few strings: `key: "name" | "email"` (TypeScript)
            for m in re.finditer(r"""\b(\w+)\??\s*:\s*(?:['"][^'"]*['"]\s*\|\s*)+['"][^'"]*['"]""", ln):
                safe.add(m.group(1))
            # typed as a number: `int id`, `for (Integer id : ids)`, `id: Int`, Go's `id int`
            for m in re.finditer(
                r"\b(?:int|long|short|Integer|Long|Short|int32|int64|uint\w*)\s+(\w+)\b|(\w+)\s*:\s*(?:Int|Long|Short|int|number)\b|"
                r"\b(\w+)\s+(?:int|int32|int64|uint\w*)\b",
                ln,
            ):
                safe.add(m.group(1) or m.group(2) or m.group(3))
            if (a := re.match(r"\s*(?:const|let|var)?\s*\$?(\w+)\s*=\s*(.+)", ln)) and not a.group(2).startswith("="):
                rhs = a.group(2)
                if re.fullmatch(r"""\s*(?:'[^'$`{]*'|"[^"$`{]*"|`[^`$]*`)\s*;?\s*""", rhs):
                    safe.add(a.group(1))  # a fixed string: `const botName = 'github-actions[bot]'`
                if (
                    re.match(r"(?:Object\.(?:keys|values)\(\s*)?[A-Z][A-Z0-9_]{2,}\b", rhs)
                    or (_root(rhs) in safe and _root(rhs) != a.group(1))
                    or NUMERIC.match(rhs.strip().rstrip(";"))  # size = int(request.args["size"])
                    or re.search(r"""\.join\(\s*\(?['"]\?['"]""", rhs)  # placeholders: ",".join("?" * len(ids))
                ):
                    safe.add(a.group(1))
    joined = " ".join(window)  # `$scope = cond ? 'concat(?, id)' : 'cast(? as text)';` (PHP, JS) or `x = 'a' if c else 'b'`
    lit = r"""(?:'[^']*'|"[^"]*")"""
    for m in re.finditer(rf"\$?(\w+)\s*=(?!=)\s*[^;]*?\?\s*{lit}\s*:\s*{lit}\s*;|(\w+)\s*=\s*{lit}\s+if\s+[^\n]+?\s+else\s+{lit}",
                         joined):  # fmt: skip
        safe.add(m.group(1) or m.group(2))
    return safe


# a value made safe for SQL text on the way in: identifier quoting and escaping, generated placeholders, a query
# builder's own SQL (its values are bound), or a choice between two constants
ESCAPED = re.compile(
    r"^(?:\$?this->)?(?:[\w$>-]+(?:->|\.))*(?:quote\w*|escape\w*|_?quote_name|wrap\w*|placeholders?|bindings?|"
    r"sqlstring\.escape\w*|identifier|ident)\s*\(|(?:\.|->)(?:getQuery|getSql|toSQL|toSql|sql)\(\s*\)$|"
    r"^[\w$.]*(?:escaped|quoted|Quoted|Escaped|safe|Safe|sanitized)\w*$|"
    r"""^[^?]+\?\s*(?:'[^']*'|"[^"]*"|`[^`$]*`)\s*:\s*(?:'[^']*'|"[^"]*"|`[^`$]*`)$""",
)


def interp_safe(expr: str, safe: set[str]) -> bool:
    e = expr.strip()
    return bool(NUMERIC.match(e)) or _root(e) in safe or bool(ESCAPED.search(e))


# ---- CI ------------------------------------------------------------------------------------------------------------


def push_skip_explained(workflow: str) -> bool:
    """The workflow says in a comment why it doesn't run on push (a deliberate choice, e.g. to save CI minutes)."""
    return any(re.match(r"\s*#.*\bpush", ln, re.I) for ln in workflow.splitlines())
