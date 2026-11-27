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
    r"JSON\.(?:parse|stringify)|(?:set|release)PointerCapture|[rR]ealpath|customElements\.define|"
    r"decodeURI(?:Component)?\b|new URL\(|"
    r"\bimport\(|require\(|\bstat(?:Sync)?\(|(?:\b|fs)[aA]ccess(?:Sync)?\(|\blstat|inspect\.signature|\.resolve\(|"
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
    if (m := re.match(r"\s*([A-Za-z_$][\w$]*)\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\);?\s*$", line)) and (
        _handled_later(lines, i, m.group(1))
    ):
        return "handled later"  # p.catch(() => {}); list.push(p); … await Promise.allSettled(list)
    if (why := _query_prefetch(lines, i)) is not None:
        return why
    if re.search(rf"=>\s*[^{{;]*\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*{VALUE}\s*\)", line):
        return "fallback"  # ids.map((id) => fetch(id).catch(() => undefined)): the arrow returns the value
    nxt = lines[i] if i < len(lines) else ""
    if re.search(rf"\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*{VALUE}\s*\)\s*(?:\.then\(|$)", line) and (
        ".then(" in line.split(".catch(")[-1] or re.match(r"\s*\.then\(", nxt)
    ):
        return "fallback"  # load().catch(() => null).then((data) => …): the next step handles the null
    if re.search(rf"\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*{VALUE}\s*\)", line):
        start = i - 1
        while start > 0 and not re.search(r"[;{}]\s*$", lines[start - 1]) and i - start < 8:
            start -= 1
        stmt = " ".join(lines[start:i])
        if re.search(r"(?<![=!<>])=(?![=>])|\breturn\b|\?\?|\|\||&&|\(\s*await\b|,\s*await\b", stmt):
            return "fallback"  # the null, false or [] is the answer the code then checks
    body = []
    for back in range(i - 2, max(-1, i - 20), -1):
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
                and len([b for b in body if b.strip() and not re.match(r"\s*(?://|#)", b)]) <= 3
                and not bare
                # (not `return JSON.parse(x)` itself: a return after the call that may throw is the normal path)
                and not any(re.search(r"\breturn\b", b) and EXPECTED_THROW.search(b) for b in body)
            ):
                return "expected failure"
            return None
        body.insert(0, ln)
    return None


def _handled_later(lines: list[str], i: int, name: str, span: int = 40) -> bool:
    """The promise `name` given a no-op catch on line i is awaited, or pushed to a list that is awaited, in the next
    lines: the catch only stops an unhandled rejection before then; the failure is still seen where it's awaited."""
    after = "\n".join(lines[i : i + span])
    n = re.escape(name)
    awaited = r"(?:\bawait\s+|Promise\.(?:all|allSettled|race|any)\(\s*\[?[^;\n]*?\b){}\b"
    if re.search(awaited.format(n), after):
        return True
    return any(
        re.search(awaited.format(re.escape(arr)), after) for arr in re.findall(rf"([A-Za-z_$][\w$.]*)\.push\(\s*{n}\s*\)", after)
    )


def _query_prefetch(lines: list[str], i: int) -> str | None:
    """`queryClient.ensureQueryData(opts).catch(() => undefined)` whose result is discarded (a route loader warming
    the cache): React Query keeps the error in its cache and the page shows it. Not when the result is assigned or
    returned: then the caller gets nothing in place of the error."""
    if not re.search(r"\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*(?:\{\s*\}|undefined|null)\s*\)", lines[i - 1]):
        return None
    start, depth = i - 1, 0
    while start > 0 and i - start < 20:  # back to the line the chain starts on, through its call's arguments
        depth += lines[start].count(")") - lines[start].count("(")
        if depth <= 0 and not re.match(r"\s*[.)]", lines[start]):
            break
        start -= 1
    chain = " ".join(lines[start:i])
    if not re.search(r"\.(?:ensureQueryData|prefetchQuery|prefetchInfiniteQuery)\(", chain):
        return None
    head = lines[start].split(".ensureQueryData(")[0].split(".prefetch")[0]
    used = r"(?<![=!<>])=(?![=>])|\breturn\b|\?\?|\|\||&&"
    if re.search(used, head) or (start and re.search(r"(?:=|\breturn|\?\?)\s*$", lines[start - 1])):
        return None
    above = reversed(lines[max(0, start - 12) : start])
    group = next((ln for ln in above if re.search(r"Promise\.all\w*\(\s*\[", ln)), "")
    if re.search(used, group.split("Promise.")[0]):
        return "fallback"  # const [org, plan] = await Promise.all([…]): undefined in place of a failed prefetch
    return "query cache"


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


def _safe_pattern(body: str) -> bool:
    """A regex that only lets digits, letters, `_`, `-` and separators through: nothing that can end a quote."""
    rest = re.sub(r"\[(?:[a-zA-Z0-9]-[a-zA-Z0-9]|\\[dw]|[_\-])+\]|\\[dw]", "", body)
    rest = re.sub(r"[+*?]|\{\d+(?:,\d*)?\}", "", rest)
    return body != rest and re.fullmatch(r"[,_\-:]*", rest) is not None


FN_DEF = re.compile(
    r"^\s*(?:export\s+)?(?:(?:const|let|var)\s+)?(?:async\s+)?(?:(?:private|protected|public|static)\s+)*(?:function\s+|def\s+)?"
    r"([A-Za-z_$][\w$]*)\s*(?:=\s*(?:async\s*)?)?\(([^)]*)\)\s*(?::\s*[^={]+)?(?:=>)?\s*[{:]?\s*$"
)
IDENT_ESCAPE = re.compile(r"\b(?:escape_?[iI]dentifier\w*|quote_?[iI]dent\w*|quoteIdentifier|quote_name|quoteName|identifier)\(")
ESCAPE_CALL = re.compile(
    r"(?:\$?\w+(?:->|\.|::))*(?:escape_?[iI]dentifier\w*|quote_?[iI]dent\w*|quoteIdentifier|quote_name|quoteName|identifier)"
    r"\([^()]*(?:\([^()]*\)[^()]*)*\)"
)
LITERAL_RETURN = re.compile(
    r"""\breturn\s+(?:'[^'$]*'|"[^"$]*"|`[^`$]*`|\w+\s*\?\s*(?:'[^']*'|"[^"]*")\s*:\s*(?:'[^']*'|"[^"]*"))\s*;?\s*$"""
)


def _escaped_only(ret: str) -> bool:
    """`return $this->escapeIdentifier($db) . '.' . $this->escapeIdentifier($t);`: escape calls and literals only."""
    e = re.sub(r"^\s*return\s+", "", ret).rstrip("; ")
    if not IDENT_ESCAPE.search(e):
        return False
    e = ESCAPE_CALL.sub("", e)
    e = re.sub(r"""'[^']*'|"[^"$]*"|`[^`$]*`""", "", e)
    return re.fullmatch(r"[\s.+]*", e) is not None


_FIXED: dict[int, tuple[list[str], set[str]]] = {}


def _fixed_cached(lines: list[str]) -> set[str]:
    """fixed_functions once per file: safe_names runs for every hit in it."""
    got = _FIXED.get(id(lines))
    if got is None or got[0] is not lines:
        if len(_FIXED) > 64:
            _FIXED.clear()
        got = _FIXED[id(lines)] = (lines, fixed_functions(lines) if len(lines) < 50_000 else set())
    return got[1]


def fixed_functions(lines: list[str]) -> set[str]:
    """Functions in this file whose result can't carry anyone's text: every `return` a string literal (or a ternary
    of two), or the body quoting an identifier on the way (`buildTableReference` calling `escapeIdentifier`)."""
    out = set()
    for n, ln in enumerate(lines):
        m = FN_DEF.match(ln)
        if not m or m.group(1) in ("if", "for", "foreach", "while", "switch", "catch", "return", "function", "elseif"):
            continue
        indent = len(ln) - len(ln.lstrip())
        body = []
        for k, nxt in enumerate(lines[n + 1 : n + 60]):
            if k == 0 and nxt.strip() == "{":
                continue  # (PHP, C#: the brace on its own line)
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break  # (the closing brace, or the next definition at the same depth)
            body.append(nxt)
        returns = [b for b in body if re.match(r"\s*return\b", b)]
        if returns and all(LITERAL_RETURN.search(r) or _escaped_only(r) for r in returns):
            out.add(m.group(1))
    return out


def safe_names(lines: list[str], i: int, span: int = 60) -> set[str]:
    """Names that, in the lines leading up to line i, only hold values from a fixed list or that were checked
    against one: `for (const t of Object.keys(TABLES))`, `const cols = keys.filter((c) => allowed.has(c))`,
    `if (known.has(t))`, `for t in TABLES`. Followed one step through names already known to be safe."""
    safe: set[str] = set()
    window = lines[max(0, i - span) : i]
    fixed = _fixed_cached(lines)
    safe |= fixed  # `${parseLocaltime(type)}`: a helper that only returns fixed text
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
            # checked against a pattern of only digits, letters and separators: `validate(x, r"^\d+,\d+$")`,
            # `re.fullmatch(r"^[a-zA-Z0-9]+$", x)`, `preg_match('/^\d+$/', $x)`
            for m in re.finditer(r"""r?(["'])/?\^((?:(?!\1).)*)\$/?\w*\1""", ln):
                if _safe_pattern(m.group(2)):
                    args = ln[: m.start()] + ln[m.end() :]  # the names passed with it to the same call
                    safe.update(n for pair in re.findall(r"\(\s*\$?(\w+)\s*[,)]|,\s*\$?(\w+)\s*\)", args) for n in pair if n)
            # unpacked from a checked value: `sid, serial = cancel_query_id.split(",")`
            if (u := re.match(r"\s*((?:\w+\s*,\s*)+\w+)\s*=\s*(\w+)\.split\(", ln)) and u.group(2) in safe:
                safe.update(n.strip() for n in u.group(1).split(","))
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
                    # the result of a helper in this file that only returns fixed text or quotes an identifier
                    or any(re.match(rf"(?:\$?\w+(?:->|\.|::))*{re.escape(f)}\(", rhs) for f in fixed)
                    # quoted as an identifier: `$database = $this->identifier($db)`, quote_ident, quoteIdentifier
                    or re.match(
                        r"(?:\$?\w+(?:->|\.|::))*(?:identifier|quote_?[iI]dent\w*|quoteName|escape_?[iI]dentifier\w*)\(", rhs
                    )
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
