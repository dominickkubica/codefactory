"""One file through tree-sitter: its functions, calls, imports and loops, as plain data.

Runs in worker processes, so everything it returns is picklable (and JSON-able, for the per-file cache). It knows no
language in particular: tree-sitter grammars name their nodes consistently (`function_declaration`,
`method_definition`, `call_expression`, `for_statement`…), and these patterns match those names. What a grammar
names differently is missed, not misread.
"""

from __future__ import annotations

import hashlib
import re

# Node kinds, by naming convention across grammars.
FUNC = re.compile(
    r"^(?:function|method|constructor|destructor|operator|init|deinit|subscript|getter|setter|accessor|local_function|"
    r"fun|func|def|singleton_method|protocol_function)_?(?:definition|declaration|item|statement|spec|signature)?$|"
    r"^(?:function_definition|method|function|subroutine_definition|function_subroutine)$"
)
NOT_FUNC = re.compile(r"signature|_type$|^function$")  # declarations without bodies; `function` keyword tokens
CLASS = re.compile(
    r"^(?:class|struct|interface|trait|impl|enum|object|module|namespace|protocol|extension|record|union|"
    r"type_spec|contract|mixin)_?(?:definition|declaration|item|specifier|body)?$|^(?:class|module)$"
)
CALL = re.compile(
    r"^(?:call|call_expression|method_invocation|function_call|invocation_expression|method_call_expression|"
    r"call_expr|function_call_expression|member_call_expression|scoped_call_expression|nullsafe_member_call_expression|"
    r"object_creation_expression|new_expression|constructor_invocation|navigation_expression_call|macro_invocation|"
    r"command|function_call_statement)$"
)
LOOP = re.compile(r"(?:^|_)(?:for|foreach|while|loop|repeat|until|do_while)(?:_|$)")
NOT_LOOP = re.compile(r"do_block|for_clause|range_clause|_in$|loop_label|while_condition|for_initializer")
IMPORT = re.compile(
    r"^(?:import|import_declaration|import_statement|import_from_statement|import_header|use_declaration|"
    r"preproc_include|using_directive|namespace_use_declaration|import_spec|require_call|include_expression|"
    r"require_expression|extern_crate_declaration)$"
)
# Iteration helpers whose block or closure argument runs once per item.
ITER = {
    "each",
    "map",
    "forEach",
    "for_each",
    "each_with_index",
    "flatMap",
    "flat_map",
    "collect",
    "select",
    "filter",
    "reject",
    "times",
    "each_value",
    "each_key",
    "forEachIndexed",
    "mapNotNull",
    "iter",
    "into_iter",
    "for_each_entry",
}
REQUIRE = {"require", "require_relative", "require_once", "include_once", "load", "dofile", "import", "source"}
CLOSURE = re.compile(r"block|lambda|closure|anonymous_function|function_literal|func_literal|arrow_function|do_block")
IDENT = re.compile(r"identifier|^name$|^constant$|word|property_identifier|field_identifier|simple_identifier")
STRINGY = re.compile(r"string|char_literal|heredoc")
NUMBER = re.compile(r"number|integer|float|decimal|^int_literal|real_literal")
COMMENT = re.compile(r"comment")
PUBLIC = re.compile(r"^\s*(?:@\w+\s+)*(?:export|public|pub\b|open\b|def\b|module_function)")
BRANCH = re.compile(
    r"^(?:if|elif|else_if|elsif|unless|for|foreach|while|until|do|loop|case|when|catch|rescue|except|guard|match_arm|"
    r"switch_case|switch_section|conditional|ternary)(?:_\w+)?$"
)
MAX_BYTES = 1_000_000  # bigger files are generated or data
MAX_DEPTH = 400  # pathological nesting (generated code) is cut, not followed


def _name(node, call: bool = False) -> str:
    """A definition's or call's name: its `name` field, else the last identifier of its callee or declarator."""
    for field in ("name", "declarator", "function", "method", "constructor", "type", "macro"):
        child = node.child_by_field_name(field)
        if child is not None:
            if IDENT.search(child.type) or child.type in ("operator_name", "destructor_name"):
                return child.text.decode("utf-8", "replace")
            found = _last_ident(child)
            if found:
                return found
    for c in node.named_children:  # Ruby `def name`, Elixir and friends: the first identifier
        if IDENT.search(c.type):
            return c.text.decode("utf-8", "replace")
    if call and node.named_children:  # Swift, Kotlin: the callee is the first child (a.b.query -> query)
        return _last_ident(node.named_children[0])
    return ""


def _last_ident(node, depth: int = 0) -> str:
    if IDENT.search(node.type) and not node.named_children:
        return node.text.decode("utf-8", "replace")
    if depth > 6:
        return ""
    for field in ("name", "field", "property", "declarator", "function", "attribute", "method"):
        child = node.child_by_field_name(field)
        if child is not None:
            return _last_ident(child, depth + 1)
    for c in reversed(node.named_children):
        if c.type in ("argument_list", "arguments", "parameter_list", "parameters", "type_arguments"):
            continue
        got = _last_ident(c, depth + 1)
        if got:
            return got
    return ""


def _callee_text(node) -> str:
    """`repo.find`: the callee as written. Java, Ruby and PHP keep the receiver and the method name in separate fields
    (object/receiver + name/method); others have one function expression."""
    receiver = node.child_by_field_name("object") or node.child_by_field_name("receiver")
    method = node.child_by_field_name("name") or node.child_by_field_name("method")
    if receiver is not None and method is not None:
        text = receiver.text.decode("utf-8", "replace") + "." + method.text.decode("utf-8", "replace")
    else:
        fn = node.child_by_field_name("function") or node.child_by_field_name("method")
        fn = fn or (node.named_children[0] if node.named_children else None)
        text = (fn or node).text.decode("utf-8", "replace")
    return re.sub(r"\s+", "", text.split("(")[0])[:80]


BODY = {"block", "body", "compound_statement", "body_statement", "function_body", "statement_block", "do_block"}


def _has_body(node) -> bool:
    return node.child_by_field_name("body") is not None or any(c.type in BODY for c in node.named_children)


def _import_sources(node) -> list[str]:
    """What an import names: every quoted path (Go's grouped imports, C includes), else the dotted path."""
    text = node.text.decode("utf-8", "replace")
    quoted = re.findall(r"""["'<]([^"'<>\n]+)["'>]""", text)
    if quoted:
        return quoted
    text = re.sub(r"^\s*(?:import|from|use|using|require|include|extern\s+crate|static)\b", "", text)
    text = re.split(r"\s+(?:import|as)\s+|[;{(]", text)[0].strip().strip("*").strip(".:")
    return [text] if text else []


HERITAGE = re.compile(
    r"inheritance|superclass|super_interfaces|base_list|extends|implements|delegation_specifier|heritage|base_class"
)


def _inherits(node, source: bytes) -> bool:
    """`class A: Base`, `extends`, `implements`, Ruby's `class A < B`: by a child node, else by the header's text."""
    if any(HERITAGE.search(c.type) for c in node.children):
        return True
    body = node.child_by_field_name("body")
    head = source[node.start_byte : body.start_byte if body is not None else min(node.end_byte, node.start_byte + 300)]
    head = head.split(b"{")[0].split(b"\n")[0]
    return bool(re.search(rb"\b(?:extends|implements)\b|^\s*(?:\w+\s+)*(?:class|struct|object|enum)\s+\w+[^:<(]*[:<]", head))


OVERRIDE = re.compile(r"\boverride\b|@Override\b")
PRIVATE = re.compile(r"^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:\w+\s+)*?(?:private|internal|protected|fileprivate)\b")
PUBLIC_BY_DEFAULT = (".kt", ".kts", ".scala", ".sc", ".groovy", ".rb", ".php")  # no modifier = public


def _public(head: str, name: str, rel: str) -> bool:
    """Part of the file's public surface: an explicit `public`/`export`/`pub`, a capitalised Go name, a Dart name
    without `_`, or no restricting modifier in a language where members are public by default (Kotlin, Scala, Ruby,
    PHP)."""
    if PUBLIC.match(head) or name == "main":
        return True
    if rel.endswith(".go"):
        return name[:1].isupper()
    if rel.endswith(".dart"):
        return not name.startswith("_")
    return rel.endswith(PUBLIC_BY_DEFAULT) and not PRIVATE.match(head)


# Declared types, by name, from the text: `repo: Repo` (Swift, Kotlin, TypeScript, Rust, Python annotations),
# `Repo repo` (Java, C#, C++), `val repo = Repo(…)` / `let repo = new Repo(…)`, Go's `repo *Repo` and `repo := &Repo{`.
# File-wide, so two variables of one name with different types in one file stay ambiguous (both are dropped).
TYPE_PATTERNS = (
    re.compile(r"\b(\w+)\s*:\s*(?:&\s*)?(?:mut\s+)?(?:inout\s+)?([A-Z]\w*)\b"),
    re.compile(r"\b([A-Z]\w*)(?:<[^<>]*>)?\s+(\w+)\s*[;=,)]"),
    re.compile(r"\b(?:let|var|val|const|auto)\s+(\w+)\s*=\s*(?:new\s+)?([A-Z]\w*)\s*[({<]"),
    re.compile(r"\b(\w+)\s+\*?([A-Z]\w*)\s*[,)]"),
    re.compile(r"\b(\w+)\s*:=\s*&?([A-Z]\w*)\s*\{"),
)
NOT_TYPES = {"String", "Int", "Bool", "Double", "Float", "Long", "Integer", "Boolean", "Object", "Any", "Void", "None",
             "Optional", "List", "Map", "Set", "Array", "Dictionary", "Self", "This", "True", "False", "Null",
             "Error"}  # fmt: skip


def declared_types(text: str) -> dict[str, str]:
    seen: dict[str, set[str]] = {}
    for i, pat in enumerate(TYPE_PATTERNS):
        for m in pat.finditer(text):
            name, typ = (m.group(2), m.group(1)) if i == 1 else (m.group(1), m.group(2))
            if typ not in NOT_TYPES and name[:1].islower():
                seen.setdefault(name, set()).add(typ)
    return {name: next(iter(types)) for name, types in seen.items() if len(types) == 1}


def walk(source: bytes, parser, rel: str) -> dict:
    """Functions (with calls, loops and structure tokens), imports and the file's top-level calls."""
    tree = parser.parse(source)
    lines = source.count(b"\n") + 1
    out = {"loc": lines, "functions": [], "imports": [], "top": {"calls": [], "refs": set()}}
    inheriting: set[str] = set()  # classes that extend or implement something: a framework may call their methods
    stack = [(tree.root_node, None, (), 0, 0)]  # node, enclosing function record, class path, loop depth, depth
    while stack:
        node, fn, classes, loops, depth = stack.pop()
        t = node.type
        if depth > MAX_DEPTH:
            continue
        if COMMENT.search(t):
            continue
        owner = fn if fn is not None else out["top"]
        if IMPORT.match(t) and fn is None:
            out["imports"] += _import_sources(node)
            continue
        if FUNC.match(t) and not NOT_FUNC.search(t) and _has_body(node) and _name(node):
            # (a definition without a name, such as a property getter `get() = …`, is part of what holds it)
            name = _name(node)
            head = source[node.start_byte : min(node.end_byte, node.start_byte + 200)].decode("utf-8", "replace")
            receiver = re.match(r"\s*func\s*\(\s*\w*\s*\*?\s*(\w+)", head)  # Go methods live outside their type
            qual = ".".join([*classes, *([receiver.group(1)] if receiver else []), name])
            rec = {
                "name": name,
                "qualname": qual,
                "line": node.start_point[0] + 1,
                "end": node.end_point[0] + 1,
                "kind": "method" if classes or receiver else "function",
                # an override is called through the type it overrides (a framework, an interface): never "unused"
                "framework": (bool(classes) and classes[-1] in inheriting) or bool(OVERRIDE.search(head)),
                "public": _public(head, name, rel),
                "calls": [],
                "refs": set(),
                "branches": 0,
                "tokens": [],
            }
            out["functions"].append(rec)
            for c in reversed(node.children):
                stack.append((c, rec, classes, 0, depth + 1))  # loops outside a function don't run its body
            continue
        if CLASS.match(t) and node.named_children:
            name = _name(node)
            if _inherits(node, source):
                inheriting.add(name)
            for c in reversed(node.children):
                stack.append((c, fn, (*classes, name) if name else classes, loops, depth + 1))
            continue
        if fn is not None and (BRANCH.search(t) or t in ("&&", "||", "and", "or", "??", "orelse", "andalso")):
            fn["branches"] += 1
        in_loop = loops
        if LOOP.search(t) and not NOT_LOOP.search(t) and node.named_children:
            in_loop = loops + 1
        if CALL.match(t):
            name = _name(node, call=True)
            if name in REQUIRE and fn is None:  # Ruby, Lua, PHP, Elixir: imports are calls
                out["imports"] += [s for s in _import_sources(node)[:1] if s != name]
            elif name:
                owner["calls"].append([name, node.start_point[0] + 1, loops > 0, _callee_text(node)])
            if name in ITER:  # the closure it's given runs per item
                for c in node.named_children:
                    if CLOSURE.search(c.type) or any(CLOSURE.search(g.type) for g in c.named_children):
                        in_loop = loops + 1
        if IDENT.search(t) and not node.named_children:
            parent = node.parent
            if (
                parent is not None
                and not FUNC.match(parent.type)
                and not CALL.match(parent.type)
                and (parent.child_by_field_name("function") != node)
            ):  # a name used as a value (a callback, a table entry): keeps that function from looking unused
                owner["refs"].add(node.text.decode("utf-8", "replace"))
        if fn is not None and not node.named_children:  # leaves: the function's structure, for duplicate detection
            text = node.text.decode("utf-8", "replace")
            if IDENT.search(t):
                # local-looking names are blanked (a renamed copy still matches); fields, types and called names are
                # kept, so small functions that merely share a shape don't look like copies
                parent = node.parent
                keep = t != "identifier" or (
                    parent is not None and (CALL.match(parent.type) or parent.child_by_field_name("function") == node)
                )
                fn["tokens"].append(text if keep else "ID")
            elif NUMBER.search(t):
                fn["tokens"].append(f"N:{text[:12]}")
            elif STRINGY.search(t) or STRINGY.search(node.parent.type if node.parent else ""):
                fn["tokens"] += [f"S:{w}" for w in text.strip("'\"`").split()[:24]]
            else:
                fn["tokens"].append(t)
        for c in reversed(node.children):
            stack.append((c, fn, classes, in_loop, depth + 1))
    out["top"]["refs"] = sorted(out["top"]["refs"])
    out["types"] = declared_types(source.decode("utf-8", "replace"))
    for rec in out["functions"]:
        rec["refs"] = sorted(rec["refs"])
        toks = rec.pop("tokens")
        rec["tokens"] = " ".join(toks) if len(toks) >= 25 else ""
        rec["shape"] = hashlib.sha1(rec["tokens"].encode("utf-8", "surrogatepass")).hexdigest()[:16] if rec["tokens"] else ""
    return out
