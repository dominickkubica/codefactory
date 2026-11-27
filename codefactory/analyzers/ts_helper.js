// TypeScript / JavaScript analyzer, run by codefactory/analyzers/typescript.py with Node:
//   node ts_helper.js <root> <typescript module path> <ignore JSON>
// Prints the graph as JSON on stdout (the same shape as the Python analyzer's). Uses the analyzed repo's own
// TypeScript and tsconfig, so path aliases ("@/...") resolve, and the type checker resolves what each call runs:
// imported functions, methods on typed objects, functions handed out by hooks, and JSX components.
"use strict";
const fs = require("fs");
const path = require("path");

const [root, tsPath, ignoreJson] = process.argv.slice(2);
const ts = require(tsPath);
const ignore = new Set(JSON.parse(ignoreJson || "[]"));
const EXT = /\.(tsx?|jsx?|mjs|cjs|mts|cts)$/;
const rel = (f) => path.relative(root, f).split(path.sep).join("/");
const realRoot = fs.realpathSync(root);
// a link to somewhere outside the repository: not its code (a pull request can commit `a.ts -> ~/.npmrc`)
const outside = (f) => {
  try {
    const r = path.relative(realRoot, fs.realpathSync(f));
    return r.startsWith("..") || path.isAbsolute(r);
  } catch { return true; }
};
const skipped = (f) => {
  const parts = rel(f).split("/");
  return parts.slice(0, -1).some((p) => ignore.has(p) || (p.startsWith(".") && p !== "." && p !== "..")) || /\.d\.[mc]?ts$|\.min\.[mc]?js$/.test(f) || !EXT.test(f) || rel(f).startsWith("..") || outside(f);
};

function walkDir(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!ignore.has(e.name)) walkDir(path.join(dir, e.name), out); }
    else if (EXT.test(e.name)) out.push(path.join(dir, e.name));
  }
  return out;
}

// Program: the repo's tsconfig when there is one (its paths and settings), plus any other source files found.
// codefactory: ignore module_state — a one-shot script: one run, one program, no importers
let options = { allowJs: true, jsx: ts.JsxEmit.Preserve, noEmit: true, skipLibCheck: true, esModuleInterop: true };
let fileNames = []; // codefactory: ignore module_state — the same one run
const cfgPath = ts.findConfigFile(root, ts.sys.fileExists, "tsconfig.json");
// (TypeScript reports paths with "/", Node on Windows with "\\": compare both resolved.)
if (cfgPath && path.resolve(path.dirname(cfgPath)) === path.resolve(root)) {
  const cfg = ts.readConfigFile(cfgPath, ts.sys.readFile);
  if (!cfg.error) {
    const parsed = ts.parseJsonConfigFileContent(cfg.config, ts.sys, path.dirname(cfgPath));
    options = { ...parsed.options, allowJs: true, noEmit: true, skipLibCheck: true };
    fileNames = parsed.fileNames;
  }
}
const all = new Set([...fileNames, ...walkDir(root, [])].map((f) => path.resolve(f)).filter((f) => !skipped(f)));
const program = ts.createProgram([...all], options);
const checker = program.getTypeChecker();
const sources = program.getSourceFiles().filter((sf) => all.has(path.resolve(sf.fileName)));

const files = [], functions = [], fnByNode = new Map(), calls = new Map(), refs = new Map(), imports = new Set();
const sites = [], ioOf = new Map();
const unresolvedProps = new Set();
const bump = (m, k) => m.set(k, (m.get(k) || 0) + 1);
const isFnLike = (n) => ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isArrowFunction(n) ||
  ts.isFunctionExpression(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessor(n) || ts.isSetAccessor(n);
const lineOf = (sf, pos) => sf.getLineAndCharacterOfPosition(pos).line + 1;

function hash(s) { // FNV-1a, 2 x 32 bits
  let a = 0x811c9dc5, b = 0x01000193;
  for (let i = 0; i < s.length; i++) { a = Math.imul(a ^ s.charCodeAt(i), 16777619) >>> 0; b = Math.imul(b ^ s.charCodeAt(i), 2654435761) >>> 0; }
  return a.toString(16).padStart(8, "0") + b.toString(16).padStart(8, "0");
}

// The name a function is known by: its own, the variable or property it's assigned to, or null (anonymous callback).
function nameOf(n) {
  if (ts.isConstructorDeclaration(n)) return "constructor";
  if (n.name && (ts.isIdentifier(n.name) || ts.isStringLiteral(n.name) || ts.isPrivateIdentifier(n.name))) return n.name.text;
  const p = n.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (p && ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) return p.name.text;
  if (p && ts.isPropertyDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (p && ts.isExportAssignment(p)) return "default";
  // const Row = memo(() => …), forwardRef(…), useCallback(…): the wrapped function is the variable. (Other calls,
  // like useSyncExternalStore(cb) or usePicker(cb), return something else: their callbacks stay anonymous.)
  if (p && ts.isCallExpression(p) && p.parent && ts.isVariableDeclaration(p.parent) && ts.isIdentifier(p.parent.name)) {
    const callee = ts.isPropertyAccessExpression(p.expression) ? p.expression.name.text : ts.isIdentifier(p.expression) ? p.expression.text : "";
    if (WRAPPERS.has(callee)) return p.parent.name.text;
  }
  return null;
}

const WRAPPERS = new Set(["memo", "forwardRef", "useCallback", "useEvent", "useEffectEvent", "observer", "styled"]);

function isDefaultExport(n) {
  const mods = ts.canHaveModifiers(n) ? ts.getModifiers(n) || [] : [];
  if (mods.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword)) return true;
  return !!(n.parent && ts.isExportAssignment(n.parent));
}

function isExported(n) {
  const has = (x) => ts.canHaveModifiers(x) && (ts.getModifiers(x) || []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  if (has(n) || isDefaultExport(n)) return true;
  const decl = n.parent && ts.isVariableDeclaration(n.parent) ? n.parent : null; // export const f = () => …
  return !!(decl && decl.parent && decl.parent.parent && has(decl.parent.parent));
}

function shapeOf(n, sf) {
  const body = n.body;
  if (!body) return "";
  const parts = [];
  let count = 0;
  const visit = (x) => {
    count++;
    parts.push(x.kind);
    if (ts.isPropertyAccessExpression(x)) parts.push(x.name.text);
    else if (ts.isIdentifier(x) && !(x.parent && ts.isPropertyAccessExpression(x.parent) && x.parent.name === x)) {
      const sym = checker.getSymbolAtLocation(x);
      const d = sym && sym.declarations && sym.declarations[0];
      const local = d && d.getSourceFile() === sf && d.pos >= n.pos && d.end <= n.end;
      if (!local) parts.push(x.text);
    } else if (ts.isBinaryExpression(x)) parts.push(x.operatorToken.kind);
    // a string's words count: two functions differing only in their SQL or messages aren't copies
    else if (ts.isStringLiteral(x) || ts.isNoSubstitutionTemplateLiteral(x) || ts.isTemplateHead(x) ||
             ts.isTemplateMiddle(x) || ts.isTemplateTail(x)) parts.push(...x.text.split(/\s+/).filter(Boolean).slice(0, 24).map((w) => "S:" + w));
    else if (ts.isNumericLiteral(x)) parts.push("N:" + x.text);
    ts.forEachChild(x, visit);
  };
  visit(body);
  if (count < 15) return { shape: "", tokens: "" };
  const tokens = parts.join(" ");
  return { shape: hash(tokens), tokens };
}

// Efficiency: where a call or await sits relative to loops, and which calls leave the process.
const ITER = new Set(["map", "forEach", "filter", "reduce", "reduceRight", "some", "every", "flatMap", "find", "findIndex",
  "findLast", "findLastIndex", "sort", "toSorted"]);
const SCAN = new Set(["find", "filter", "includes", "indexOf", "lastIndexOf", "some", "every", "findIndex", "findLast", "findLastIndex"]);
const IO_FN = /^(getAll|getFirst|getEach|run|exec|prepare|execute|withTransaction|withExclusiveTransaction)(Async|Sync)$|^(fetch|readAsStringAsync|writeAsStringAsync|downloadAsync|downloadFileAsync|uploadAsync|getItemAsync|setItemAsync|deleteItemAsync|readFile|writeFile|readFileSync|writeFileSync|appendFile|appendFileSync|readdir|readdirSync|stat|statSync)$/;
const IO_RECEIVER = /^(axios|AsyncStorage|prisma|knex|pool|client|db|sql|supabase|firestore|redis|mongoose)$/i;
const IO_VIA_RECEIVER = /^(query|execute|get|set|post|put|patch|delete|findMany|findUnique|findFirst|create|update|upsert|select|insert|from|getItem|setItem|removeItem|multiGet|multiSet)$/;

// { loop, stmt }: runs once per iteration of a loop (for/while, or an array callback like .map); stmt = a for/while
// statement around it in the same function body (an await there waits on each round in turn).
// A list whose length is fixed in the code: an array or object literal, a const holding one (also imported, and
// through Object.keys/values/entries, .map, .filter…), an enum, or anything cut to a small .slice(0, N).
const SMALL = 50;
function constIterable(e, depth = 0) {
  if (!e || depth > 5) return false;
  while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isNonNullExpression(e) ||
         (ts.isSatisfiesExpression && ts.isSatisfiesExpression(e))) e = e.expression;
  if (ts.isArrayLiteralExpression(e) || ts.isObjectLiteralExpression(e)) return true;
  if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression)) {
    const name = e.expression.name.text, recv = e.expression.expression;
    if (name === "slice" && e.arguments.length === 2 && ts.isNumericLiteral(e.arguments[1]) && Number(e.arguments[1].text) <= SMALL) return true;
    if (ts.isIdentifier(recv) && recv.text === "Object" && ["keys", "values", "entries"].includes(name)) return constIterable(e.arguments[0], depth + 1);
    if (["map", "filter", "flatMap", "slice", "concat", "toSorted", "toReversed"].includes(name)) return constIterable(recv, depth + 1);
  }
  if (ts.isIdentifier(e) || ts.isPropertyAccessExpression(e)) {
    let sym = checker.getSymbolAtLocation(ts.isPropertyAccessExpression(e) ? e.name : e);
    if (sym && sym.flags & ts.SymbolFlags.Alias) { try { sym = checker.getAliasedSymbol(sym); } catch { return false; } }
    const d = sym && sym.declarations && sym.declarations[0];
    if (!d) return false;
    if (ts.isEnumDeclaration(d)) return true;
    if (ts.isVariableDeclaration(d) && d.initializer && (ts.getCombinedNodeFlags(d) & ts.NodeFlags.Const)) return constIterable(d.initializer, depth + 1);
    if (ts.isPropertyAssignment(d)) return constIterable(d.initializer, depth + 1);
    // const { tables } = PARTS[part]: a piece of a constant object is as fixed as the object
    if (ts.isBindingElement(d) && ts.isVariableDeclaration(d.parent.parent)) return constRoot(d.parent.parent.initializer, depth + 1);
  }
  if (ts.isElementAccessExpression(e)) return constRoot(e, depth + 1);
  return false;
}
// PARTS[part].tables, CONFIG.items: the object at the root of the access is a constant literal.
function constRoot(e, depth) {
  while (e && (ts.isElementAccessExpression(e) || ts.isPropertyAccessExpression(e) || ts.isParenthesizedExpression(e) ||
               ts.isAsExpression(e) || ts.isNonNullExpression(e))) e = e.expression;
  return !!e && ts.isIdentifier(e) && constIterable(e, depth);
}
function boundedLoop(p) {
  if (ts.isForOfStatement(p) || ts.isForInStatement(p)) return constIterable(p.expression);
  if (ts.isForStatement(p) && p.condition && ts.isBinaryExpression(p.condition)) {
    const r = p.condition.right;
    return (ts.isNumericLiteral(r) && Number(r.text) <= SMALL) ||
      (ts.isPropertyAccessExpression(r) && r.name.text === "length" && constIterable(r.expression));
  }
  return false; // while / do: can't tell
}

// Decision points in a function's own body (if, loops, case, catch, ?:, && || ??): how hard it is to follow, which
// length alone doesn't say (a 700-line table of options is long and simple).
function branchesOf(fnNode) {
  let count = 0;
  const visit = (x) => {
    if (x !== fnNode && fnByNode.has(x)) return;
    if (ts.isIfStatement(x) || ts.isForStatement(x) || ts.isForOfStatement(x) || ts.isForInStatement(x) || ts.isWhileStatement(x) ||
      ts.isDoStatement(x) || ts.isCaseClause(x) || ts.isCatchClause(x) || ts.isConditionalExpression(x)) count++;
    if (ts.isBinaryExpression(x) && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken,
      ts.SyntaxKind.QuestionQuestionToken].includes(x.operatorToken.kind)) count++;
    ts.forEachChild(x, visit);
  };
  visit(fnNode);
  return count;
}

// A write inside a callback handed to transaction()/withTransactionAsync()/atomic(): batched into one transaction.
const TX = /transaction|atomic|batch|writeTxn|serializ/i;
function inTransaction(n) {
  for (let p = n.parent; p; p = p.parent) {
    if (ts.isSourceFile(p)) return false;
    if (isFnLike(p)) {
      const call = p.parent;
      if (call && ts.isCallExpression(call) && call.arguments.includes(p) && TX.test(lastName(call.expression) || "")) return true;
      if (fnByNode.has(p)) return false;
    }
  }
  return false;
}

// { loop, stmt, bounded }: runs once per iteration of a loop (for/while, or an array callback like .map); stmt = a
// for/while statement around it in the same function body (an await there waits on each round in turn); bounded =
// every loop around it goes over a list fixed in the code, so the number of rounds can't grow with the data.
function loopState(n) {
  let loop = false, stmt = false, crossed = false, bounded = true;
  for (let c = n, p = n.parent; p; c = p, p = p.parent) {
    if (fnByNode.has(p) || ts.isSourceFile(p)) break;
    const statementLoop = ((ts.isForOfStatement(p) || ts.isForInStatement(p)) && c === p.statement) ||
      (ts.isForStatement(p) && c !== p.initializer) || ts.isWhileStatement(p) || ts.isDoStatement(p);
    if (statementLoop) { loop = true; if (!crossed) stmt = true; bounded = bounded && boundedLoop(p); }
    if (isFnLike(p)) {
      const call = p.parent;
      const iterating = call && ts.isCallExpression(call) && call.arguments.includes(p) && ts.isPropertyAccessExpression(call.expression) &&
        ITER.has(call.expression.name.text);
      // any other callback (onPress={() => …}, setTimeout, .then) runs later, not once per iteration of loops around it
      if (!iterating) break;
      loop = true;
      crossed = true;
      bounded = bounded && constIterable(call.expression.expression);
    }
  }
  return { loop, stmt, bounded: loop && bounded };
}
// The array searched is fresh on each round: declared inside the loop (this page of results, this item's own list)
// or the loop's own variable. One pass over it per round is linear overall, not O(n²). An UPPER_CASE name is a fixed
// table.
function freshEachRound(n, expr) {
  let head = expr;
  while (head && (ts.isPropertyAccessExpression(head) || ts.isCallExpression(head) || ts.isNonNullExpression(head) ||
                  ts.isElementAccessExpression(head) || ts.isParenthesizedExpression(head))) head = head.expression;
  if (!head || !ts.isIdentifier(head)) return false;
  if (/^[A-Z][A-Z0-9_]{2,}$/.test(head.text)) return true;
  const sym = checker.getSymbolAtLocation(head);
  const decl = sym && sym.declarations && sym.declarations[0];
  if (!decl) return false;
  for (let c = n, p = n.parent; p; c = p, p = p.parent) {
    if (fnByNode.has(p) || ts.isSourceFile(p)) return false;
    const loopNode = ts.isForOfStatement(p) || ts.isForInStatement(p) || ts.isForStatement(p) || ts.isWhileStatement(p) ||
      ts.isDoStatement(p) || (isFnLike(p) && p.parent && ts.isCallExpression(p.parent) && p.parent.arguments.includes(p));
    if (loopNode) return decl.pos >= p.pos && decl.end <= p.end;
  }
  return false;
}
function lastName(expr) {
  while (expr && (ts.isPropertyAccessExpression(expr) || ts.isCallExpression(expr) || ts.isNonNullExpression(expr))) {
    if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
    expr = expr.expression;
  }
  return expr && ts.isIdentifier(expr) ? expr.text : expr && expr.kind === ts.SyntaxKind.ThisKeyword ? "this" : "";
}
function headName(expr) {
  while (expr && (ts.isPropertyAccessExpression(expr) || ts.isCallExpression(expr) || ts.isNonNullExpression(expr))) expr = expr.expression;
  return expr && ts.isIdentifier(expr) ? expr.text : "";
}
function ioCall(call) {
  const e = call.expression;
  if (ts.isIdentifier(e)) return IO_FN.test(e.text) ? e.text : null;
  if (!ts.isPropertyAccessExpression(e)) return null;
  const name = e.name.text, recv = lastName(e.expression), head = headName(e.expression);
  if (IO_FN.test(name) || IO_RECEIVER.test(head) && (IO_VIA_RECEIVER.test(name) || /^axios$/i.test(head))) return recv ? `${recv}.${name}` : name;
  return null;
}
function arrayish(expr) {
  try {
    const t = checker.getTypeAtLocation(expr);
    if (typeof checker.isArrayType === "function" && checker.isArrayType(t)) return true;
    return /\[\]$|^(readonly )?(Readonly)?Array</.test(checker.typeToString(t));
  } catch { return false; }
}

// 1. Files and functions. Nested named functions (a hook's handlers, a component's callbacks) are their own
// functions, qualified by what holds them ("useRun.logSet"); anonymous callbacks belong to the function around them.
for (const sf of sources) {
  const id = rel(sf.fileName);
  files.push({ id, module: id.replace(EXT, ""), loc: sf.getLineAndCharacterOfPosition(sf.end).line + 1 });
  const top = { id: `${id}::<module>`, file: id, name: "<module>", qualname: "<module>", line: 1, end: 1, loc: 0,
    kind: "module", decorated: false, exported: false, shape: "", tokens: "", dynamic: false, public: false, io: [] };
  functions.push(top);
  fnByNode.set(sf, top);
  const seen = new Map();
  const visit = (n, owner, cls) => {
    let next = owner, nextCls = cls;
    if (ts.isClassDeclaration(n) || ts.isClassExpression(n)) nextCls = n.name ? n.name.text : cls;
    if (isFnLike(n)) {
      // A function written inline as an object property or JSX prop inside another function ({ onPress: () => … },
      // headerRight: () => …) is a callback handed to something else: part of the function around it.
      const inline = owner && owner.kind !== "module" && n.parent &&
        (ts.isPropertyAssignment(n.parent) || ts.isJsxExpression(n.parent) || (ts.isMethodDeclaration(n) && ts.isObjectLiteralExpression(n.parent)));
      const name = inline ? null : nameOf(n);
      if (name) {
        const prefix = cls && (ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessor(n) ||
          ts.isSetAccessor(n) || (n.parent && ts.isPropertyDeclaration(n.parent))) ? cls : owner && owner.kind !== "module" ? owner.qualname : null;
        let qual = prefix ? `${prefix}.${name}` : name;
        const line = lineOf(sf, n.getStart(sf)), end = lineOf(sf, n.end);
        const fid = seen.has(qual) ? `${id}::${qual}@${line}` : `${id}::${qual}`;
        seen.set(qual, true);
        // A function stored in a module-level object ({ label, onPress: () => … }) is handed around as data and
        // called by whatever receives it: never reported as unused.
        const asData = n.parent && (ts.isPropertyAssignment(n.parent) || (ts.isMethodDeclaration(n) && ts.isObjectLiteralExpression(n.parent)));
        const fn = { id: fid, file: id, name, qualname: qual, line, end, loc: end - line + 1,
          kind: prefix && prefix === cls ? "method" : "function", decorated: !!(ts.canHaveDecorators(n) && ts.getDecorators(n)?.length),
          exported: !!asData || isDefaultExport(n) || (n.parent && ts.isVariableDeclaration(n.parent) && isDefaultExport(n.parent.parent.parent)),
          ...shapeOf(n, sf), dynamic: false, public: isExported(n), io: [], branches: branchesOf(n) };
        functions.push(fn);
        fnByNode.set(n, fn);
        next = fn;
        if (prefix === cls) nextCls = null; // inside a method, nested functions are qualified by the method
      }
    }
    ts.forEachChild(n, (c) => visit(c, next, nextCls));
  };
  ts.forEachChild(sf, (c) => visit(c, top, null));
}

// 2. Edges.
function fnForDeclaration(d) {
  if (!d) return null;
  if (fnByNode.has(d)) return fnByNode.get(d);
  if (ts.isVariableDeclaration(d) && d.initializer) {
    let init = d.initializer;
    while (init && (ts.isParenthesizedExpression(init) || ts.isAsExpression(init) || ts.isCallExpression(init))) {
      if (ts.isCallExpression(init)) { // memo(() => …): the wrapped function; any other call returns something else
        const callee = ts.isPropertyAccessExpression(init.expression) ? init.expression.name.text : ts.isIdentifier(init.expression) ? init.expression.text : "";
        init = WRAPPERS.has(callee) ? init.arguments.find((a) => isFnLike(a)) : null;
      } else init = init.expression;
    }
    if (init && fnByNode.has(init)) return fnByNode.get(init);
  }
  if ((ts.isPropertyAssignment(d) || ts.isPropertyDeclaration(d)) && d.initializer && fnByNode.has(d.initializer)) return fnByNode.get(d.initializer);
  if (ts.isShorthandPropertyAssignment(d)) {
    const v = checker.getShorthandAssignmentValueSymbol(d);
    return v ? fnForSymbol(v) : null;
  }
  return null;
}
function fnForSymbol(sym) {
  if (!sym) return null;
  if (sym.flags & ts.SymbolFlags.Alias) { try { sym = checker.getAliasedSymbol(sym); } catch { return null; } }
  for (const d of sym.declarations || []) { const f = fnForDeclaration(d); if (f) return f; }
  if (sym.flags & ts.SymbolFlags.Class) { // new Foo() / <Foo />: its constructor
    for (const d of sym.declarations || []) for (const m of d.members || []) if (ts.isConstructorDeclaration(m) && fnByNode.has(m)) return fnByNode.get(m);
  }
  return null;
}
// Code loaded on demand: const { fn } = require("./x") (also cast with `as`), const m = require("./x"); m.fn(),
// require("./x").fn(), await import("./x"). The type checker can't see through these; the module's exports can.
// codefactory: ignore module_state — filled once per run, read by the passes after it
let exportsByFile = null;
function exportsOf(fileId) {
  if (!exportsByFile) {
    exportsByFile = new Map();
    for (const f of functions) {
      if (f.kind === "module" || f.qualname.includes(".")) continue;
      if (!exportsByFile.has(f.file)) exportsByFile.set(f.file, new Map());
      exportsByFile.get(f.file).set(f.name, f);
    }
  }
  return exportsByFile.get(fileId);
}
function requiredFile(init) {
  while (init && (ts.isParenthesizedExpression(init) || ts.isAsExpression(init) || ts.isAwaitExpression(init) ||
                  ts.isNonNullExpression(init) || (ts.isTypeAssertionExpression && ts.isTypeAssertionExpression(init)))) init = init.expression;
  if (!init || !ts.isCallExpression(init) || !init.arguments[0] || !ts.isStringLiteral(init.arguments[0])) return null;
  const isRequire = ts.isIdentifier(init.expression) && init.expression.text === "require";
  if (!isRequire && init.expression.kind !== ts.SyntaxKind.ImportKeyword) return null;
  return resolveModule(init.arguments[0].text, init.getSourceFile());
}
function fnViaRequire(sym, prop) {
  for (const d of (sym && sym.declarations) || []) {
    if (ts.isBindingElement(d) && ts.isObjectBindingPattern(d.parent) && ts.isVariableDeclaration(d.parent.parent)) {
      const file = requiredFile(d.parent.parent.initializer);
      const name = d.propertyName && ts.isIdentifier(d.propertyName) ? d.propertyName.text : ts.isIdentifier(d.name) ? d.name.text : "";
      if (file) return (exportsOf(file) || new Map()).get(name) || null;
    }
    if (prop && ts.isVariableDeclaration(d) && ts.isIdentifier(d.name)) {
      const file = requiredFile(d.initializer);
      if (file) return (exportsOf(file) || new Map()).get(prop) || null;
    }
  }
  return null;
}

function calleeOf(node) {
  try {
    const sig = checker.getResolvedSignature(node);
    const f = sig && sig.declaration && fnForDeclaration(sig.declaration);
    if (f) return f;
  } catch { /* fall back to the symbol */ }
  const target = ts.isCallExpression(node) || ts.isNewExpression(node) ? node.expression : node.tagName;
  const f = fnForSymbol(checker.getSymbolAtLocation(ts.isPropertyAccessExpression(target) ? target.name : target));
  if (f) return f;
  if (ts.isIdentifier(target)) return fnViaRequire(checker.getSymbolAtLocation(target), null);
  if (ts.isPropertyAccessExpression(target)) {
    if (ts.isIdentifier(target.expression)) {
      const viaVar = fnViaRequire(checker.getSymbolAtLocation(target.expression), target.name.text);
      if (viaVar) return viaVar;
    }
    const file = requiredFile(target.expression);
    if (file) return (exportsOf(file) || new Map()).get(target.name.text) || null;
  }
  return null;
}
// TABLE[key](…): one of the table's functions runs (the type checker picks just one); link to all of them.
function linkTable(n, src) {
  let root = n.expression;
  while (ts.isElementAccessExpression(root) || ts.isPropertyAccessExpression(root)) root = root.expression;
  let sym = ts.isIdentifier(root) ? checker.getSymbolAtLocation(root) : null;
  if (sym && sym.flags & ts.SymbolFlags.Alias) { try { sym = checker.getAliasedSymbol(sym); } catch { sym = null; } }
  const decl = sym && sym.declarations && sym.declarations[0];
  if (!decl || !ts.isVariableDeclaration(decl) || !decl.initializer) return;
  const link = (f) => { if (f && f !== src) bump(refs, `${src.id}\u0000${f.id}`); };
  const walk = (x) => {
    if (isFnLike(x) && fnByNode.has(x)) return link(fnByNode.get(x)); // an inline function in the table
    if (ts.isIdentifier(x) || ts.isPropertyAccessExpression(x)) {
      link(fnForSymbol(checker.getSymbolAtLocation(ts.isPropertyAccessExpression(x) ? x.name : x)));
      if (ts.isIdentifier(x)) return;
    }
    ts.forEachChild(x, walk);
  };
  walk(decl.initializer);
}
function ownerOf(n) {
  for (let p = n.parent; p; p = p.parent) if (fnByNode.has(p)) return fnByNode.get(p);
  return null;
}
function resolveModule(spec, sf) {
  const r = ts.resolveModuleName(spec, sf.fileName, options, ts.sys).resolvedModule;
  if (!r || r.isExternalLibraryImport) return null;
  const f = path.resolve(r.resolvedFileName);
  return all.has(f) ? rel(f) : null;
}
// Names a file uses as values: everything but type annotations, interfaces, `implements` and the imports themselves.
// An import whose names appear only in types is erased by the compiler, so it can't take part in a loading loop.
const valueNamesCache = new Map();
function valueNames(sf) {
  let names = valueNamesCache.get(sf);
  if (names) return names;
  names = new Set();
  const walk = (n, inType) => {
    if (ts.isImportDeclaration(n)) return;
    const typeHere = inType || ts.isTypeNode(n) || ts.isInterfaceDeclaration(n) || ts.isTypeAliasDeclaration(n) ||
      (ts.isHeritageClause(n) && n.token === ts.SyntaxKind.ImplementsKeyword);
    if (ts.isIdentifier(n) && !typeHere) {
      const p = n.parent;
      if (!(p && ts.isPropertyAccessExpression(p) && p.name === n)) names.add(n.text);
    }
    ts.forEachChild(n, (c) => walk(c, typeHere));
  };
  walk(sf, false);
  valueNamesCache.set(sf, names);
  return names;
}
const typeOnly = (d) => {
  const c = d.importClause;
  if (!c) return false;  // `import "./x"`: runs the module
  if (c.isTypeOnly) return true;
  const named = c.namedBindings && ts.isNamedImports(c.namedBindings) ? c.namedBindings.elements : [];
  if (!c.name && named.length > 0 && named.every((e) => e.isTypeOnly)) return true;
  const locals = [c.name, ...named.filter((e) => !e.isTypeOnly).map((e) => e.name),
    c.namedBindings && ts.isNamespaceImport(c.namedBindings) ? c.namedBindings.name : null].filter(Boolean);
  if (!locals.length || options.verbatimModuleSyntax || options.preserveValueImports) return false;
  const used = valueNames(d.getSourceFile());
  return locals.every((id) => !used.has(id.text));
};

for (const sf of sources) {
  const fileId = rel(sf.fileName);
  const visit = (n) => {
    if ((ts.isImportDeclaration(n) || ts.isExportDeclaration(n)) && n.moduleSpecifier && ts.isStringLiteral(n.moduleSpecifier)
        && !(ts.isImportDeclaration(n) && typeOnly(n)) && !(ts.isExportDeclaration(n) && n.isTypeOnly)) {
      const dst = resolveModule(n.moduleSpecifier.text, sf);
      if (dst && dst !== fileId) imports.add(`${fileId}\u0000${dst}`);
    }
    const isCall = ts.isCallExpression(n) || ts.isNewExpression(n) || ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n);
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === "require" && n.arguments[0] && ts.isStringLiteral(n.arguments[0])) {
      // only a top-level require runs when the file loads; one inside a function is loaded on demand (no loop)
      const dst = resolveModule(n.arguments[0].text, sf);
      const owner = ownerOf(n);
      if (dst && dst !== fileId && (!owner || owner.kind === "module")) imports.add(`${fileId}\u0000${dst}`);
    } else if (isCall) {
      const src = ownerOf(n), dst = calleeOf(n);
      if (src && ts.isCallExpression(n) && ts.isElementAccessExpression(n.expression)) linkTable(n, src);
      const where = src && (ts.isCallExpression(n) || ts.isNewExpression(n)) ? loopState(n) : { loop: false };
      const line = lineOf(sf, n.getStart(sf));
      if (src && dst && dst !== src) {
        bump(calls, `${src.id}\u0000${dst.id}`);
        if (where.loop) sites.push({ fn: src.id, kind: "loop_call", line, target: dst.id, detail: "", bounded: where.bounded, tx: inTransaction(n) });
        else if (inTransaction(n)) sites.push({ fn: src.id, kind: "tx_call", line, target: dst.id, detail: "", bounded: false, tx: true });
      } else if (!dst && ts.isCallExpression(n)) {
        if (ts.isPropertyAccessExpression(n.expression)) unresolvedProps.add(n.expression.name.text);
        const io = src && ioCall(n);
        if (io) {
          (ioOf.get(src) || ioOf.set(src, new Set()).get(src)).add(io);
          if (where.loop) sites.push({ fn: src.id, kind: "loop_io", line, target: "", detail: io, bounded: where.bounded, tx: inTransaction(n) });
        } else if (src && where.loop && ts.isPropertyAccessExpression(n.expression) && SCAN.has(n.expression.name.text) &&
                   arrayish(n.expression.expression) && !constIterable(n.expression.expression) && // [a, b].includes(x) is O(1)
                   !freshEachRound(n, n.expression.expression)) {
          sites.push({ fn: src.id, kind: "loop_scan", line, target: "", detail: `${lastName(n.expression.expression) || "array"}.${n.expression.name.text}`, bounded: where.bounded });
        }
      }
    } else if (ts.isAwaitExpression(n)) {
      const src = ownerOf(n);
      const ls = src && loopState(n);
      if (ls && ls.stmt) sites.push({ fn: src.id, kind: "loop_await", line: lineOf(sf, n.getStart(sf)), target: "", detail: "", bounded: ls.bounded });
    } else if (ts.isIdentifier(n)) {
      const p = n.parent;
      const callee = p && (ts.isCallExpression(p) || ts.isNewExpression(p)) && p.expression === n;
      const tag = p && (ts.isJsxOpeningElement(p) || ts.isJsxSelfClosingElement(p) || ts.isJsxClosingElement(p)) && p.tagName === n;
      const declName = p && (p.name === n) && (isFnLike(p) || ts.isVariableDeclaration(p) || ts.isPropertyAssignment(p) ||
        ts.isPropertyDeclaration(p) || ts.isClassDeclaration(p) || ts.isMethodDeclaration(p));
      const memberCallee = p && ts.isPropertyAccessExpression(p) && p.name === n && p.parent && ts.isCallExpression(p.parent) && p.parent.expression === p;
      if (!callee && !tag && !declName && !memberCallee) {
        const sym = p && ts.isShorthandPropertyAssignment(p) ? checker.getShorthandAssignmentValueSymbol(p) : checker.getSymbolAtLocation(n);
        const dst = fnForSymbol(sym) || fnViaRequire(sym, null);
        const src = ownerOf(n);
        if (src && dst && dst !== src) bump(refs, `${src.id}\u0000${dst.id}`);
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
}
for (const f of functions) if (f.kind === "method" && unresolvedProps.has(f.name)) f.dynamic = true;

const edges = [];
for (const [k, count] of calls) { const [src, dst] = k.split("\u0000"); edges.push({ src, dst, kind: "call", count }); }
for (const [k, count] of refs) if (!calls.has(k)) { const [src, dst] = k.split("\u0000"); edges.push({ src, dst, kind: "ref", count }); }
for (const k of imports) { const [src, dst] = k.split("\u0000"); edges.push({ src, dst, kind: "import", count: 1 }); }
for (const [fn, set] of ioOf) fn.io = [...set].sort();
process.stdout.write(JSON.stringify({ files, functions, edges, sites }));
