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
const skipped = (f) => {
  const parts = rel(f).split("/");
  return parts.slice(0, -1).some((p) => ignore.has(p)) || /\.d\.[mc]?ts$/.test(f) || !EXT.test(f) || rel(f).startsWith("..");
};

function walkDir(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!ignore.has(e.name)) walkDir(path.join(dir, e.name), out); }
    else if (EXT.test(e.name)) out.push(path.join(dir, e.name));
  }
  return out;
}

// Program: the repo's tsconfig when there is one (its paths and settings), plus any other source files found.
let options = { allowJs: true, jsx: ts.JsxEmit.Preserve, noEmit: true, skipLibCheck: true, esModuleInterop: true };
let fileNames = [];
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
function loopState(n) {
  let loop = false, stmt = false, crossed = false;
  for (let c = n, p = n.parent; p; c = p, p = p.parent) {
    if (fnByNode.has(p) || ts.isSourceFile(p)) break;
    const statementLoop = ((ts.isForOfStatement(p) || ts.isForInStatement(p)) && c === p.statement) ||
      (ts.isForStatement(p) && c !== p.initializer) || ts.isWhileStatement(p) || ts.isDoStatement(p);
    if (statementLoop) { loop = true; if (!crossed) stmt = true; }
    if (isFnLike(p)) {
      const call = p.parent;
      const iterating = call && ts.isCallExpression(call) && call.arguments.includes(p) && ts.isPropertyAccessExpression(call.expression) &&
        ITER.has(call.expression.name.text);
      // any other callback (onPress={() => …}, setTimeout, .then) runs later, not once per iteration of loops around it
      if (!iterating) break;
      loop = true;
      crossed = true;
    }
  }
  return { loop, stmt };
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
          ...shapeOf(n, sf), dynamic: false, public: isExported(n), io: [] };
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
function calleeOf(node) {
  try {
    const sig = checker.getResolvedSignature(node);
    const f = sig && sig.declaration && fnForDeclaration(sig.declaration);
    if (f) return f;
  } catch { /* fall back to the symbol */ }
  const target = ts.isCallExpression(node) || ts.isNewExpression(node) ? node.expression : node.tagName;
  return fnForSymbol(checker.getSymbolAtLocation(ts.isPropertyAccessExpression(target) ? target.name : target));
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
const typeOnly = (d) => d.importClause && (d.importClause.isTypeOnly ||
  (!d.importClause.name && d.importClause.namedBindings && ts.isNamedImports(d.importClause.namedBindings) &&
    d.importClause.namedBindings.elements.length > 0 && d.importClause.namedBindings.elements.every((e) => e.isTypeOnly)));

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
      const dst = resolveModule(n.arguments[0].text, sf);
      if (dst && dst !== fileId) imports.add(`${fileId}\u0000${dst}`);
    } else if (isCall) {
      const src = ownerOf(n), dst = calleeOf(n);
      const where = src && (ts.isCallExpression(n) || ts.isNewExpression(n)) ? loopState(n) : { loop: false };
      const line = lineOf(sf, n.getStart(sf));
      if (src && dst && dst !== src) {
        bump(calls, `${src.id}\u0000${dst.id}`);
        if (where.loop) sites.push({ fn: src.id, kind: "loop_call", line, target: dst.id, detail: "" });
      } else if (!dst && ts.isCallExpression(n)) {
        if (ts.isPropertyAccessExpression(n.expression)) unresolvedProps.add(n.expression.name.text);
        const io = src && ioCall(n);
        if (io) {
          (ioOf.get(src) || ioOf.set(src, new Set()).get(src)).add(io);
          if (where.loop) sites.push({ fn: src.id, kind: "loop_io", line, target: "", detail: io });
        } else if (src && where.loop && ts.isPropertyAccessExpression(n.expression) && SCAN.has(n.expression.name.text) &&
                   arrayish(n.expression.expression)) {
          sites.push({ fn: src.id, kind: "loop_scan", line, target: "", detail: `${lastName(n.expression.expression) || "array"}.${n.expression.name.text}` });
        }
      }
    } else if (ts.isAwaitExpression(n)) {
      const src = ownerOf(n);
      if (src && loopState(n).stmt) sites.push({ fn: src.id, kind: "loop_await", line: lineOf(sf, n.getStart(sf)), target: "", detail: "" });
    } else if (ts.isIdentifier(n)) {
      const p = n.parent;
      const callee = p && (ts.isCallExpression(p) || ts.isNewExpression(p)) && p.expression === n;
      const tag = p && (ts.isJsxOpeningElement(p) || ts.isJsxSelfClosingElement(p) || ts.isJsxClosingElement(p)) && p.tagName === n;
      const declName = p && (p.name === n) && (isFnLike(p) || ts.isVariableDeclaration(p) || ts.isPropertyAssignment(p) ||
        ts.isPropertyDeclaration(p) || ts.isClassDeclaration(p) || ts.isMethodDeclaration(p));
      const memberCallee = p && ts.isPropertyAccessExpression(p) && p.name === n && p.parent && ts.isCallExpression(p.parent) && p.parent.expression === p;
      if (!callee && !tag && !declName && !memberCallee) {
        const sym = p && ts.isShorthandPropertyAssignment(p) ? checker.getShorthandAssignmentValueSymbol(p) : checker.getSymbolAtLocation(n);
        const dst = fnForSymbol(sym);
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
