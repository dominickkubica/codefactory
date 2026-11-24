// codefactory: ignore-file raw_html — every value from the graph goes through esc() before it's inserted
// The factory floor: layers are zones (left = depends on the others, right = depended on), files are machines
// (size = lines), calls or imports are belts (thickness = how many), and flags are lights on the machines.
(function () {
  "use strict";
  const D = window.FACTORY;
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const SEV = { high: 0, warn: 1, info: 2 };
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- model -------------------------------------------------------------------------------------------
  const fnById = new Map(D.functions.map((f) => [f.id, f]));
  const files = D.files.map((f) => ({ ...f, fns: [], flags: [], inn: new Map(), out: new Map(), worst: null }));
  const fileById = new Map(files.map((f) => [f.id, f]));
  for (const fn of D.functions) if (fn.kind !== "module") fileById.get(fn.file)?.fns.push(fn);
  const fileOf = (target) => fileById.get(target) || fileById.get(fnById.get(target)?.file);
  for (const fl of D.flags) {
    const f = fileOf(fl.target);
    if (!f) continue;
    f.flags.push(fl);
    if (f.worst === null || SEV[fl.severity] < SEV[f.worst]) f.worst = fl.severity;
  }
  // Lenses: duplication (copies and near-copies), efficiency (I/O, searches and awaits inside loops), size.
  const DUP = new Set(["duplicate", "similar"]), SLOW = new Set(["io_in_loop", "quadratic_scan", "sequential_await"]);
  const LENS_KINDS = { duplication: DUP, efficiency: SLOW, size: new Set(["large_file", "long_function"]) };
  for (const f of files) {
    const copied = new Set(f.flags.filter((x) => DUP.has(x.kind)).map((x) => x.target));
    f.dupFns = copied.size;
    f.dupLoc = [...copied].reduce((t, id) => t + (fnById.get(id)?.loc || 0), 0);
    f.slow = f.flags.filter((x) => SLOW.has(x.kind)).reduce((t, x) => t + (x.severity === "warn" ? 3 : 1), 0);
    f.ioFns = f.fns.filter((fn) => fn.io && fn.io.length).length;
    f.longFns = f.flags.filter((x) => x.kind === "long_function").length;
  }
  const twins = new Map(); // "a|b" -> { a, b, score }: two files holding copies of each other's code
  for (const fl of D.flags) {
    if (!DUP.has(fl.kind)) continue;
    const a = fileOf(fl.target);
    for (const r of fl.related || []) {
      const b = fileOf(r);
      if (!a || !b || a === b) continue;
      const [x, y] = a.id < b.id ? [a, b] : [b, a], k = x.id + "|" + y.id;
      const score = fl.kind === "duplicate" ? 1 : fl.score || 0.8;
      const t = twins.get(k);
      if (!t || t.score < score) twins.set(k, { a: x, b: y, score, n: (t?.n || 0) + 1 });
      else t.n++;
    }
  }
  const hot = new Set(); // "src>dst" file pairs where a loop calls into code that does I/O
  for (const fl of D.flags) {
    if (fl.kind !== "io_in_loop") continue;
    const a = fileOf(fl.target), b = fl.related && fl.related[0] ? fileOf(fl.related[0]) : a;
    if (a && b) hot.add(a.id + ">" + b.id);
  }
  const lensMetric = { issues: () => 0, duplication: (f) => f.dupLoc, efficiency: (f) => f.slow, size: (f) => f.loc };
  const lensMax = {};
  for (const k of Object.keys(lensMetric)) lensMax[k] = Math.max(1, ...files.map(lensMetric[k]));
  let lens = "issues";
  const fnCallers = new Map(), fnCallees = new Map();
  function beltsFor(kind) {
    const agg = new Map();
    for (const e of D.edges) {
      if (kind === "call" ? e.kind !== "call" : e.kind !== "import") continue;
      const a = fileOf(e.src), b = fileOf(e.dst);
      if (!a || !b || a === b || a.hidden || b.hidden) continue;
      const k = a.id + "\u0000" + b.id;
      agg.set(k, (agg.get(k) || 0) + e.count);
    }
    return [...agg].map(([k, count]) => { const [s, d] = k.split("\u0000"); return { src: fileById.get(s), dst: fileById.get(d), count }; });
  }
  for (const e of D.edges) {
    if (e.kind === "import") continue;
    if (!fnCallers.has(e.dst)) fnCallers.set(e.dst, []);
    if (!fnCallees.has(e.src)) fnCallees.set(e.src, []);
    fnCallers.get(e.dst).push(e); fnCallees.get(e.src).push(e);
  }

  // EXPLAIN for a function: everything it eventually calls, each at its shortest depth.
  function traceFrom(start) {
    const depth = new Map([[start, 0]]), order = [];
    const q = [start];
    let loop = false;
    while (q.length) {
      const cur = q.shift();
      for (const e of fnCallees.get(cur) || []) {
        if (e.kind !== "call") continue;
        if (e.dst === start) loop = true;
        if (!depth.has(e.dst) && fnById.has(e.dst)) { depth.set(e.dst, depth.get(cur) + 1); order.push(e.dst); q.push(e.dst); }
      }
    }
    const fns = order.map((id) => ({ fn: fnById.get(id), depth: depth.get(id) }));
    return { start: fnById.get(start), fns, loop, files: new Set([fnById.get(start).file, ...fns.map((x) => x.fn.file)]),
      maxDepth: Math.max(0, ...fns.map((x) => x.depth)), loc: fns.reduce((t, x) => t + x.fn.loc, 0) };
  }

  // ---- layout -------------------------------------------------------------------------------------------
  const GAP = 140, PAD = 40, TOP = 110;
  const size = (f) => Math.round(Math.min(150, Math.max(36, 26 + Math.sqrt(f.loc) * 2.6)) / 10) * 10;
  const layers = D.layers.length ? D.layers : [...new Set(files.map((f) => f.layer))];
  const hasTests = files.some((f) => f.layer === "tests");
  let showTests = !hasTests || files.filter((f) => f.layer === "tests").length < files.length * 0.1;
  let zones = [], worldW = 0, worldH = 0;
  files.forEach((f) => { f.s = size(f); });
  // Zones are halls of one shared height, each as wide as its machines need, so the whole floor has about the
  // screen's shape: a big codebase fits on screen instead of becoming a long thin strip.
  function layout() {
    zones = [];
    files.forEach((f) => { f.hidden = f.layer === "tests" && !showTests; f.zone = -1; });
    const groups = layers.map((name) => files.filter((f) => f.layer === name && !f.hidden)).filter((m) => m.length);
    const areaOf = (m) => m.reduce((t, f) => t + (f.s + PAD) ** 2, 0) * 1.15;
    const total = groups.reduce((t, m) => t + areaOf(m), 0);
    const aspect = Math.max(1, (innerWidth - 360) / Math.max(300, innerHeight));
    const hall = Math.max(240, Math.sqrt(total / aspect));
    let x = 0;
    for (const members of groups) {
      members.sort((a, b) => b.s - a.s || a.id.localeCompare(b.id));
      // never a sliver: even a hall of one file is wide enough for its summary card when zoomed out
      const width = Math.max(members[0].s + PAD, hall * 0.22, Math.ceil(areaOf(members) / hall / 10) * 10);
      let cx = 0, cy = 0, rowH = 0;
      for (const f of members) {
        if (cx > 0 && cx + f.s > width) { cx = 0; cy += rowH + PAD; rowH = 0; }
        f.x = x + PAD + cx; f.y = TOP + cy; cx += f.s + PAD; rowH = Math.max(rowH, f.s);
        f.zone = zones.length;
      }
      zones.push({ name: members[0].layer, x, w: width + PAD * 2, h: cy + rowH + PAD * 2 + 30, count: members.length });
      x += width + PAD * 2 + GAP;
    }
    const h = Math.max(...zones.map((z) => z.h), 200);
    zones.forEach((z) => { z.h = h; });
    worldW = x - GAP; worldH = h + TOP;
  }
  layout();

  let mode = "call", belts = [];
  function buildBelts() {
    belts = beltsFor(mode).map((b, i) => {
      const back = b.dst.zone < b.src.zone; // flows against the zone order
      const over = b.dst.zone <= b.src.zone; // routed over the top: backwards, or within one zone
      const x1 = b.src.x + b.src.s, y1 = b.src.y + b.src.s / 2, x2 = b.dst.x, y2 = b.dst.y + b.dst.s / 2;
      let pts;
      if (!over) {
        const z = zones[b.src.zone];
        const mx = z.x + z.w + 12 + (i * 7) % (GAP - 24);
        pts = [[x1, y1], [mx, y1], [mx, y2], [x2, y2]];
      } else { // up and over the top of the floor
        const lane = 16 + (i * 5) % 44;
        pts = [[b.src.x + b.src.s / 2, b.src.y], [b.src.x + b.src.s / 2, lane], [b.dst.x + b.dst.s / 2, lane], [b.dst.x + b.dst.s / 2, b.dst.y]];
      }
      let len = 0; const segs = [];
      for (let k = 1; k < pts.length; k++) { const l = Math.abs(pts[k][0] - pts[k - 1][0]) + Math.abs(pts[k][1] - pts[k - 1][1]); segs.push(l); len += l; }
      return { ...b, back, pts, segs, len, w: 1 + Math.min(5, Math.log2(b.count + 1)), dots: Math.min(6, 1 + Math.floor(Math.log2(b.count + 1))) };
    });
    for (const f of files) { f.inn = new Map(); f.out = new Map(); }
    for (const b of belts) { b.src.out.set(b.dst, b.count); b.dst.inn.set(b.src, b.count); }
    // The overview: one conveyor per pair of halls, and a summary card per hall.
    const agg = new Map();
    for (const b of belts) {
      if (b.src.zone === b.dst.zone) continue;
      const k = b.src.zone + ">" + b.dst.zone;
      const l = agg.get(k) || { a: b.src.zone, b: b.dst.zone, count: 0, links: 0 };
      l.count += b.count; l.links++; agg.set(k, l);
    }
    zoneLinks = [...agg.values()].sort((x, y) => x.count - y.count);
    zones.forEach((z, i) => {
      const members = files.filter((f) => f.zone === i);
      z.loc = members.reduce((t, f) => t + f.loc, 0);
      z.fns = members.reduce((t, f) => t + f.fns.length, 0);
      z.sev = { high: 0, warn: 0, info: 0 };
      for (const f of members) for (const fl of f.flags) z.sev[fl.severity]++;
      z.top = members.filter((f) => f.inn.size).sort((p, q) => q.inn.size - p.inn.size).slice(0, 3);
      z.dupFns = members.reduce((t, f) => t + f.dupFns, 0);
      z.slowWarn = members.reduce((t, f) => t + f.flags.filter((x) => SLOW.has(x.kind) && x.severity === "warn").length, 0);
      z.slowAll = members.reduce((t, f) => t + f.flags.filter((x) => SLOW.has(x.kind)).length, 0);
      z.ioFns = members.reduce((t, f) => t + f.ioFns, 0);
      z.longFns = members.reduce((t, f) => t + f.longFns, 0);
      z.metric = members.reduce((t, f) => t + lensMetric[lens](f), 0);
    });
  }
  let zoneLinks = [];
  buildBelts();

  // ---- view ---------------------------------------------------------------------------------------------
  const canvas = $("#floor"), ctx = canvas.getContext("2d");
  let scale = 1, ox = 0, oy = 0, hover = null, selected = null, flagFilter = null, query = "", traced = null, spot = null;
  function resize() {
    const r = canvas.getBoundingClientRect(), dpr = devicePixelRatio || 1;
    canvas.width = r.width * dpr; canvas.height = r.height * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function fit() {
    const r = canvas.getBoundingClientRect();
    scale = Math.min(2, Math.max(0.02, Math.min((r.width - 40) / worldW, (r.height - 40) / worldH)));
    ox = (r.width - worldW * scale) / 2; oy = Math.max(20, (r.height - worldH * scale) / 2);
  }
  // Zoom to show these machines together (a trace), close enough to see them as machines.
  // If they're too far apart to show as machines together, centre on `primary` (the function being traced).
  function fitFiles(list, primary) {
    const shown = list.filter((f) => f && !f.hidden);
    if (!shown.length) return;
    const r = canvas.getBoundingClientRect();
    const x0 = Math.min(...shown.map((f) => f.x)), y0 = Math.min(...shown.map((f) => f.y));
    const x1 = Math.max(...shown.map((f) => f.x + f.s)), y1 = Math.max(...shown.map((f) => f.y + f.s));
    const fitScale = Math.min((r.width - 80) / Math.max(1, x1 - x0), (r.height - 80) / Math.max(1, y1 - y0));
    if (fitScale < NEAR + 0.06 && primary && !primary.hidden) {
      scale = Math.max(scale, NEAR + 0.2);
      ox = r.width / 2 - (primary.x + primary.s / 2) * scale; oy = r.height / 2 - (primary.y + primary.s / 2) * scale;
      return;
    }
    scale = Math.min(1.4, fitScale);
    ox = r.width / 2 - ((x0 + x1) / 2) * scale; oy = r.height / 2 - ((y0 + y1) / 2) * scale;
  }
  function focusOn(f) {
    if (f.hidden) { showTests = true; testsBtn.setAttribute("aria-pressed", true); layout(); buildBelts(); }
    const r = canvas.getBoundingClientRect();
    scale = Math.max(scale, 1);
    ox = r.width / 2 - (f.x + f.s / 2) * scale; oy = r.height / 2 - (f.y + f.s / 2) * scale;
  }
  const toWorld = (px, py) => [(px - ox) / scale, (py - oy) / scale];
  const hit = (wx, wy) => files.find((f) => !f.hidden && wx >= f.x && wx <= f.x + f.s && wy >= f.y && wy <= f.y + f.s) || null;
  const matches = (f) => (!query || f.id.toLowerCase().includes(query)) && (!flagFilter || f.flags.some((fl) => fl.kind === flagFilter));

  function pointAt(b, d) {
    for (let k = 0; k < b.segs.length; k++) {
      if (d <= b.segs[k]) {
        const [ax, ay] = b.pts[k], [bx, by] = b.pts[k + 1], t = b.segs[k] ? d / b.segs[k] : 0;
        return [ax + (bx - ax) * t, ay + (by - ay) * t];
      }
      d -= b.segs[k];
    }
    return b.pts[b.pts.length - 1];
  }

  // Semantic zoom: below FAR the floor is shown as halls with summary cards and one conveyor per hall pair;
  // above NEAR, the machines. In between, one fades into the other.
  const FAR = 0.26, NEAR = 0.46;
  const detailLevel = () => Math.min(1, Math.max(0, (scale - FAR) / (NEAR - FAR)));
  const overview = () => detailLevel() < 0.5;
  let hoverZone = -1;
  const hallRect = (z) => ({ x: ox + z.x * scale, y: oy + (TOP - 30) * scale, w: z.w * scale, h: z.h * scale });
  function zoneAt(px, py) {
    return zones.findIndex((z) => { const h = hallRect(z); return px >= h.x && px <= h.x + h.w && py >= h.y && py <= h.y + h.h; });
  }
  function zoomToZone(i) {
    const z = zones[i], r = canvas.getBoundingClientRect();
    scale = Math.min(1.4, Math.max(NEAR + 0.04, Math.min((r.width - 60) / z.w, (r.height - 60) / (z.h + 40))));
    ox = r.width / 2 - (z.x + z.w / 2) * scale; oy = r.height / 2 - (TOP - 30 + z.h / 2) * scale;
  }
  const fmt = (n) => n.toLocaleString("en-US");
  function fitText(text, max) {
    if (ctx.measureText(text).width <= max) return text;
    let t = text;
    while (t.length > 1 && ctx.measureText(t + "…").width > max) t = t.slice(0, -1);
    return t + "…";
  }
  function drawOverview(C, a, lensColor) {
    const zMax = Math.max(1, ...zones.map((z) => z.metric || 0));
    const max = Math.max(1, ...zoneLinks.map((l) => l.count));
    ctx.save(); ctx.globalAlpha = a;
    // halls
    zones.forEach((z, i) => {
      const h = hallRect(z);
      ctx.fillStyle = C.panel; ctx.globalAlpha = a * 0.88; ctx.fillRect(h.x, h.y, h.w, h.h); ctx.globalAlpha = a;
      if (lensColor && z.metric > 0) {
        ctx.fillStyle = lensColor; ctx.globalAlpha = a * (0.08 + 0.32 * Math.sqrt(z.metric / zMax)); ctx.fillRect(h.x, h.y, h.w, h.h); ctx.globalAlpha = a;
      }
      ctx.strokeStyle = i === hoverZone ? C.sel : C.edge; ctx.lineWidth = i === hoverZone ? 2.5 : 1.2; ctx.strokeRect(h.x, h.y, h.w, h.h);
    });
    // conveyors: forward ones arch over the top, backward ones (a lower layer reaching up) under the floor
    const top = Math.min(...zones.map((z) => hallRect(z).y)), bottom = Math.max(...zones.map((z) => { const h = hallRect(z); return h.y + h.h; }));
    const labels = [];
    for (const l of zoneLinks) {
      const A = hallRect(zones[l.a]), B = hallRect(zones[l.b]), back = l.b < l.a;
      const on = hoverZone < 0 || l.a === hoverZone || l.b === hoverZone;
      const share = l.count / max, w = 1.5 + 7 * Math.sqrt(share);
      const x1 = A.x + A.w * (back ? 0.35 : 0.65), x2 = B.x + B.w * (back ? 0.65 : 0.35);
      const span = Math.abs(l.b - l.a);
      const y0 = back ? bottom : top, lift = (back ? 1 : -1) * (18 + span * 16);
      ctx.globalAlpha = a * (on ? 0.35 + 0.6 * Math.sqrt(share) : 0.06);
      ctx.strokeStyle = back ? C.back : C.belt; ctx.lineWidth = w; ctx.setLineDash(back ? [10, 6] : []);
      ctx.beginPath(); ctx.moveTo(x1, y0); ctx.bezierCurveTo(x1, y0 + lift * 1.6, x2, y0 + lift * 1.6, x2, y0); ctx.stroke();
      ctx.setLineDash([]);
      // arrowhead at the receiving hall
      ctx.fillStyle = ctx.strokeStyle; ctx.beginPath();
      const d = back ? -1 : 1;
      ctx.moveTo(x2, y0); ctx.lineTo(x2 - w - 3, y0 - d * (w + 7)); ctx.lineTo(x2 + w + 3, y0 - d * (w + 7)); ctx.fill();
      if (on && (share >= 0.12 || hoverZone >= 0)) labels.push({ x: (x1 + x2) / 2, y: y0 + lift * 1.2, text: `${fmt(l.count)} ${mode === "call" ? "calls" : "imports"}` });
    }
    ctx.globalAlpha = a; ctx.font = "600 12px Inter, system-ui, sans-serif"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    for (const lb of labels) {
      const w = ctx.measureText(lb.text).width + 10;
      ctx.fillStyle = C.floor; ctx.fillRect(lb.x - w / 2, lb.y - 9, w, 18);
      ctx.fillStyle = C.muted; ctx.fillText(lb.text, lb.x, lb.y);
    }
    // cards
    ctx.textAlign = "left"; ctx.textBaseline = "alphabetic";
    zones.forEach((z) => {
      const h = hallRect(z), pad = Math.max(6, Math.min(16, h.w * 0.06)), room = h.w - pad * 2;
      if (room < 46) { // too narrow for a card: the name, written up the hall
        ctx.save(); ctx.translate(h.x + h.w / 2 + 4, h.y + h.h - 10); ctx.rotate(-Math.PI / 2);
        ctx.fillStyle = C.ink; ctx.font = "700 12px Inter, system-ui, sans-serif";
        ctx.fillText(fitText(`${z.name.toUpperCase()} · ${z.count}`, h.h - 20), 0, 0); ctx.restore();
        return;
      }
      const big = Math.max(11, Math.min(22, room / 6.5));
      let y = h.y + pad + big;
      ctx.fillStyle = C.ink; ctx.font = `700 ${big}px Inter, system-ui, sans-serif`;
      ctx.fillText(fitText(z.name.toUpperCase(), room), h.x + pad, y);
      const small = Math.max(10, Math.min(13, room / 11));
      ctx.font = `400 ${small}px Inter, system-ui, sans-serif`; ctx.fillStyle = C.muted;
      for (const line of [`${fmt(z.count)} files`, `${fmt(z.fns)} functions`, `${fmt(z.loc)} lines`]) {
        y += small * 1.5; ctx.fillText(fitText(line, room), h.x + pad, y);
      }
      // issue pills
      y += small * 1.2;
      let px = h.x + pad;
      ctx.font = `600 ${small}px Inter, system-ui, sans-serif`;
      for (const sv of ["high", "warn", "info"]) {
        if (!z.sev[sv]) continue;
        const t = `${z.sev[sv]} ${sv}`, w = ctx.measureText(t).width + 12;
        if (px + w > h.x + h.w - pad) { px = h.x + pad; y += small * 1.9; }
        ctx.fillStyle = C[sv]; ctx.globalAlpha = a * 0.16; ctx.fillRect(px, y, w, small * 1.6);
        ctx.globalAlpha = a; ctx.fillStyle = C[sv]; ctx.fillText(t, px + 6, y + small * 1.15);
        px += w + 5;
      }
      // what the lens is about, in words
      const lensLine = lens === "duplication" ? (z.dupFns ? `${z.dupFns} copied functions` : "no copies")
        : lens === "efficiency" ? `${z.slowWarn} N+1 loops · ${z.slowAll - z.slowWarn} minor loop notes · ${z.ioFns} functions do I/O`
        : lens === "size" ? `${z.longFns} long functions` : "";
      if (lensLine) {
        y += small * 2.6; ctx.font = `700 ${small}px Inter, system-ui, sans-serif`; ctx.fillStyle = lensColor;
        const words = lensLine.split(" · ");
        for (const w of words) { ctx.fillText(fitText(w, room), h.x + pad, y); y += small * 1.4; }
        y -= small * 1.4;
      }
      // most-used files
      if (z.top.length && y + small * 7 < h.y + h.h) {
        y += small * 3.2; ctx.fillStyle = C.muted; ctx.font = `600 ${small}px Inter, system-ui, sans-serif`;
        ctx.fillText(fitText("MOST USED", room), h.x + pad, y);
        ctx.font = `400 ${small}px JetBrains Mono, ui-monospace, monospace`; ctx.fillStyle = C.ink;
        for (const f of z.top) { y += small * 1.5; ctx.fillText(fitText(`${f.id.split("/").pop()} · ${f.inn.size}`, room), h.x + pad, y); }
      }
    });
    // hint
    ctx.font = "12px Inter, system-ui, sans-serif"; ctx.fillStyle = C.muted; ctx.textAlign = "center";
    const r = canvas.getBoundingClientRect();
    ctx.fillText("Click a hall or zoom in to see its files", r.width / 2, Math.min(r.height - 60, bottom + 120));
    ctx.textAlign = "left";
    ctx.restore();
  }

  function draw(now) {
    const r = canvas.getBoundingClientRect();
    const C = { floor: css("--floor"), grid: css("--grid"), machine: css("--machine"), edge: css("--machine-edge"),
      belt: css("--belt"), dot: css("--belt-dot"), back: css("--back"), ink: css("--ink"), muted: css("--muted"),
      idle: css("--idle"), sel: css("--sel"), high: css("--high"), warn: css("--warn"), info: css("--info"), line: css("--line"),
      panel: css("--panel"), dup: css("--dup"), slow: css("--slow"), size: css("--size") };
    const lensColor = { duplication: C.dup, efficiency: C.slow, size: C.size }[lens];
    const detail = detailLevel();
    ctx.fillStyle = C.floor; ctx.fillRect(0, 0, r.width, r.height);
    ctx.save(); ctx.translate(ox, oy); ctx.scale(scale, scale);
    // floor grid
    const step = 20, [x0, y0] = toWorld(0, 0), [x1, y1] = toWorld(r.width, r.height);
    if (scale > 0.35) {
      ctx.fillStyle = C.grid;
      for (let gx = Math.floor(x0 / step) * step; gx < x1; gx += step)
        for (let gy = Math.floor(y0 / step) * step; gy < y1; gy += step) ctx.fillRect(gx, gy, 1.2, 1.2);
    }
    // zones
    for (const z of zones) {
      ctx.globalAlpha = detail;
      ctx.strokeStyle = C.line; ctx.lineWidth = 1.5; ctx.setLineDash([6, 6]);
      ctx.strokeRect(z.x, TOP - 30, z.w, z.h); ctx.setLineDash([]);
      ctx.fillStyle = C.muted; ctx.font = "600 13px Inter, system-ui, sans-serif";
      ctx.fillText(`${z.name.toUpperCase()}  ·  ${z.count}`, z.x + 10, TOP - 12);
    }
    const focus = hover || selected;
    const linked = (b) => traced ? traced.files.has(b.src.id) && traced.files.has(b.dst.id) : !focus || b.src === focus || b.dst === focus;
    // belts
    for (const b of belts) {
      const on = linked(b), visible = matches(b.src) || matches(b.dst);
      // with no machine in focus, a big floor's belts stay faint so the machines read first
      const isHot = lens === "efficiency" && hot.has(b.src.id + ">" + b.dst.id);
      const rest = focus || traced ? 0.9 : belts.length > 300 ? 0.28 : 0.8;
      const lensDim = lens === "issues" || isHot ? 1 : lens === "efficiency" ? 0.25 : 0.35;
      ctx.globalAlpha = (!visible ? 0.06 : on ? (isHot ? 1 : rest) : 0.1) * detail * lensDim;
      if (detail === 0) continue;
      ctx.strokeStyle = isHot ? C.slow : b.back ? C.back : C.belt; ctx.lineWidth = isHot ? b.w + 2.5 : b.w;
      ctx.setLineDash(b.back ? [8, 5] : []);
      ctx.beginPath(); ctx.moveTo(...b.pts[0]); for (const p of b.pts.slice(1)) ctx.lineTo(...p); ctx.stroke();
      ctx.setLineDash([]);
      if (on && visible && !reduceMotion && detail > 0.5) {
        ctx.fillStyle = C.dot;
        for (let k = 0; k < b.dots; k++) {
          const d = ((now / 1000) * 60 + (k * b.len) / b.dots) % b.len, [px, py] = pointAt(b, d);
          ctx.fillRect(px - 2, py - 2, 4, 4);
        }
      }
    }
    ctx.globalAlpha = 1;
    // machines
    for (const f of files) {
      if (f.hidden) continue;
      const dim = !matches(f) || (spot ? !spot.has(f.id) : traced ? !traced.files.has(f.id) : focus && f !== focus && !focus.inn.has(f) && !focus.out.has(f));
      ctx.globalAlpha = (dim ? 0.25 : 1) * (0.3 + 0.7 * detail);
      const idle = f.inn.size === 0 && f.out.size === 0;
      ctx.fillStyle = idle ? C.idle : C.machine; ctx.fillRect(f.x, f.y, f.s, f.s);
      if (lensColor) { // heat: how much of this lens's problem the machine holds
        const m = lensMetric[lens](f);
        if (m > 0) {
          const a0 = ctx.globalAlpha;
          ctx.globalAlpha = a0 * (0.18 + 0.67 * Math.sqrt(m / lensMax[lens]));
          ctx.fillStyle = lensColor; ctx.fillRect(f.x, f.y, f.s, f.s); ctx.globalAlpha = a0;
        }
      }
      ctx.strokeStyle = f === selected ? C.sel : C.edge; ctx.lineWidth = f === selected ? 3 : 1.5;
      ctx.strokeRect(f.x, f.y, f.s, f.s);
      if (lens === "efficiency" && f.ioFns) { // a drum: this file talks to a database, files or the network itself
        const cx = f.x + 10, cy = f.y + 10;
        ctx.fillStyle = C.slow; ctx.strokeStyle = C.slow; ctx.lineWidth = 1.2;
        ctx.beginPath(); ctx.ellipse(cx, cy - 3, 5, 2, 0, 0, Math.PI * 2); ctx.fill();
        ctx.beginPath(); ctx.moveTo(cx - 5, cy - 3); ctx.lineTo(cx - 5, cy + 3); ctx.ellipse(cx, cy + 3, 5, 2, 0, Math.PI, 0, true);
        ctx.lineTo(cx + 5, cy - 3); ctx.stroke();
      }
      // function bars: one tick per function, height by its size
      const n = Math.min(f.fns.length, Math.floor((f.s - 10) / 4));
      ctx.fillStyle = C.muted;
      for (let k = 0; k < n; k++) {
        const h = Math.min(f.s * 0.45, 3 + Math.sqrt(f.fns[k].loc) * 1.6);
        ctx.fillRect(f.x + 6 + k * 4, f.y + f.s - 6 - h, 2.5, h);
      }
      // ports
      ctx.fillStyle = C.edge;
      if (f.inn.size) ctx.fillRect(f.x - 3, f.y + f.s / 2 - 4, 3, 8);
      if (f.out.size) ctx.fillRect(f.x + f.s, f.y + f.s / 2 - 4, 3, 8);
      // status light
      if (f.worst) {
        ctx.fillStyle = C[f.worst]; ctx.beginPath(); ctx.arc(f.x + f.s - 8, f.y + 8, 5, 0, Math.PI * 2); ctx.fill();
      }
      if (scale > 0.45) {
        ctx.fillStyle = C.ink; ctx.font = "11px JetBrains Mono, ui-monospace, monospace";
        let name = f.id.split("/").pop();
        const room = f.s + PAD - 8;
        while (name.length > 4 && ctx.measureText(name).width > room) name = name.slice(0, -2) + "…";
        ctx.fillText(name, f.x, f.y + f.s + 14);
      }
    }
    if (lens === "duplication" && detail > 0) { // arcs joining files that hold copies of each other's code
      ctx.font = "600 11px Inter, system-ui, sans-serif"; ctx.textAlign = "center";
      for (const t of twins.values()) {
        if (t.a.hidden || t.b.hidden) continue;
        const on = !(hover || selected || spot) || [hover, selected].includes(t.a) || [hover, selected].includes(t.b) || (spot && spot.has(t.a.id) && spot.has(t.b.id));
        const x1 = t.a.x + t.a.s / 2, y1 = t.a.y + t.a.s / 2, x2 = t.b.x + t.b.s / 2, y2 = t.b.y + t.b.s / 2;
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy) || 1;
        const cx = mx - (dy / len) * Math.min(160, len * 0.3), cy = my + (dx / len) * Math.min(160, len * 0.3);
        ctx.globalAlpha = detail * (on ? 0.95 : 0.12);
        ctx.strokeStyle = C.dup; ctx.lineWidth = 1.5 + 2.5 * t.score; ctx.setLineDash([7, 4]);
        ctx.beginPath(); ctx.moveTo(x1, y1); ctx.quadraticCurveTo(cx, cy, x2, y2); ctx.stroke(); ctx.setLineDash([]);
        if (on && scale > 0.3) {
          const lx = 0.25 * x1 + 0.5 * cx + 0.25 * x2, ly = 0.25 * y1 + 0.5 * cy + 0.25 * y2, label = `${Math.round(t.score * 100)}%`;
          const w = ctx.measureText(label).width + 8;
          ctx.fillStyle = C.floor; ctx.fillRect(lx - w / 2, ly - 8, w, 16);
          ctx.fillStyle = C.dup; ctx.fillText(label, lx, ly + 4);
        }
      }
      ctx.textAlign = "left";
    }
    ctx.globalAlpha = 1; ctx.restore();
    if (detail < 1) drawOverview(C, 1 - detail, lensColor);
    requestAnimationFrame(draw);
  }

  // ---- input --------------------------------------------------------------------------------------------
  let drag = null;
  canvas.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, ox, oy, moved: false }; canvas.setPointerCapture(e.pointerId); });
  canvas.addEventListener("pointermove", (e) => {
    const r = canvas.getBoundingClientRect();
    if (drag) {
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (Math.abs(dx) + Math.abs(dy) > 3) { drag.moved = true; canvas.classList.add("drag"); }
      ox = drag.ox + dx; oy = drag.oy + dy; return;
    }
    const tip = $("#tip");
    if (overview()) {
      hover = null;
      hoverZone = zoneAt(e.clientX - r.left, e.clientY - r.top);
      const z = zones[hoverZone];
      if (z) {
        const out = zoneLinks.filter((l) => l.a === hoverZone).reduce((t, l) => t + l.count, 0);
        const inn = zoneLinks.filter((l) => l.b === hoverZone).reduce((t, l) => t + l.count, 0);
        tip.innerHTML = `${esc(z.name)} · ${fmt(z.count)} files<br>${fmt(inn)} ${mode === "call" ? "calls" : "imports"} in · ${fmt(out)} out` +
          `<br>${z.sev.high} high · ${z.sev.warn} warn · ${z.sev.info} info<br>click to open`;
        tip.style.display = "block"; tip.style.left = e.clientX - r.left + 14 + "px"; tip.style.top = e.clientY - r.top + 14 + "px";
      } else tip.style.display = "none";
      return;
    }
    hoverZone = -1;
    hover = hit(...toWorld(e.clientX - r.left, e.clientY - r.top));
    if (hover) {
      const lights = ["high", "warn", "info"].map((s) => [s, hover.flags.filter((f) => f.severity === s).length]).filter(([, c]) => c);
      tip.innerHTML = `${esc(hover.id)}<br>${hover.loc} lines · ${hover.fns.length} functions · in ${hover.inn.size} · out ${hover.out.size}` +
        (lights.length ? `<br>${lights.map(([s, c]) => `${c} ${s}`).join(" · ")}` : "");
      tip.style.display = "block"; tip.style.left = e.clientX - r.left + 14 + "px"; tip.style.top = e.clientY - r.top + 14 + "px";
    } else tip.style.display = "none";
  });
  canvas.addEventListener("pointerup", (e) => {
    canvas.classList.remove("drag");
    if (drag && !drag.moved) {
      const r = canvas.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top;
      if (overview()) { const i = zoneAt(px, py); if (i >= 0) { zoomToZone(i); hoverZone = -1; $("#tip").style.display = "none"; } }
      else select(hit(...toWorld(px, py)));
    }
    drag = null;
  });
  canvas.addEventListener("pointerleave", () => { hover = null; hoverZone = -1; $("#tip").style.display = "none"; });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top;
    const k = Math.exp(-e.deltaY * 0.0015), next = Math.min(4, Math.max(0.02, scale * k));
    ox = px - (px - ox) * (next / scale); oy = py - (py - oy) * (next / scale); scale = next;
  }, { passive: false });
  addEventListener("resize", resize);
  addEventListener("keydown", (e) => { if (e.target.tagName !== "INPUT" && e.key === "f") fit(); if (e.key === "Escape") { traced = null; select(null); } });

  // ---- fix prompts ---------------------------------------------------------------------------------------
  // Every issue belongs to a task of `codefactory plan`; its prompt is ready to paste into Claude Code.
  const taskOfFlag = new Map();
  for (const t of D.tasks || []) for (const i of t.flags) taskOfFlag.set(i, t);
  function copyText(text) {
    const done = () => toast("Prompt copied. Paste it into Claude Code.");
    if (navigator.clipboard && window.isSecureContext !== false) {
      navigator.clipboard.writeText(text).then(done, () => fallback());
    } else fallback();
    function fallback() {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0"; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch { toast("Couldn't copy: select the prompt text instead."); }
      ta.remove();
    }
  }
  let toastTimer = 0;
  function toast(msg) {
    const el = $("#toast"); el.textContent = msg; el.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 2600);
  }
  const promptButton = (i) => taskOfFlag.has(i)
    ? `<button class="fixbtn" data-fix="${i}" title="${esc(taskOfFlag.get(i).title)}">Copy fix prompt</button>` : "";
  function wireFix(root) {
    root.querySelectorAll("[data-fix]").forEach((b) => b.onclick = (e) => { e.stopPropagation(); copyText(taskOfFlag.get(+b.dataset.fix).prompt); });
  }

  // ---- panels -------------------------------------------------------------------------------------------
  const KIND = { cycle: "Import loops", layer_violation: "Layer violations", io_in_loop: "Calls in loops",
    duplicate: "Duplicates", similar: "Near-duplicates", unused: "Unused", quadratic_scan: "Searches in loops",
    sequential_await: "Awaits in loops", test_only: "Test only", hub: "Hubs", large_file: "Large files", long_function: "Long functions" };
  const shortTarget = (t) => t.includes("::") ? t.split("::")[1] + "  ·  " + t.split("::")[0] : t;
  function renderIssues() {
    const counts = {};
    for (const fl of D.flags) counts[fl.kind] = (counts[fl.kind] || 0) + 1;
    const kinds = Object.keys(counts).sort((a, b) => Object.keys(KIND).indexOf(a) - Object.keys(KIND).indexOf(b));
    const lensSet = LENS_KINDS[lens];
    const list = D.flags.filter((fl) => flagFilter ? fl.kind === flagFilter : !lensSet || lensSet.has(fl.kind)).slice(0, 400);
    $("#issues").innerHTML = (kinds.length ? `<div class="chips">${kinds.map((k) =>
      `<button class="chip" data-kind="${k}" aria-pressed="${flagFilter === k}">${KIND[k] || k} ${counts[k]}</button>`).join("")}</div>` :
      `<p class="empty">No issues found.</p>`) +
      list.map((fl) => { const i = D.flags.indexOf(fl); return `<div class="flag ${fl.severity}" tabindex="0" data-i="${i}"><b>${esc(KIND[fl.kind] || fl.kind)}</b> · ${esc(fl.message)}
        <div class="where">${esc(shortTarget(fl.target))}${fl.line ? ":" + fl.line : ""}</div>${promptButton(i)}</div>`; }).join("");
    wireFix($("#issues"));
    $("#issues").querySelectorAll(".chip").forEach((b) => b.onclick = () => { flagFilter = flagFilter === b.dataset.kind ? null : b.dataset.kind; renderIssues(); });
    $("#issues").querySelectorAll(".flag").forEach((el) => {
      const go = () => {
        const fl = D.flags[+el.dataset.i], f = fileOf(fl.target);
        if (!f) return;
        select(f); focusOn(f);
        // a copy or a loop calling elsewhere: light up every file involved
        if (fl.related && fl.related.length) spot = new Set([f.id, ...fl.related.map((r) => fileOf(r)?.id).filter(Boolean)]);
      };
      el.onclick = go; el.onkeydown = (e) => { if (e.key === "Enter") go(); };
    });
  }
  function fnRows(f) {
    return f.fns.slice().sort((a, b) => a.line - b.line).map((fn) => {
      const inn = (fnCallers.get(fn.id) || []).length, out = (fnCallees.get(fn.id) || []).length;
      const fl = D.flags.filter((x) => x.target === fn.id).map((x) => KIND[x.kind] || x.kind).join(", ");
      return `<tr><td><span class="link" data-trace="${esc(fn.id)}" title="Trace what it calls">${esc(fn.qualname)}</span><div class="where" style="color:var(--muted)">line ${fn.line}${fl ? " · " + esc(fl) : ""}</div></td>
        <td class="n">${fn.loc}</td><td class="n">${inn}</td><td class="n">${out}</td></tr>`;
    }).join("");
  }
  function neighbours(map, label) {
    const rows = [...map].sort((a, b) => b[1] - a[1]).map(([g, c]) => `<tr><td><span class="link" data-file="${esc(g.id)}">${esc(g.id)}</span></td><td class="n">${c}</td></tr>`).join("");
    return `<h2>${label}</h2>` + (rows ? `<table>${rows}</table>` : `<p class="empty">None.</p>`);
  }
  function select(f) {
    selected = f; traced = null; spot = null;
    const pane = $("#selected");
    pane.scrollTop = 0;
    if (!f) { pane.innerHTML = `<p class="empty">Click a machine to see its functions, belts and issues.</p>`; return; }
    pane.innerHTML = `<h2>Machine</h2><div style="font:13px var(--mono);word-break:break-all">${esc(f.id)}</div>
      <div class="sub">layer ${esc(f.layer)} · ${f.loc} lines · ${f.fns.length} functions</div>` +
      (f.flags.length ? `<h2>Issues</h2>` + f.flags.map((fl) => `<div class="flag ${fl.severity}"><b>${esc(KIND[fl.kind] || fl.kind)}</b> · ${esc(fl.message)}${promptButton(D.flags.indexOf(fl))}</div>`).join("") : "") +
      `<h2>Functions</h2>` + (f.fns.length ? `<table><tr><th>Name</th><th class="n">Lines</th><th class="n">In</th><th class="n">Out</th></tr>${fnRows(f)}</table>` : `<p class="empty">None.</p>`) +
      neighbours(f.inn, `Belts in (${mode === "call" ? "calls" : "imports"})`) + neighbours(f.out, `Belts out (${mode === "call" ? "calls" : "imports"})`);
    pane.querySelectorAll("[data-file]").forEach((el) => el.onclick = () => { const g = fileById.get(el.dataset.file); select(g); focusOn(g); });
    pane.querySelectorAll("[data-trace]").forEach((el) => el.onclick = () => showTrace(el.dataset.trace));
    wireFix(pane);
    tab("selected");
  }
  function showTrace(id) {
    traced = traceFrom(id);
    const t = traced, pane = $("#selected");
    pane.scrollTop = 0;
    fitFiles([...t.files].map((fid) => fileById.get(fid)), fileById.get(t.start.file));
    pane.innerHTML = `<h2>Trace</h2><div style="font:13px var(--mono);word-break:break-all">${esc(t.start.qualname)}</div>
      <div class="sub">${esc(t.start.file)}:${t.start.line}</div>
      <p>Reaches <b>${t.fns.length}</b> ${t.fns.length === 1 ? "function" : "functions"} in <b>${t.files.size - 1}</b> other ${t.files.size === 2 ? "file" : "files"}, <b>${t.maxDepth}</b> ${t.maxDepth === 1 ? "call" : "calls"} deep,
      <b>${t.loc}</b> lines of code.${t.loop ? ` <span style="color:var(--warn)">Calls back into itself (a call loop).</span>` : ""}</p>
      <button class="chip" id="untrace">Clear trace</button>
      <h2>Calls, by depth</h2>` + (t.fns.length ? `<table>${t.fns.map((x) => `<tr><td style="padding-left:${6 + (x.depth - 1) * 14}px">
        <span class="link" data-trace="${esc(x.fn.id)}">${esc(x.fn.qualname)}</span>
        <div style="color:var(--muted);font:11.5px var(--mono)">${esc(x.fn.file)}:${x.fn.line}</div></td>
        <td class="n">${x.fn.loc}</td></tr>`).join("")}</table>` : `<p class="empty">It calls nothing the analyzer could resolve.</p>`);
    pane.querySelectorAll("[data-trace]").forEach((el) => el.onclick = () => showTrace(el.dataset.trace));
    $("#untrace").onclick = () => { const f = fileById.get(t.start.file); traced = null; select(f); };
    tab("selected");
  }
  function tab(name) {
    document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === name));
    $("#issues").hidden = name !== "issues"; $("#selected").hidden = name !== "selected";
  }
  document.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => tab(b.dataset.tab));
  document.querySelectorAll("[data-mode]").forEach((b) => b.onclick = () => {
    mode = b.dataset.mode; buildBelts();
    document.querySelectorAll("[data-mode]").forEach((x) => x.setAttribute("aria-pressed", x === b));
    if (selected) select(selected);
  });
  $("#fit").onclick = fit;
  const LEGEND = {
    issues: $("#legend").innerHTML,
    duplication: `<span><i style="background:var(--dup)"></i>tint = lines in copied functions</span><span><i style="background:var(--dup);border-radius:0"></i>dashed arc = files holding copies, with similarity</span>`,
    efficiency: `<span><i style="background:var(--slow)"></i>tint = loop problems</span><span><i style="background:var(--slow);border-radius:0"></i>red belt = a loop calling into I/O</span><span>drum = does database, file or network I/O</span>`,
    size: `<span><i style="background:var(--size)"></i>tint = lines of code</span>`,
  };
  $("#lens").onchange = (e) => {
    lens = e.target.value; flagFilter = null;
    zones.forEach((z, i) => { z.metric = files.filter((f) => f.zone === i).reduce((t, f) => t + lensMetric[lens](f), 0); });
    $("#legend").innerHTML = LEGEND[lens];
    renderIssues(); tab("issues");
  };
  const testsBtn = $("#tests");
  testsBtn.hidden = !hasTests;
  testsBtn.setAttribute("aria-pressed", showTests);
  testsBtn.onclick = () => {
    showTests = !showTests; testsBtn.setAttribute("aria-pressed", showTests);
    if (selected && selected.layer === "tests" && !showTests) select(null);
    traced = null; layout(); buildBelts(); fit();
  };
  $("#search").oninput = (e) => { query = e.target.value.trim().toLowerCase(); };
  $("#search").onkeydown = (e) => { if (e.key === "Enter") { const f = files.find(matches); if (f) { select(f); focusOn(f); } } };

  const sev = { high: 0, warn: 0, info: 0 };
  for (const fl of D.flags) sev[fl.severity]++;
  $("#title").textContent = D.root.split(/[\\/]/).filter(Boolean).pop() || D.root;
  const quiet = (D.silenced || []).length;
  $("#meta").textContent = `${D.language} · ${files.length} files · ${D.functions.filter((f) => f.kind !== "module").length} functions · ${sev.high} high · ${sev.warn} warn · ${sev.info} info${quiet ? ` · ${quiet} silenced` : ""}`;
  resize(); fit(); renderIssues(); select(null); tab("issues"); requestAnimationFrame(draw);
})();
