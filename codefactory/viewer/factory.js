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
  const fnCallers = new Map(), fnCallees = new Map();
  function beltsFor(kind) {
    const agg = new Map();
    for (const e of D.edges) {
      if (kind === "call" ? e.kind !== "call" : e.kind !== "import") continue;
      const a = fileOf(e.src), b = fileOf(e.dst);
      if (!a || !b || a === b) continue;
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

  // ---- layout -------------------------------------------------------------------------------------------
  const GAP = 140, PAD = 40, TOP = 110;
  const size = (f) => Math.round(Math.min(150, Math.max(36, 26 + Math.sqrt(f.loc) * 2.6)) / 10) * 10;
  const layers = D.layers.length ? D.layers : [...new Set(files.map((f) => f.layer))];
  const zones = [];
  let x = 0;
  for (const name of layers) {
    const members = files.filter((f) => f.layer === name);
    if (!members.length) continue;
    members.forEach((f) => { f.s = size(f); });
    members.sort((a, b) => b.s - a.s || a.id.localeCompare(b.id));
    const area = members.reduce((t, f) => t + (f.s + PAD) ** 2, 0);
    const width = Math.max(220, Math.ceil(Math.sqrt(area) * 1.1 / 10) * 10);
    let cx = 0, cy = 0, rowH = 0;
    for (const f of members) {
      if (cx > 0 && cx + f.s > width) { cx = 0; cy += rowH + PAD; rowH = 0; }
      f.x = x + PAD + cx; f.y = TOP + cy; cx += f.s + PAD; rowH = Math.max(rowH, f.s);
      f.zone = zones.length;
    }
    zones.push({ name, x, w: width + PAD * 2, h: cy + rowH + PAD * 2 + 30, count: members.length });
    x += width + PAD * 2 + GAP;
  }
  const worldW = x - GAP, worldH = Math.max(...zones.map((z) => z.h), 200) + TOP;

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
  }
  buildBelts();

  // ---- view ---------------------------------------------------------------------------------------------
  const canvas = $("#floor"), ctx = canvas.getContext("2d");
  let scale = 1, ox = 0, oy = 0, hover = null, selected = null, flagFilter = null, query = "";
  function resize() {
    const r = canvas.getBoundingClientRect(), dpr = devicePixelRatio || 1;
    canvas.width = r.width * dpr; canvas.height = r.height * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function fit() {
    const r = canvas.getBoundingClientRect();
    scale = Math.min(2, Math.max(0.1, Math.min((r.width - 40) / worldW, (r.height - 40) / worldH)));
    ox = (r.width - worldW * scale) / 2; oy = Math.max(20, (r.height - worldH * scale) / 2);
  }
  function focusOn(f) {
    const r = canvas.getBoundingClientRect();
    scale = Math.max(scale, 1);
    ox = r.width / 2 - (f.x + f.s / 2) * scale; oy = r.height / 2 - (f.y + f.s / 2) * scale;
  }
  const toWorld = (px, py) => [(px - ox) / scale, (py - oy) / scale];
  const hit = (wx, wy) => files.find((f) => wx >= f.x && wx <= f.x + f.s && wy >= f.y && wy <= f.y + f.s) || null;
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

  function draw(now) {
    const r = canvas.getBoundingClientRect();
    const C = { floor: css("--floor"), grid: css("--grid"), machine: css("--machine"), edge: css("--machine-edge"),
      belt: css("--belt"), dot: css("--belt-dot"), back: css("--back"), ink: css("--ink"), muted: css("--muted"),
      idle: css("--idle"), sel: css("--sel"), high: css("--high"), warn: css("--warn"), info: css("--info"), line: css("--line") };
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
      ctx.strokeStyle = C.line; ctx.lineWidth = 1.5; ctx.setLineDash([6, 6]);
      ctx.strokeRect(z.x, TOP - 30, z.w, z.h); ctx.setLineDash([]);
      ctx.fillStyle = C.muted; ctx.font = "600 13px Inter, system-ui, sans-serif";
      ctx.fillText(`${z.name.toUpperCase()}  ·  ${z.count}`, z.x + 10, TOP - 12);
    }
    const focus = hover || selected;
    const linked = (b) => !focus || b.src === focus || b.dst === focus;
    // belts
    for (const b of belts) {
      const on = linked(b), visible = matches(b.src) || matches(b.dst);
      ctx.globalAlpha = !visible ? 0.06 : on ? 0.9 : 0.12;
      ctx.strokeStyle = b.back ? C.back : C.belt; ctx.lineWidth = b.w;
      ctx.setLineDash(b.back ? [8, 5] : []);
      ctx.beginPath(); ctx.moveTo(...b.pts[0]); for (const p of b.pts.slice(1)) ctx.lineTo(...p); ctx.stroke();
      ctx.setLineDash([]);
      if (on && visible && !reduceMotion) {
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
      const dim = !matches(f) || (focus && f !== focus && !focus.inn.has(f) && !focus.out.has(f));
      ctx.globalAlpha = dim ? 0.25 : 1;
      const idle = f.inn.size === 0 && f.out.size === 0;
      ctx.fillStyle = idle ? C.idle : C.machine; ctx.fillRect(f.x, f.y, f.s, f.s);
      ctx.strokeStyle = f === selected ? C.sel : C.edge; ctx.lineWidth = f === selected ? 3 : 1.5;
      ctx.strokeRect(f.x, f.y, f.s, f.s);
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
    ctx.globalAlpha = 1; ctx.restore();
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
    hover = hit(...toWorld(e.clientX - r.left, e.clientY - r.top));
    const tip = $("#tip");
    if (hover) {
      const lights = ["high", "warn", "info"].map((s) => [s, hover.flags.filter((f) => f.severity === s).length]).filter(([, c]) => c);
      tip.innerHTML = `${esc(hover.id)}<br>${hover.loc} lines · ${hover.fns.length} functions · in ${hover.inn.size} · out ${hover.out.size}` +
        (lights.length ? `<br>${lights.map(([s, c]) => `${c} ${s}`).join(" · ")}` : "");
      tip.style.display = "block"; tip.style.left = e.clientX - r.left + 14 + "px"; tip.style.top = e.clientY - r.top + 14 + "px";
    } else tip.style.display = "none";
  });
  canvas.addEventListener("pointerup", (e) => {
    canvas.classList.remove("drag");
    if (drag && !drag.moved) { const r = canvas.getBoundingClientRect(); select(hit(...toWorld(e.clientX - r.left, e.clientY - r.top))); }
    drag = null;
  });
  canvas.addEventListener("pointerleave", () => { hover = null; $("#tip").style.display = "none"; });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect(), px = e.clientX - r.left, py = e.clientY - r.top;
    const k = Math.exp(-e.deltaY * 0.0015), next = Math.min(4, Math.max(0.08, scale * k));
    ox = px - (px - ox) * (next / scale); oy = py - (py - oy) * (next / scale); scale = next;
  }, { passive: false });
  addEventListener("resize", resize);
  addEventListener("keydown", (e) => { if (e.target.tagName !== "INPUT" && e.key === "f") fit(); if (e.key === "Escape") select(null); });

  // ---- panels -------------------------------------------------------------------------------------------
  const KIND = { cycle: "Import loops", layer_violation: "Layer violations", duplicate: "Duplicates", unused: "Unused",
    hub: "Hubs", large_file: "Large files", long_function: "Long functions" };
  const shortTarget = (t) => t.includes("::") ? t.split("::")[1] + "  ·  " + t.split("::")[0] : t;
  function renderIssues() {
    const counts = {};
    for (const fl of D.flags) counts[fl.kind] = (counts[fl.kind] || 0) + 1;
    const kinds = Object.keys(counts).sort((a, b) => Object.keys(KIND).indexOf(a) - Object.keys(KIND).indexOf(b));
    const list = D.flags.filter((fl) => !flagFilter || fl.kind === flagFilter).slice(0, 400);
    $("#issues").innerHTML = (kinds.length ? `<div class="chips">${kinds.map((k) =>
      `<button class="chip" data-kind="${k}" aria-pressed="${flagFilter === k}">${KIND[k] || k} ${counts[k]}</button>`).join("")}</div>` :
      `<p class="empty">No issues found.</p>`) +
      list.map((fl, i) => `<div class="flag ${fl.severity}" tabindex="0" data-i="${D.flags.indexOf(fl)}"><b>${esc(KIND[fl.kind] || fl.kind)}</b> · ${esc(fl.message)}
        <div class="where">${esc(shortTarget(fl.target))}</div></div>`).join("");
    $("#issues").querySelectorAll(".chip").forEach((b) => b.onclick = () => { flagFilter = flagFilter === b.dataset.kind ? null : b.dataset.kind; renderIssues(); });
    $("#issues").querySelectorAll(".flag").forEach((el) => {
      const go = () => { const f = fileOf(D.flags[+el.dataset.i].target); if (f) { select(f); focusOn(f); } };
      el.onclick = go; el.onkeydown = (e) => { if (e.key === "Enter") go(); };
    });
  }
  function fnRows(f) {
    return f.fns.slice().sort((a, b) => a.line - b.line).map((fn) => {
      const inn = (fnCallers.get(fn.id) || []).length, out = (fnCallees.get(fn.id) || []).length;
      const fl = D.flags.filter((x) => x.target === fn.id).map((x) => KIND[x.kind] || x.kind).join(", ");
      return `<tr><td>${esc(fn.qualname)}<div class="where" style="color:var(--muted)">line ${fn.line}${fl ? " · " + esc(fl) : ""}</div></td>
        <td class="n">${fn.loc}</td><td class="n">${inn}</td><td class="n">${out}</td></tr>`;
    }).join("");
  }
  function neighbours(map, label) {
    const rows = [...map].sort((a, b) => b[1] - a[1]).map(([g, c]) => `<tr><td><span class="link" data-file="${esc(g.id)}">${esc(g.id)}</span></td><td class="n">${c}</td></tr>`).join("");
    return `<h2>${label}</h2>` + (rows ? `<table>${rows}</table>` : `<p class="empty">None.</p>`);
  }
  function select(f) {
    selected = f;
    const pane = $("#selected");
    if (!f) { pane.innerHTML = `<p class="empty">Click a machine to see its functions, belts and issues.</p>`; return; }
    pane.innerHTML = `<h2>Machine</h2><div style="font:13px var(--mono);word-break:break-all">${esc(f.id)}</div>
      <div class="sub">layer ${esc(f.layer)} · ${f.loc} lines · ${f.fns.length} functions</div>` +
      (f.flags.length ? `<h2>Issues</h2>` + f.flags.map((fl) => `<div class="flag ${fl.severity}"><b>${esc(KIND[fl.kind] || fl.kind)}</b> · ${esc(fl.message)}</div>`).join("") : "") +
      `<h2>Functions</h2>` + (f.fns.length ? `<table><tr><th>Name</th><th class="n">Lines</th><th class="n">In</th><th class="n">Out</th></tr>${fnRows(f)}</table>` : `<p class="empty">None.</p>`) +
      neighbours(f.inn, `Belts in (${mode === "call" ? "calls" : "imports"})`) + neighbours(f.out, `Belts out (${mode === "call" ? "calls" : "imports"})`);
    pane.querySelectorAll("[data-file]").forEach((el) => el.onclick = () => { const g = fileById.get(el.dataset.file); select(g); focusOn(g); });
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
  $("#search").oninput = (e) => { query = e.target.value.trim().toLowerCase(); };
  $("#search").onkeydown = (e) => { if (e.key === "Enter") { const f = files.find(matches); if (f) { select(f); focusOn(f); } } };

  const sev = { high: 0, warn: 0, info: 0 };
  for (const fl of D.flags) sev[fl.severity]++;
  $("#title").textContent = D.root.split(/[\\/]/).filter(Boolean).pop() || D.root;
  $("#meta").textContent = `${D.language} · ${files.length} files · ${D.functions.filter((f) => f.kind !== "module").length} functions · ${sev.high} high · ${sev.warn} warn · ${sev.info} info`;
  resize(); fit(); renderIssues(); select(null); tab("issues"); requestAnimationFrame(draw);
})();
