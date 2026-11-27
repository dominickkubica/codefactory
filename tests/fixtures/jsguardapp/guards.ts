// Each guard from real repositories beside the same flow without it: only the lines marked `// flow` are flows.
import express from "express";
import fs from "fs";
import path from "path";
import axios from "axios";
import jwt from "jsonwebtoken";

const app = express();
const UPLOADS = "/srv/uploads";

// maxun, cal.com: a validator's result checked before the request goes out
app.post("/hook/test", async (req, res) => {
  const { webhook } = req.body;
  const check = await validateWebhookUrl(webhook.url);
  if (!check.safe) return res.status(400).end();
  await axios.post(webhook.url, {});
});
app.post("/hook/raw", async (req, res) => {
  const { webhook } = req.body;
  await axios.post(webhook.url, {}); // flow
});

// a check called for its throw
app.get("/proxy", async (req, res) => {
  const target = req.query.target;
  await assertSafeUrl(target);
  res.send(await fetch(target));
});
app.get("/proxy/raw", async (req, res) => {
  res.send(await fetch(req.query.target)); // flow
});

// NodeBB: containment by name, its result failing the request
app.get("/browse", async (req, res, next) => {
  const folder = path.join(UPLOADS, req.query.dir);
  if (!isPathInside(UPLOADS, folder)) return next(new Error("invalid path"));
  res.json(await fs.promises.readdir(folder));
});
app.get("/browse/raw", async (req, res) => {
  const folder = path.join(UPLOADS, req.query.dir);
  res.json(await fs.promises.readdir(folder)); // flow
});

// parse-server: a resolved path held to its base by startsWith; and by path.relative
app.get("/page/:name", async (req, res) => {
  const p = path.normalize(path.join(UPLOADS, req.params.name));
  if (!p.startsWith(UPLOADS + path.sep)) throw new Error("outside");
  res.send(await fs.promises.readFile(p, "utf-8"));
});
app.get("/page2/:name", async (req, res) => {
  const p = path.resolve(UPLOADS, req.params.name);
  const rel = path.relative(UPLOADS, p);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return res.status(404).end();
  res.send(await fs.promises.readFile(p, "utf-8"));
});
app.get("/page3/:name", async (req, res) => {
  const p = path.resolve(UPLOADS, req.params.name);
  res.send(await fs.promises.readFile(p, "utf-8")); // flow
});

// wiki, express: send confines the name to a root
app.get("/static/:name", (req, res) => {
  res.sendFile(req.params.name, { root: UPLOADS });
});
app.get("/static2/:name", (req, res) => {
  res.sendFile(req.params.name); // flow
});

// teable: an allow-listed redirect in a ternary
app.get("/after-login", (req, res) => {
  const target = req.query.redirect && isValidRedirectPath(req.query.redirect) ? req.query.redirect : "/space";
  res.redirect(target);
  res.redirect(req.query.redirect); // flow
});

// NodeBB, openstatus, tldraw: a fixed base (a settings getter, constant ternary, a URL's pathname) before the value
app.get("/groups/:slug", (req, res) => {
  const slug = req.params.slug.toLowerCase();
  res.redirect(`${nconf.get("relative_path")}/groups/${slug}`);
  res.redirect(`${dev ? "http://localhost:3000" : "https://app.example.dev"}/app/${slug}`);
  const url = new URL(req.query.u);
  fetch(`${POSTHOG_URL}${url.pathname}${url.search}`);
  res.redirect(`${slug}/groups`); // flow
});

// NodeBB: a slug written back into req.params doesn't make req.path request text
app.get("/user/:userslug", (req, res) => {
  const lower = req.params.userslug.toLowerCase();
  if (req.params.userslug !== lower) {
    req.params.userslug = lower;
    const newPath = req.path.replace(`/${req.params.userslug}`, () => `/${lower}`);
    return res.redirect(`${nconf.get("relative_path")}${newPath}`);
  }
  res.redirect(req.path.replace("/me", req.params.userslug)); // flow
});

// rallly: only a URL's path changes; the host stays the request's own
app.get("/i18n", (req, res) => {
  const next = new URL(FALLBACK);
  next.pathname = `/${req.headers["accept-language"]}/home`;
  res.redirect(next);
});
app.get("/i18n/host", (req, res) => {
  const next = new URL(FALLBACK);
  next.host = req.headers["x-host"];
  res.redirect(next); // flow
});

// parse-server, n8n: what an options object sends isn't where it goes
function verify(url, receipt) {
  return axios.request({ url, method: "POST", data: { receipt } });
}
app.post("/receipt", (req, res) => {
  verify("https://buy.itunes.apple.com/verifyReceipt", req.body.receipt);
  axios.request({ url: req.body.endpoint, method: "POST" }); // flow
});

// linkwarden: a value of a server-signed token
app.get("/preserved", async (req, res) => {
  const token = await decode({ token: req.query.token, secret: process.env.SECRET });
  res.send(fs.readFileSync(token.filePath));
  const claims = jwt.verify(req.query.jwt, process.env.SECRET);
  res.send(fs.readFileSync(claims.path));
  const unsigned = decode({ token: req.query.other });
  res.send(fs.readFileSync(unsigned.filePath)); // flow
});

// teable: knex's toQuery escapes its bindings; an SSRF-safe agent; the guard off only by the operator's choice
app.get("/search", async (req, res) => {
  const q = knex("t").where("name", "ilike", `%${req.query.q}%`).toQuery();
  await prisma.$queryRawUnsafe(q);
  await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE name = '${req.query.q}'`); // flow
  await axios.get(req.query.file, { ...getSafeAxiosAgents() });
  if (isSsrfProtectionDisabled()) {
    await fetch(req.query.file);
  }
});
