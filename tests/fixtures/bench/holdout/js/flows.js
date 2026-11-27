const fastify = require("fastify")();
const Router = require("@koa/router");
const { execSync, spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

const router = new Router();

fastify.get("/report", async (request, reply) => {
  const name = request.query.name;
  const out = execSync("wc -l reports/" + name);
  return out.toString();
});

fastify.get("/report/tail", async (request, reply) => {
  const lines = parseInt(request.query.lines, 10);
  return execSync(`tail -n ${lines} app.log`).toString();
});

router.get("/files/:name", async (ctx) => {
  const file = path.join("/srv/uploads", ctx.params.name);
  ctx.body = fs.createReadStream(file);
});

router.get("/avatar/:id", async (ctx) => {
  const id = path.basename(ctx.params.id);
  ctx.body = fs.createReadStream(path.join("/srv/avatars", id));
});

router.post("/import", async (ctx) => {
  const { url } = ctx.request.body;
  const res = await axios.get(url);
  ctx.body = res.data;
});

router.post("/notify", async (ctx) => {
  const target = ctx.request.body.target;
  await axios.post(`https://hooks.partner-service.com/v1/${target}`, {});
});

const SORTS = { newest: "created_at DESC", oldest: "created_at ASC" };
router.get("/posts", async (ctx) => {
  const order = SORTS[ctx.query.sort] || SORTS.newest;
  ctx.body = await db.query(`SELECT * FROM posts ORDER BY ${order}`);
});

router.get("/search", async (ctx) => {
  const term = ctx.query.q;
  ctx.body = await db.query("SELECT * FROM posts WHERE title LIKE '%" + term + "%'");
});

router.get("/go", async (ctx) => {
  ctx.redirect(ctx.query.to);
});

router.get("/back", async (ctx) => {
  ctx.redirect(`/dashboard?tab=${ctx.query.tab}`);
});

function runReport(kind) {
  return execSync(`./report.sh ${kind}`);
}
fastify.post("/run", async (request) => runReport(request.body.kind));

fastify.post("/calc", async (request) => {
  return { result: eval(request.body.expr) };
});

fastify.get("/hello", async (request, reply) => {
  reply.type("text/html").send(`<p>Hello ${request.query.name}</p>`);
});

fastify.get("/thumb", async (request) => {
  spawn("convert", [request.query.file, "out.png"]);
});
