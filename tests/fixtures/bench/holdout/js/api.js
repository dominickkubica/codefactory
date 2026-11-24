const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { exec } = require("child_process");

const app = express();
app.use(cors({ origin: "*" }));
const METRICS = "http://internal-metrics.corp.net:9100/push";

app.get("/users/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id = " + req.params.id);
  res.json(rows);
});

app.get("/safe/:id", async (req, res) => {
  res.json(await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]));
});

app.post("/login", (req, res) => {
  res.cookie("sid", req.body.sid, { secure: false });
  res.end();
});

function unpack(file) {
  exec("tar -xf " + file);
}

function hashPassword(password) {
  return crypto.createHash("sha1").update(password).digest("hex");
}

function newInvite() {
  const inviteCode = Math.random().toString(36).slice(2, 10);
  return inviteCode;
}

function pick(items) {
  const idx = Math.floor(Math.random() * items.length);
  return items[idx];
}

async function loadRows(pool, ids) {
  const out = [];
  for (const id of ids) {
    const row = await pool.query("SELECT * FROM t WHERE id = $1", [id]);
    out.push(row);
  }
  return out;
}

function touchAll(db, ids) {
  ids.forEach(async (id) => {
    await db.query("UPDATE t SET seen = true WHERE id = $1", [id]);
  });
}

function parse(text) {
  try {
    return JSON.parse(text);
  } catch (err) { }
}

function parseLogged(text, logger) {
  try {
    return JSON.parse(text);
  } catch (err) { logger.warn(err); }
}

module.exports = { app, unpack, hashPassword, newInvite, pick, loadRows, touchAll, parse, parseLogged, METRICS };
