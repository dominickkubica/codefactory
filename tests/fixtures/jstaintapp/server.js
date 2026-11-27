const express = require("express");
const { exec, execFile } = require("child_process");
const fs = require("fs");
const db = require("./db");
const app = express();

function runIt(cmd) {
  exec(cmd);                                   // BAD via caller
}

app.get("/ls", (req, res) => {
  const { dir } = req.query;
  exec(`ls ${dir}`);                           // BAD shell
  execFile("ls", [dir]);                       // ok
  runIt("echo " + req.query.x);                // BAD via runIt
  const n = parseInt(req.query.n);
  exec(`head -n ${n} f`);                      // ok sanitized
});

app.post("/user", async (req, res) => {
  const name = req.body.name;
  await db.query("SELECT * FROM users WHERE name = '" + name + "'");   // BAD sql
  await db.query("SELECT * FROM users WHERE name = $1", [name]);       // ok
  await db.query(sql`SELECT * FROM users WHERE name = ${name}`);       // ok tagged
  res.redirect(req.query.next);                // BAD redirect
  res.redirect(`/users/${name}`);              // ok local
  const safe = ["/a", "/b"];
  const nxt = req.query.n2;
  if (!safe.includes(nxt)) return res.redirect("/");
  res.redirect(nxt);                           // ok validated
  fs.readFile(req.params.file, () => {});      // BAD path
  await fetch(`https://api.example.com/x/${name}`);   // ok host fixed
  await fetch(req.body.url);                   // BAD ssrf
  res.send(`<h1>Hello ${name}</h1>`);          // BAD html
  res.send({ name });                          // ok
  if (typeof name === "string") eval(name);    // BAD code
  const re = /a/; re.exec(name);               // ok
});
