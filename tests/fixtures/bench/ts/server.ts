import { createHash } from "crypto";
import * as child_process from "child_process";
import { execFileSync, execSync } from "child_process";
import https from "https";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use("/public", cors({ origin: ["https://app.example.com"] }));

const agent = new https.Agent({ rejectUnauthorized: false });
const strictAgent = new https.Agent({ rejectUnauthorized: true });

export function run(code: string) {
  return eval(code);
}

export function compile(src: string) {
  return new Function("x", src);
}

export function evaluateScore(n: number) {
  return n * 2;
}

export function gitLog(branch: string) {
  return execSync(`git log ${branch}`).toString();
}

export function gitLogSafe(branch: string) {
  return execFileSync("git", ["log", branch]).toString();
}

export function runCmd(cmd: string) {
  child_process.exec(cmd, () => undefined);
}

export function hashPassword(password: string) {
  return createHash("md5").update(password).digest("hex");
}

export function cacheKey(fileBuffer: Buffer) {
  return createHash("md5").update(fileBuffer).digest("hex");
}

export function newSessionId() {
  const sessionId = Math.random().toString(36).slice(2);
  return sessionId;
}

export function hue() {
  return Math.random() * 360;
}

app.post("/login", (req, res) => {
  res.cookie("session", req.body.sid, { httpOnly: false });
  res.cookie("theme", "dark", { httpOnly: true });
  const claims = jwt.verify(req.body.token, process.env.KEY!, { ignoreExpiration: true });
  res.json(claims);
});

export async function loadAll(db: any, ids: number[]) {
  const rows = [];
  for (const id of ids) {
    rows.push(await db.getFirstAsync("SELECT * FROM t WHERE id = ?", [id]));
  }
  return rows;
}

export async function search(db: any, name: string) {
  return db.getAllAsync(`SELECT * FROM t WHERE name = '${name}'`);
}

const PAGE_SIZE = 50;
export async function page(db: any, id: number) {
  await db.getAllAsync(`SELECT * FROM t LIMIT ${PAGE_SIZE}`);
  return db.getAllAsync(`SELECT * FROM t WHERE id = ?`, [id]);
}

interface User { id: number; name: string }
interface Order { id: number; userId: number }

export function attach(orders: Order[], users: User[]) {
  return orders.map((o) => ({ ...o, user: users.find((u) => u.id === o.userId) }));
}

export function attachFast(orders: Order[], users: Map<number, User>) {
  return orders.map((o) => ({ ...o, user: users.get(o.userId) }));
}

export function parse(text: string) {
  try {
    return JSON.parse(text);
  } catch (e) {}
}

export function parseQuiet(text: string) {
  try {
    return JSON.parse(text);
  } catch {
    /* not JSON: keep the raw text */
  }
  return text;
}

export function fireAndForget(p: Promise<void>) {
  p.catch(() => {});
}

export { agent, strictAgent };
