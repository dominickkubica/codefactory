declare const db: { getFirstAsync(sql: string, ...args: unknown[]): Promise<unknown> };
declare function require(name: string): unknown;

const TABLES = ["plans", "workouts", "sets"] as const;
const SPEC = { plans: 1, sets: 2 };
const PARTS = { training: { tables: ["workouts", "body_metrics"] } };

// One query per table: the tables are fixed in the code, so this can't grow with the data.
export async function countTables() {
  const out: unknown[] = [];
  for (const t of TABLES) out.push(await db.getFirstAsync(`SELECT count(*) FROM ${t}`));
  for (const [t] of Object.entries(SPEC)) out.push(await db.getFirstAsync("SELECT 1", t));
  const { tables } = PARTS.training;
  await Promise.all(tables.map((t) => db.getFirstAsync("SELECT 2", t)));
  return out;
}

// Capped: at most 5 rounds.
export async function firstFive(ids: number[]) {
  for (const id of ids.slice(0, 5)) await db.getFirstAsync("SELECT 3", id);
}

// Lazy-loaded helpers, in the two shapes apps use.
export function report() {
  const { buildReport } = require("@/data/lazy") as { buildReport: () => string };
  const lazy = require("@/data/lazy") as { buildSummary: () => string };
  return buildReport() + lazy.buildSummary();
}

// A dispatch table: HANDLERS[kind]() runs one of these.
function handleCreate() {
  return "create";
}
function handleDelete() {
  return "delete";
}
const HANDLERS = { create: handleCreate, delete: handleDelete };

export function dispatch(kinds: (keyof typeof HANDLERS)[]) {
  // searching a two-item list written in the code is constant time, not O(n²)
  return kinds.map((k) => (["create", "delete"].includes(k) ? HANDLERS[k]() : ""));
}
