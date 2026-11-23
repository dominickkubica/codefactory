declare const db: { getFirstAsync(sql: string, ...args: unknown[]): Promise<unknown> };

// N+1: one query per id.
export async function loadAll(ids: number[]) {
  const out: unknown[] = [];
  for (const id of ids) {
    out.push(await db.getFirstAsync("SELECT * FROM t WHERE id = ?", id));
  }
  return out;
}

// picked.includes runs once per item: O(n²) on long lists.
export function tagged(items: { id: number }[], picked: number[]) {
  return items.map((it) => ({ ...it, on: picked.includes(it.id) }));
}
