"""The graph as a SQLite database, so any question about the code is a SQL query.

Tables: files, functions, edges, flags. Views: function_stats (fan-in/out per function), file_deps (calls between
files). Saved queries in factory.toml run against the same database and become flags.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE files (id TEXT PRIMARY KEY, module TEXT, loc INTEGER, layer TEXT);
CREATE TABLE functions (id TEXT PRIMARY KEY, file TEXT REFERENCES files(id), name TEXT, qualname TEXT,
  line INTEGER, end_line INTEGER, loc INTEGER, kind TEXT, decorated INTEGER, exported INTEGER, dynamic INTEGER);
CREATE TABLE edges (src TEXT, dst TEXT, kind TEXT, count INTEGER);
CREATE TABLE flags (kind TEXT, severity TEXT, target TEXT, message TEXT, line INTEGER);
CREATE INDEX edges_src ON edges(src, kind);
CREATE INDEX edges_dst ON edges(dst, kind);
CREATE INDEX functions_file ON functions(file);
CREATE VIEW function_stats AS
  SELECT f.id, f.file, f.qualname, f.loc,
    (SELECT COUNT(*) FROM edges e WHERE e.dst = f.id AND e.kind = 'call') AS fan_in,
    (SELECT COUNT(*) FROM edges e WHERE e.src = f.id AND e.kind = 'call') AS fan_out,
    (SELECT COUNT(DISTINCT c.file) FROM edges e JOIN functions c ON c.id = e.src
      WHERE e.dst = f.id AND e.kind = 'call' AND c.file != f.file) AS caller_files
  FROM functions f WHERE f.kind != 'module';
CREATE VIEW file_deps AS
  SELECT a.file AS src_file, b.file AS dst_file, SUM(e.count) AS calls
  FROM edges e JOIN functions a ON a.id = e.src JOIN functions b ON b.id = e.dst
  WHERE e.kind = 'call' AND a.file != b.file GROUP BY a.file, b.file;
"""


def to_sqlite(graph: dict, path: str | Path = ":memory:") -> sqlite3.Connection:
    if path != ":memory:":
        Path(path).unlink(missing_ok=True)
    db = sqlite3.connect(str(path))
    db.executescript(SCHEMA)
    db.executemany(
        "INSERT INTO files VALUES (?, ?, ?, ?)", [(f["id"], f["module"], f["loc"], f["layer"]) for f in graph["files"]]
    )
    db.executemany(
        "INSERT INTO functions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                f["id"],
                f["file"],
                f["name"],
                f["qualname"],
                f["line"],
                f["end"],
                f["loc"],
                f["kind"],
                int(f["decorated"]),
                int(f["exported"]),
                int(f.get("dynamic", False)),
            )
            for f in graph["functions"]
        ],
    )
    db.executemany("INSERT INTO edges VALUES (?, ?, ?, ?)", [(e["src"], e["dst"], e["kind"], e["count"]) for e in graph["edges"]])
    db.executemany(
        "INSERT INTO flags VALUES (?, ?, ?, ?, ?)",
        [(f["kind"], f["severity"], f["target"], f["message"], f.get("line", 0)) for f in graph["flags"]],
    )
    db.commit()
    return db


def run_query(db: sqlite3.Connection, sql: str) -> tuple[list[str], list[tuple]]:
    cur = db.execute(sql)
    cols = [d[0] for d in cur.description or []]
    return cols, cur.fetchall()


def query_flags(graph: dict, queries: list[dict]) -> list[dict]:
    """Saved queries -> flags. Each row is one issue: a `target` column (file or function id), and optionally
    `message`; any other columns are added to the message."""
    if not queries:
        return []
    db = to_sqlite(graph)
    try:
        return _rows_to_flags(db, queries)
    finally:
        db.close()


def _rows_to_flags(db: sqlite3.Connection, queries: list[dict]) -> list[dict]:
    out = []
    for q in queries:
        # codefactory: ignore io_in_loop — one query per saved query in factory.toml, on an in-memory database
        cols, rows = run_query(db, q["sql"])
        if "target" not in cols:
            raise ValueError(f"Saved query {q['name']!r} must return a 'target' column")
        for row in rows:
            r = dict(zip(cols, row, strict=True))
            extra = ", ".join(f"{k} {v}" for k, v in r.items() if k not in ("target", "message"))
            msg = r.get("message") or q.get("message") or q["name"]
            out.append(
                {
                    "kind": q["name"],
                    "severity": q.get("severity", "warn"),
                    "target": str(r["target"]),
                    "message": f"{msg} ({extra})" if extra else str(msg),
                    "related": [],
                }
            )
    return out
