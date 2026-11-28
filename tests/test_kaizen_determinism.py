"""The same code gives the same results: two runs under different hash seeds export the same audit, byte for byte
(but its date). Set order once picked which flow named a sink line, how copies were listed and, in a big repository,
which summaries settled before the data-flow pass ran out of steps."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# several request values reach each sink: which one the finding names came from a set
SERVER_JS = """\
const express = require("express");
const { exec } = require("child_process");
const app = express();

function run(first, second, third) {
  exec("tar " + first + second + third);
}

app.get("/a", (req, res) => {
  const { name, kind } = req.query;
  const extra = req.headers.extra;
  run(name, req.body.mode, extra);
  exec(`ls ${req.query.dir} ${req.params.id} ${req.body.path} ${kind} ${req.cookies.sid}`);
  db.query(`SELECT * FROM t WHERE a = ${req.query.a} AND b = ${req.body.b} AND c = ${req.params.c}`);
  res.send("ok");
});
"""

VIEWS_PY = """\
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    a, b, c = request.args.get("a"), request.form.get("b"), request.headers.get("c")
    subprocess.call("echo " + a + b + c, shell=True)
    os.system(f"ls {request.args['d']} {request.cookies['e']} {b}")
    return "ok"
"""

# copies of one function: their group's members, and its title, once followed the hash seed
COPY = """\
def {name}(rows, limit, offset):
    out = []
    for row in rows:
        if row.get("active") and row.get("score", 0) > limit:
            total = sum(v for v in row.get("values", []) if v is not None)
            label = str(row.get("name", "")).strip().lower()
            out.append({{"label": label, "total": total + offset, "{name}": True}})
        elif row.get("pending"):
            out.append({{"label": "pending", "total": offset, "{name}": False}})
    out.sort(key=lambda r: (r["total"], r["label"]))
    return out[:limit]
"""


def _fixture() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "server.js").write_text(SERVER_JS, encoding="utf-8")
    (root / "views.py").write_text(VIEWS_PY, encoding="utf-8")
    for i, name in enumerate(("collect", "gather", "harvest", "assemble", "compile_rows")):
        (root / f"mod_{i}.py").write_text(COPY.format(name=name), encoding="utf-8")
    return root


def _export(root: Path, seed: str) -> dict:
    out = root.parent / f"{root.name}-audit-{seed}.json"
    env = {**os.environ, "PYTHONHASHSEED": seed, "CODEFACTORY_JOBS": "1"}
    subprocess.run([sys.executable, "-m", "codefactory", "export", str(root), "--json", "--no-cache", "-o", str(out)],
                   cwd=ROOT, env=env, check=True, capture_output=True)  # fmt: skip
    data = json.loads(out.read_text(encoding="utf-8"))
    data.pop("date", None)
    return data


GRAPH = """
import json, sys
from pathlib import Path
from codefactory.cli import build
print(json.dumps(build(Path(sys.argv[1]), cache=False).to_dict()))
"""


def _graph(root: Path, seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed, "CODEFACTORY_JOBS": "1", "PYTHONPATH": str(ROOT)}
    return subprocess.run([sys.executable, "-c", GRAPH, str(root)], cwd=ROOT, env=env, check=True, capture_output=True,
                          text=True).stdout  # fmt: skip


class DeterminismTest(unittest.TestCase):
    def test_two_hash_seeds_build_the_same_graph(self):
        # (the edges were built from sets: the same code gave them in a different order each run, so no two graphs or
        # caches compared byte for byte)
        root = _fixture()
        for name in ("alpha", "bravo", "charlie", "delta", "echo"):  # one module importing several: a set, once
            (root / f"{name}.py").write_text(f"def {name}():\n    return 1\n", encoding="utf-8")
        (root / "hub.py").write_text("import alpha\nimport bravo\nimport charlie\nimport delta\nimport echo\n",
                                     encoding="utf-8")  # fmt: skip
        self.assertEqual(_graph(root, "1"), _graph(root, "2"))

    def test_two_hash_seeds_export_the_same_audit(self):
        root = _fixture()
        first, second = _export(root, "1"), _export(root, "2")
        self.assertTrue(first["findings"])
        self.assertEqual(json.dumps(first, indent=1), json.dumps(second, indent=1))


if __name__ == "__main__":
    unittest.main()
