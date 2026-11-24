"""The attack surface: endpoints per framework, their auth checks, what they change, and risky lines they reach."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from codefactory.brief import View
from codefactory.cli import build
from codefactory.review import Review
from codefactory.security import surface
from tests.test_typescript import available as ts_available


def project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def review_of(root: Path) -> Review:
    r = Review(build(root, cache=False).to_dict(), root)
    r.security()
    return r


FASTAPI = {
    "app/__init__.py": "",
    "app/db.py": """
        def insert_item(conn, name):
            conn.execute("INSERT INTO items (name) VALUES (?)", (name,))


        def delete_item(conn, item_id):
            conn.execute("DELETE FROM items WHERE id = ?", (item_id,))


        def list_items(conn):
            return conn.execute("SELECT * FROM items").fetchall()
        """,
    "app/auth.py": """
        from typing import Annotated
        from fastapi import Depends


        def get_current_user(token: str = ""):
            return token


        CurrentUser = Annotated[str, Depends(get_current_user)]
        """,
    "app/routes.py": """
        from fastapi import APIRouter, Depends
        from app.auth import CurrentUser, get_current_user
        from app.db import delete_item, insert_item, list_items

        router = APIRouter(prefix="/items")


        @router.get("")
        def read(conn=None):
            return list_items(conn)


        @router.post("")
        def create(name: str, user=Depends(get_current_user), conn=None):
            insert_item(conn, name)


        @router.put("/{item_id}")
        def rename(item_id: int, user: CurrentUser, conn=None):
            insert_item(conn, str(item_id))


        @router.delete("/{item_id}")
        def remove(item_id: int, conn=None):
            delete_item(conn, item_id)
        """,
}


class FastAPITest(unittest.TestCase):
    def test_endpoints_auth_and_prefix(self):
        root = project(FASTAPI)
        g = build(root, cache=False).to_dict()
        entries = {(e.method, e.path): e.auth for e in surface(root, g, View(g)).entries}
        self.assertEqual(
            entries,
            {("GET", "/items"): "", ("POST", "/items"): "Depends(get_current_user)",
             ("PUT", "/items/{item_id}"): "Depends(get_current_user)", ("DELETE", "/items/{item_id}"): ""},
        )  # fmt: skip

    def test_an_open_endpoint_among_protected_ones_is_high(self):
        r = review_of(project(FASTAPI))
        f = next(f for f in r.findings if f.title.startswith("Endpoints that change data"))
        self.assertEqual((f.severity, f.title), ("High", "Endpoints that change data without an auth check (1)"))
        self.assertIn("DELETE /items/{item_id}", f.evidence[0])  # GET /items only reads: not listed

    def test_router_level_auth_covers_every_route(self):
        files = dict(FASTAPI)
        files["app/routes.py"] = files["app/routes.py"].replace(
            'APIRouter(prefix="/items")', 'APIRouter(prefix="/items", dependencies=[Depends(get_current_user)])'
        )
        r = review_of(project(files))
        self.assertFalse([f for f in r.findings if f.title.startswith("Endpoints that change data")])


class FlaskReachabilityTest(unittest.TestCase):
    FILES = {
        "app.py": """
            from flask import Flask, request
            from flask_login import login_required

            app = Flask(__name__)


            def find(conn, name):
                return conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()


            def report(conn, table):
                return conn.execute(f"SELECT count(*) FROM {table}").fetchall()


            @app.route("/search")
            def search():
                return find(None, request.args["q"])


            @app.route("/admin/purge", methods=["POST"])
            @login_required
            def purge():
                return "ok"


            if __name__ == "__main__":
                app.run(host="127.0.0.1")
            """,
    }

    def test_sql_reached_from_a_route_goes_up_with_its_chain(self):
        r = review_of(project(self.FILES))
        sql = next(f for f in r.findings if f.title == "SQL assembled from strings")
        self.assertEqual(sql.severity, "High")  # Medium, one level up: a request reaches it
        reached = next(e for e in sql.evidence if "find" in e or "name =" in e)
        self.assertIn("reached from `GET /search → search → find`", reached)
        self.assertTrue(any("(no endpoint reaches it)" in e for e in sql.evidence))  # report() isn't reachable

    def test_flask_decorator_auth_and_local_listening(self):
        root = project(self.FILES)
        g = build(root, cache=False).to_dict()
        s = surface(root, g, View(g))
        self.assertEqual({(e.method, e.path, e.auth) for e in s.entries},
                         {("GET", "/search", ""), ("POST", "/admin/purge", "@login_required")})  # fmt: skip
        self.assertEqual(s.exposure, "local")


class LocalToolTest(unittest.TestCase):
    def test_no_auth_anywhere_on_a_local_server_is_low(self):
        files = dict(FASTAPI)
        files["app/routes.py"] = (
            files["app/routes.py"].replace("user=Depends(get_current_user), ", "").replace("user: CurrentUser, ", "")
        )
        files["app/main.py"] = 'API_HOST = "127.0.0.1"\n'
        f = next(f for f in review_of(project(files)).findings if f.title.startswith("Endpoints that change data"))
        self.assertEqual(f.severity, "Low")
        self.assertIn("listens only on this machine", f.impact)


@unittest.skipUnless(ts_available(), "Node.js and the typescript package are needed")
class ExpressTest(unittest.TestCase):
    def test_middleware_auth_and_open_writes(self):
        root = project({
            "server.js": '''
                const express = require("express");
                const app = express();
                const db = require("./db");

                function requireAuth(req, res, next) { next(); }
                function createOrder(req, res) { db.run("INSERT INTO orders VALUES (?)", req.body.id); res.end(); }
                function deleteOrder(req, res) { db.run("DELETE FROM orders WHERE id = ?", req.params.id); res.end(); }

                app.post("/orders", requireAuth, createOrder);
                app.delete("/orders/:id", deleteOrder);
                app.listen(3000, "0.0.0.0");
                ''',
            "db.js": "module.exports = { run(sql, ...args) { return null; } };\n",
        })  # fmt: skip
        g = build(root, cache=False).to_dict()
        s = surface(root, g, View(g))
        self.assertEqual({(e.method, e.path, e.auth) for e in s.entries},
                         {("POST", "/orders", "requireAuth"), ("DELETE", "/orders/:id", "")})  # fmt: skip
        self.assertEqual(s.exposure, "open")


if __name__ == "__main__":
    unittest.main()
