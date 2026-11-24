import os
import subprocess

import requests
from fastapi import APIRouter, Depends
from flask import Flask, request

router = APIRouter()
app = Flask(__name__)


def find_user(conn, name):
    sql = "SELECT * FROM users WHERE name = '%s'" % name
    return conn.execute(sql).fetchall()


def find_user_safe(conn, name):
    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()


def get_db():
    return None


def search_term():
    return request.args.get("q", "")


@router.get("/users")
def users(name: str, limit: int = 10, conn=Depends(get_db)):
    return find_user(conn, name)


@router.get("/users/safe")
def users_safe(name: str, conn=Depends(get_db)):
    return find_user_safe(conn, name)


@router.get("/page/{page_id}")
def page(page_id: str, conn=Depends(get_db)):
    return find_user(conn, int(page_id))  # sanitized: an int can't inject


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    return requests.get(url).text


@app.route("/download")
def download():
    path = os.path.join("/srv/files", request.args["file"])
    return open(path).read()


@app.route("/ping")
def ping():
    host = search_term()
    return subprocess.run(f"ping -c 1 {host}", shell=True).returncode


def stored_path(conn, shot_id):
    row = conn.execute("SELECT path FROM shots WHERE id = ?", (shot_id,)).fetchone()
    return row["path"]


@router.get("/shot/{shot_id}")
def shot(shot_id: int, conn=Depends(get_db)):
    return open(stored_path(conn, shot_id)).read()  # an int id, a path read back from the database: not a flow


@router.get("/report")
def report(table: str, conn=Depends(get_db)):
    return conn.execute(f"SELECT count(*) FROM {table}").fetchone()  # a request string pasted into SQL
