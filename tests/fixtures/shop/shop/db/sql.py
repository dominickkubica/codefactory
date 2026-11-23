import sqlite3


def connect(path):
    return sqlite3.connect(path)


def get_order(conn, order_id):
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()


def save_line(conn, line):
    conn.execute("INSERT INTO lines (sku, qty) VALUES (?, ?)", (line["sku"], line["qty"]))
