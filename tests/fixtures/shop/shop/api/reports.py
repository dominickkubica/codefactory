from shop.db.sql import get_order, save_line


def order_report(conn, ids):
    """N+1: one query per order."""
    return [get_order(conn, i) for i in ids]


def import_lines(conn, lines):
    for line in lines:
        save_line(conn, line)


def shipping_cost(order):
    weight = sum(item["weight"] * item["qty"] for item in order["items"])
    if weight <= 0:
        return 0
    base = 4.99 if order["country"] == "US" else 14.99
    per_kg = 0.8 if order["country"] == "US" else 2.4
    total = base + weight * per_kg
    return round(total, 2)


def freight_cost(shipment):
    mass = sum(entry["weight"] * entry["qty"] for entry in shipment["items"])
    if mass <= 0:
        return 0
    base = 4.99 if shipment["country"] == "US" else 14.99
    per_kg = 0.8 if shipment["country"] == "US" else 2.4
    total = base + mass * per_kg
    total = max(total, 9.99)
    return round(total, 2)
