from shop.core import pricing
from shop.db import store
from shop.db.store import save_order


def checkout(cart):
    total = pricing.total(cart)
    save_order(cart, total)
    return total


def list_orders():
    return store.load_orders()


def legacy_export():
    return "never called"
