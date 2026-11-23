class Store:
    def __init__(self):
        self.rows = []

    def add(self, row):
        self.rows.append(row)

    def unused_method(self):
        return len(self.rows)


_store = Store()


def save_order(cart, total):
    _store.add({"cart": cart, "total": total})


def load_orders():
    return list(_store.rows)
