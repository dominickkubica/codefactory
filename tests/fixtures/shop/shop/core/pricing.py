from shop.core import tax


def total(cart):
    subtotal = sum(item["price"] * item["qty"] for item in cart)
    return subtotal + tax.tax_for(subtotal)


def total_copy(basket):
    """Pasted from total() with renamed variables."""
    amount = sum(line["price"] * line["qty"] for line in basket)
    return amount + tax.tax_for(amount)


def discount(cart, pct):
    lines = []
    for item in cart:
        price = item["price"] * (1 - pct)
        lines.append({**item, "price": price})
    if not lines:
        return []
    return lines


def apply_coupon(cart, code):
    lines = []
    for row in cart:
        cost = row["price"] * (1 - code)
        lines.append({**row, "price": cost})
    if not lines:
        return []
    return lines
