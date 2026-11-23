from shop.core import pricing  # loops back: pricing imports tax


RATE = 0.08


def tax_for(amount):
    return round(amount * RATE, 2)


def preview(cart):
    return pricing.total(cart)
