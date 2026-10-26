"""Standard Roman numerals, 1..3999."""

_SYMBOLS = [
    (1000, "M"),
    (500, "D"),
    (100, "C"),
    (50, "L"),
    (10, "X"),
    (5, "V"),
    (1, "I"),
]


def to_roman(number: int) -> str:
    if not 0 < number < 4000:
        raise ValueError("number must be in 1..3999")
    out = []
    for value, symbol in _SYMBOLS:
        while number >= value:
            out.append(symbol)
            number -= value
    return "".join(out)
