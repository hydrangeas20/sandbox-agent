"""Temperature conversion."""


def f_to_c(fahrenheit: float) -> float:
    return (fahrenheit - 32) * 9 / 5


def c_to_f(celsius: float) -> float:
    return celsius * 9 / 5 + 32
